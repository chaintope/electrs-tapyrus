use bincode;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use std::collections::{HashMap, HashSet};
use std::iter::FromIterator;
use std::sync::RwLock;
use tapyrus::blockdata::block::{Block, BlockHeader};
use tapyrus::blockdata::script::{ColorIdentifier, Script};
use tapyrus::blockdata::transaction::{Transaction, TxIn, TxOut};
use tapyrus::consensus::encode::{deserialize, serialize};
use tapyrus::hash_types::{BlockHash, Txid};
use tapyrus::util::hash::BitcoinHash;

use crate::daemon::Daemon;
use crate::errors::*;
use crate::metrics::{
    Counter, Gauge, HistogramOpts, HistogramTimer, HistogramVec, MetricOpts, Metrics,
};
use crate::signal::Waiter;
use crate::store::{ReadStore, Row, WriteStore};
use crate::util::{
    full_hash, hash_prefix, spawn_thread, Bytes, FullHash, HashPrefix, HeaderEntry, HeaderList,
    HeaderMap, SyncChannel, HASH_PREFIX_LEN,
};

#[derive(Serialize, Deserialize)]
pub struct TxInKey {
    pub code: u8,
    pub prev_hash_prefix: HashPrefix,
    pub prev_index: u16,
}

#[derive(Serialize, Deserialize)]
pub struct TxInRow {
    key: TxInKey,
    pub txid_prefix: HashPrefix,
}

impl TxInRow {
    pub fn new(txid: &Txid, input: &TxIn) -> TxInRow {
        TxInRow {
            key: TxInKey {
                code: b'I',
                prev_hash_prefix: hash_prefix(&input.previous_output.txid[..]),
                prev_index: input.previous_output.vout as u16,
            },
            txid_prefix: hash_prefix(&txid[..]),
        }
    }

    pub fn filter(txid: &Txid, output_index: usize) -> Bytes {
        bincode::serialize(&TxInKey {
            code: b'I',
            prev_hash_prefix: hash_prefix(&txid[..]),
            prev_index: output_index as u16,
        })
        .unwrap()
    }

    pub fn to_row(&self) -> Row {
        Row {
            key: bincode::serialize(&self).unwrap(),
            value: vec![],
        }
    }

    pub fn from_row(row: &Row) -> TxInRow {
        bincode::deserialize(&row.key).expect("failed to parse TxInRow")
    }
}

#[derive(Serialize, Deserialize)]
pub struct TxOutKey {
    code: u8,
    script_hash_prefix: HashPrefix,
}

#[derive(Serialize, Deserialize)]
pub struct TxOutRow {
    key: TxOutKey,
    pub txid_prefix: HashPrefix,
}

impl TxOutRow {
    pub fn new(txid: &Txid, output: &TxOut, colored: bool) -> TxOutRow {
        let script = if colored {
            let (_color_id, script) = split_colored_script(&output.script_pubkey)
                .expect("Expected colored script(cp2pkh or cp2sh) but script is not colored");
            script
        } else {
            Script::from(Script::from(Vec::from(&output.script_pubkey[..])))
        };

        TxOutRow {
            key: TxOutKey {
                code: b'O',
                script_hash_prefix: hash_prefix(&compute_script_hash(&script[..])),
            },
            txid_prefix: hash_prefix(&txid[..]),
        }
    }

    pub fn filter(script_hash: &[u8]) -> Bytes {
        bincode::serialize(&TxOutKey {
            code: b'O',
            script_hash_prefix: hash_prefix(&script_hash[..HASH_PREFIX_LEN]),
        })
        .unwrap()
    }

    pub fn to_row(&self) -> Row {
        Row {
            key: bincode::serialize(&self).unwrap(),
            value: vec![],
        }
    }

    pub fn from_row(row: &Row) -> TxOutRow {
        bincode::deserialize(&row.key).expect("failed to parse TxOutRow")
    }
}

#[derive(Serialize, Deserialize)]
pub struct TxKey {
    code: u8,
    pub txid: FullHash,
}

pub struct TxRow {
    pub key: TxKey,
    pub height: u32, // value
}

impl TxRow {
    pub fn new(txid: &Txid, height: u32) -> TxRow {
        TxRow {
            key: TxKey {
                code: b'T',
                txid: full_hash(&txid[..]),
            },
            height,
        }
    }

    pub fn filter_prefix(txid_prefix: HashPrefix) -> Bytes {
        [b"T", &txid_prefix[..]].concat()
    }

    pub fn filter_full(txid: &Txid) -> Bytes {
        [b"T", &txid[..]].concat()
    }

    pub fn to_row(&self) -> Row {
        Row {
            key: bincode::serialize(&self.key).unwrap(),
            value: bincode::serialize(&self.height).unwrap(),
        }
    }

    pub fn from_row(row: &Row) -> TxRow {
        TxRow {
            key: bincode::deserialize(&row.key).expect("failed to parse TxKey"),
            height: bincode::deserialize(&row.value).expect("failed to parse height"),
        }
    }
}

#[derive(Serialize, Deserialize)]
struct BlockKey {
    code: u8,
    hash: FullHash,
}

pub fn compute_script_hash(data: &[u8]) -> FullHash {
    let mut hash = FullHash::default();
    let mut sha2 = Sha256::new();
    sha2.input(data);
    sha2.result(&mut hash);
    hash
}

pub fn split_colored_script(script: &Script) -> Option<(ColorIdentifier, Script)> {
    if script.is_colored() {
        let color_id = deserialize(&script[1..34]).expect("unexpect color_id");
        Some((color_id, Script::from(Vec::from(&script[35..]))))
    } else {
        None
    }
}

pub fn index_transaction<'a>(
    txn: &'a Transaction,
    height: usize,
) -> impl 'a + Iterator<Item = Row> {
    let null_hash = Txid::default();
    let txid: Txid = txn.malfix_txid();

    let inputs = txn.input.iter().filter_map(move |input| {
        if input.previous_output.txid == null_hash {
            None
        } else {
            Some(TxInRow::new(&txid, &input).to_row())
        }
    });
    let outputs = txn
        .output
        .iter()
        .map(move |output| TxOutRow::new(&txid, &output, false).to_row());
    let colored_outputs = txn
        .output
        .iter()
        .filter(|o| o.script_pubkey.is_colored())
        .map(move |output| TxOutRow::new(&txid, &output, true).to_row());

    // Persist transaction ID and confirmed height
    inputs
        .chain(outputs)
        .chain(colored_outputs)
        .chain(std::iter::once(TxRow::new(&txid, height as u32).to_row()))
}

pub fn index_block<'a>(block: &'a Block, height: usize) -> impl 'a + Iterator<Item = Row> {
    let blockhash = block.bitcoin_hash();
    // Persist block hash and header
    let row = Row {
        key: bincode::serialize(&BlockKey {
            code: b'B',
            hash: full_hash(&blockhash[..]),
        })
        .unwrap(),
        value: serialize(&block.header),
    };
    block
        .txdata
        .iter()
        .flat_map(move |txn| index_transaction(&txn, height))
        .chain(std::iter::once(row))
}

pub fn last_indexed_block(blockhash: &BlockHash) -> Row {
    // Store last indexed block (i.e. all previous blocks were indexed)
    Row {
        key: b"L".to_vec(),
        value: serialize(blockhash),
    }
}

pub fn read_indexed_blockhashes(store: &dyn ReadStore) -> HashSet<BlockHash> {
    let mut result = HashSet::new();
    for row in store.scan(b"B") {
        let key: BlockKey = bincode::deserialize(&row.key).unwrap();
        result.insert(deserialize(&key.hash).unwrap());
    }
    result
}

fn read_indexed_headers(store: &dyn ReadStore) -> HeaderList {
    let latest_blockhash: BlockHash = match store.get(b"L") {
        // latest blockheader persisted in the DB.
        Some(row) => deserialize(&row).unwrap(),
        None => BlockHash::default(),
    };
    trace!("latest indexed blockhash: {}", latest_blockhash);
    let mut map = HeaderMap::new();
    for row in store.scan(b"B") {
        let key: BlockKey = bincode::deserialize(&row.key).unwrap();
        let header: BlockHeader = deserialize(&row.value).unwrap();
        map.insert(deserialize(&key.hash).unwrap(), header);
    }
    let mut headers = vec![];
    let null_hash = BlockHash::default();
    let mut blockhash = latest_blockhash;
    while blockhash != null_hash {
        let header = map
            .remove(&blockhash)
            .unwrap_or_else(|| panic!("missing {} header in DB", blockhash));
        blockhash = header.prev_blockhash;
        headers.push(header);
    }
    headers.reverse();
    assert_eq!(
        headers
            .first()
            .map(|h| h.prev_blockhash)
            .unwrap_or(null_hash),
        null_hash
    );
    assert_eq!(
        headers
            .last()
            .map(BitcoinHash::bitcoin_hash)
            .unwrap_or(null_hash),
        latest_blockhash
    );
    let mut result = HeaderList::empty();
    let entries = result.order(headers);
    result.apply(entries, latest_blockhash);
    result
}

struct Stats {
    blocks: Counter,
    txns: Counter,
    vsize: Counter,
    height: Gauge,
    duration: HistogramVec,
}

impl Stats {
    fn new(metrics: &Metrics) -> Stats {
        Stats {
            blocks: metrics.counter(MetricOpts::new(
                "electrs_index_blocks",
                "# of indexed blocks",
            )),
            txns: metrics.counter(MetricOpts::new(
                "electrs_index_txns",
                "# of indexed transactions",
            )),
            vsize: metrics.counter(MetricOpts::new(
                "electrs_index_vsize",
                "# of indexed vbytes",
            )),
            height: metrics.gauge(MetricOpts::new(
                "electrs_index_height",
                "Last indexed block's height",
            )),
            duration: metrics.histogram_vec(
                HistogramOpts::new("electrs_index_duration", "indexing duration (in seconds)"),
                &["step"],
            ),
        }
    }

    fn update(&self, block: &Block, height: usize) {
        self.blocks.inc();
        self.txns.inc_by(block.txdata.len() as i64);
        for tx in &block.txdata {
            self.vsize.inc_by(tx.get_weight() as i64 / 4);
        }
        self.update_height(height);
    }

    fn update_height(&self, height: usize) {
        self.height.set(height as i64);
    }

    fn start_timer(&self, step: &str) -> HistogramTimer {
        self.duration.with_label_values(&[step]).start_timer()
    }
}

pub struct Index {
    // TODO: store also latest snapshot.
    headers: RwLock<HeaderList>,
    daemon: Daemon,
    stats: Stats,
    batch_size: usize,
}

impl Index {
    pub fn load(
        store: &dyn ReadStore,
        daemon: &Daemon,
        metrics: &Metrics,
        batch_size: usize,
    ) -> Result<Index> {
        let stats = Stats::new(metrics);
        let headers = read_indexed_headers(store);
        stats.height.set((headers.len() as i64) - 1);
        Ok(Index {
            headers: RwLock::new(headers),
            daemon: daemon.reconnect()?,
            stats,
            batch_size,
        })
    }

    pub fn reload(&self, store: &dyn ReadStore) {
        let mut headers = self.headers.write().unwrap();
        *headers = read_indexed_headers(store);
    }

    pub fn best_header(&self) -> Option<HeaderEntry> {
        let headers = self.headers.read().unwrap();
        headers.header_by_blockhash(&headers.tip()).cloned()
    }

    pub fn get_header(&self, height: usize) -> Option<HeaderEntry> {
        self.headers
            .read()
            .unwrap()
            .header_by_height(height)
            .cloned()
    }

    pub fn update(&self, store: &impl WriteStore, waiter: &Waiter) -> Result<BlockHash> {
        let daemon = self.daemon.reconnect()?;
        let tip = daemon.getbestblockhash()?;
        let new_headers: Vec<HeaderEntry> = {
            let indexed_headers = self.headers.read().unwrap();
            indexed_headers.order(daemon.get_new_headers(&indexed_headers, &tip)?)
        };
        if let Some(latest_header) = new_headers.last() {
            info!("{:?} ({} left to index)", latest_header, new_headers.len());
        };
        let height_map = HashMap::<BlockHash, usize>::from_iter(
            new_headers.iter().map(|h| (*h.hash(), h.height())),
        );

        let chan = SyncChannel::new(1);
        let sender = chan.sender();
        let blockhashes: Vec<BlockHash> = new_headers.iter().map(|h| *h.hash()).collect();
        let batch_size = self.batch_size;
        let fetcher = spawn_thread("fetcher", move || {
            for chunk in blockhashes.chunks(batch_size) {
                sender
                    .send(daemon.getblocks(&chunk))
                    .expect("failed sending blocks to be indexed");
            }
            sender
                .send(Ok(vec![]))
                .expect("failed sending explicit end of stream");
        });
        loop {
            waiter.poll()?;
            let timer = self.stats.start_timer("fetch");
            let batch = chan
                .receiver()
                .recv()
                .expect("block fetch exited prematurely")?;
            timer.observe_duration();
            if batch.is_empty() {
                break;
            }

            let rows_iter = batch.iter().flat_map(|block| {
                let blockhash = block.bitcoin_hash();
                let height = *height_map
                    .get(&blockhash)
                    .unwrap_or_else(|| panic!("missing header for block {}", blockhash));

                self.stats.update(block, height); // TODO: update stats after the block is indexed
                index_block(block, height).chain(std::iter::once(last_indexed_block(&blockhash)))
            });

            let timer = self.stats.start_timer("index+write");
            store.write(rows_iter);
            timer.observe_duration();
        }
        let timer = self.stats.start_timer("flush");
        store.flush(); // make sure no row is left behind
        timer.observe_duration();

        fetcher.join().expect("block fetcher failed");
        self.headers.write().unwrap().apply(new_headers, tip);
        assert_eq!(tip, self.headers.read().unwrap().tip());
        self.stats
            .update_height(self.headers.read().unwrap().len() - 1);
        Ok(tip)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tapyrus::blockdata::script::Builder;

    #[test]
    fn test_split_colored_script() {
        // for cp2pkh
        let hex = "21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bc76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac";
        let script = Builder::from(hex::decode(hex).unwrap()).into_script();
        let hex = "76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac";
        let expected = Builder::from(hex::decode(hex).unwrap()).into_script();
        assert!(script.is_cp2pkh());
        assert!(expected.is_p2pkh());
        assert_eq!(split_colored_script(&script).unwrap().1, expected);

        // for cp2sh
        let hex = "21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bca9147620a79e8657d066cff10e21228bf983cf546ac687";
        let script = Builder::from(hex::decode(hex).unwrap()).into_script();
        let hex = "a9147620a79e8657d066cff10e21228bf983cf546ac687";
        let expected = Builder::from(hex::decode(hex).unwrap()).into_script();
        assert!(script.is_cp2sh());
        assert!(expected.is_p2sh());
        assert_eq!(split_colored_script(&script).unwrap().1, expected);

        // for p2pkh(non-colored)
        let hex = "76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac";
        let script = Builder::from(hex::decode(hex).unwrap()).into_script();
        assert!(split_colored_script(&script).is_none());
    }

    #[test]
    fn test_index_transaction() {
        let input1 = TxIn::default();

        // cp2pkh
        let hex = "21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bc76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac";
        let script = Builder::from(hex::decode(hex).unwrap()).into_script();
        let output1 = TxOut {
            value: 1,
            script_pubkey: script,
        };

        // cp2sh
        let hex = "21c3ec2fd806701a3f55808cbec3922c38dafaa3070c48c803e9043ee3642c660b46bca9147620a79e8657d066cff10e21228bf983cf546ac687";
        let script = Builder::from(hex::decode(hex).unwrap()).into_script();
        let output2 = TxOut {
            value: 1,
            script_pubkey: script,
        };

        // p2pkh(non-colored)
        let hex = "76a91446c2fbfbecc99a63148fa076de58cf29b0bcf0b088ac";
        let script = Builder::from(hex::decode(hex).unwrap()).into_script();
        let output3 = TxOut {
            value: 1,
            script_pubkey: script,
        };

        // Uncolored Transaction
        let txn = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![input1.clone()],
            output: vec![output3.clone()],
        };
        let height = 1;
        let rows = index_transaction(&txn, height);
        //1 TxRow and 1 TxOutRow
        assert_eq!(rows.count(), 2);

        // Colored Transaction
        let txn = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![input1],
            output: vec![output1, output2, output3],
        };
        let height = 1;
        let rows = index_transaction(&txn, height);
        //1 TxRow and 5 TxOutRow
        assert_eq!(rows.count(), 6);
    }
}
