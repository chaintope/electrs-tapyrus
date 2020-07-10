use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin_hashes::Hash;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use serde_json::Value;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use tapyrus::blockdata::transaction::Transaction;
use tapyrus::blockdata::script::ColorIdentifier;
use tapyrus::consensus::encode::deserialize;
use tapyrus::hash_types::{BlockHash, Txid};

use crate::app::App;
use crate::cache::TransactionCache;
use crate::errors::*;
use crate::index::{compute_script_hash, split_colored_script, TxInRow, TxOutRow, TxRow};
use crate::mempool::Tracker;
use crate::metrics::{HistogramOpts, HistogramVec, Metrics};
use crate::open_assets::{OpenAsset, OpenAssetCache, OpenAssetQuery};
use crate::store::{ReadStore, Row};
use crate::util::{FullHash, HashPrefix, HeaderEntry};

pub struct FundingOutput {
    pub txn_id: Txid,
    pub height: u32,
    pub output_index: usize,
    pub value: u64,
    pub color_id: Option<ColorIdentifier>,
    pub asset: Option<OpenAsset>,
}

impl FundingOutput {
    pub fn build(
        txn_id: Txid,
        height: u32,
        output_index: usize,
        value: u64,
        color_id: Option<ColorIdentifier>,
        asset: Option<OpenAsset>,
    ) -> Self {
        FundingOutput {
            txn_id,
            height,
            output_index,
            value,
            color_id,
            asset,
        }
    }
}

impl FundingOutput {
    pub fn to_json(&self, open_assets: bool) -> Value {
        if open_assets && self.asset.is_some() {
            json!({
                "height": self.height,
                "tx_pos": self.output_index,
                "tx_hash": self.txn_id.to_hex(),
                "value": self.value,
                "asset": self.asset.as_ref().expect("failed to read asset"),
            })
        } else if self.color_id.is_some() {
            let color_id = self.color_id.as_ref().expect("failed to get color_id");
            json!({
                "height": self.height,
                "tx_pos": self.output_index,
                "tx_hash": self.txn_id.to_hex(),
                "color_id": format!("{}", color_id),
                "value": self.value,
            })
        } else {
            json!({
                "height": self.height,
                "tx_pos": self.output_index,
                "tx_hash": self.txn_id.to_hex(),
                "value": self.value,
            })
        }
    }
}

type OutPoint = (Txid, usize); // (txid, output_index)

struct SpendingInput {
    txn_id: Txid,
    height: u32,
    funding_output: OutPoint,
    value: u64,
}

#[derive(Clone)]
pub struct Balance {
    confirmed: u64,
    unconfirmed: u64,
    color_id: Option<ColorIdentifier>,
}

impl Serialize for Balance {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        if let Some(color_id) = &self.color_id {
            let mut state = serializer.serialize_struct("Balance", 3)?;
            state.serialize_field("confirmed", &self.confirmed)?;
            state.serialize_field("unconfirmed", &self.unconfirmed)?;
            state.serialize_field("colorid", &format!("{}", color_id))?;
            state.end()
        } else {
            let mut state = serializer.serialize_struct("Balance", 2)?;
            state.serialize_field("confirmed", &self.confirmed)?;
            state.serialize_field("unconfirmed", &self.unconfirmed)?;
            state.end()
        }
    }
}

pub struct Status {
    confirmed: (Vec<FundingOutput>, Vec<SpendingInput>),
    mempool: (Vec<FundingOutput>, Vec<SpendingInput>),
}

fn calc_balance((funding, spending): &(Vec<FundingOutput>, Vec<SpendingInput>)) -> i64 {
    let funded: u64 = funding.iter().map(|output| output.value).sum();
    let spent: u64 = spending.iter().map(|input| input.value).sum();
    funded as i64 - spent as i64
}

impl Status {
    fn funding(&self) -> impl Iterator<Item = &FundingOutput> {
        self.confirmed.0.iter().chain(self.mempool.0.iter())
    }

    fn spending(&self) -> impl Iterator<Item = &SpendingInput> {
        self.confirmed.1.iter().chain(self.mempool.1.iter())
    }

    pub fn confirmed_balance(&self) -> i64 {
        calc_balance(&self.confirmed)
    }

    pub fn mempool_balance(&self) -> i64 {
        calc_balance(&self.mempool)
    }

    pub fn history(&self) -> Vec<(i32, Txid)> {
        let mut txns_map = HashMap::<Txid, i32>::new();
        for f in self.funding() {
            txns_map.insert(f.txn_id, f.height as i32);
        }
        for s in self.spending() {
            txns_map.insert(s.txn_id, s.height as i32);
        }
        let mut txns: Vec<(i32, Txid)> =
            txns_map.into_iter().map(|item| (item.1, item.0)).collect();
        txns.sort_unstable();
        txns
    }

    pub fn unspent(&self) -> Vec<&FundingOutput> {
        let mut outputs_map = HashMap::<OutPoint, &FundingOutput>::new();
        for f in self.funding() {
            outputs_map.insert((f.txn_id, f.output_index), f);
        }
        for s in self.spending() {
            if outputs_map.remove(&s.funding_output).is_none() {
                warn!("failed to remove {:?}", s.funding_output);
            }
        }
        let mut outputs = outputs_map
            .into_iter()
            .map(|item| item.1) // a reference to unspent output
            .collect::<Vec<&FundingOutput>>();
        outputs.sort_unstable_by_key(|out| out.height);
        outputs
    }

    pub fn hash(&self) -> Option<FullHash> {
        let txns = self.history();
        if txns.is_empty() {
            None
        } else {
            let mut hash = FullHash::default();
            let mut sha2 = Sha256::new();
            for (height, txn_id) in txns {
                let part = format!("{}:{}:", txn_id.to_hex(), height);
                sha2.input(part.as_bytes());
            }
            sha2.result(&mut hash);
            Some(hash)
        }
    }

    pub fn balances(&self) -> Vec<Balance> {
        let key_for_native = "000000000000000000000000000000000000000000000000000000000000000000";
        let mut balance_map = HashMap::<String, Balance>::new();
        for output in self.unspent() {
            let key = if let Some(color_id) = &output.color_id {
                format!("{}", color_id)
            } else {
                key_for_native.to_string()
            };

            if !balance_map.contains_key(&key) {
                let balance = Balance {
                    color_id: output.color_id.clone(),
                    confirmed: 0,
                    unconfirmed: 0,
                };
                balance_map.insert(key.clone(), balance);
            }

            let balance = balance_map.get_mut(&key).expect("Can not get balance");

            // output is unconfirmed?
            if output.height == 0 {
                balance.unconfirmed += output.value;
            } else {
                balance.confirmed += output.value;
            }
        }
        let mut outputs = balance_map
            .into_iter()
            .map(|item| item.1)
            .collect::<Vec<Balance>>();
        outputs.sort_unstable_by_key(|out| out.color_id.clone());
        outputs
    }
}

struct TxnHeight {
    txn: Transaction,
    height: u32,
}

fn merklize(left: Sha256dHash, right: Sha256dHash) -> Sha256dHash {
    let data = [&left[..], &right[..]].concat();
    Sha256dHash::hash(&data)
}

fn create_merkle_branch_and_root(
    mut hashes: Vec<Sha256dHash>,
    mut index: usize,
) -> (Vec<Sha256dHash>, Sha256dHash) {
    let mut merkle = vec![];
    while hashes.len() > 1 {
        if hashes.len() % 2 != 0 {
            let last = *hashes.last().unwrap();
            hashes.push(last);
        }
        index = if index % 2 == 0 { index + 1 } else { index - 1 };
        merkle.push(hashes[index]);
        index /= 2;
        hashes = hashes
            .chunks(2)
            .map(|pair| merklize(pair[0], pair[1]))
            .collect()
    }
    (merkle, hashes[0])
}

// TODO: the functions below can be part of ReadStore.
fn txrow_by_txid(store: &dyn ReadStore, txid: &Txid) -> Option<TxRow> {
    let key = TxRow::filter_full(&txid);
    let value = store.get(&key)?;
    Some(TxRow::from_row(&Row { key, value }))
}

fn txrows_by_prefix(store: &dyn ReadStore, txid_prefix: HashPrefix) -> Vec<TxRow> {
    store
        .scan(&TxRow::filter_prefix(txid_prefix))
        .iter()
        .map(|row| TxRow::from_row(row))
        .collect()
}

fn txids_by_script_hash(store: &dyn ReadStore, script_hash: &[u8]) -> Vec<HashPrefix> {
    store
        .scan(&TxOutRow::filter(script_hash))
        .iter()
        .map(|row| TxOutRow::from_row(row).txid_prefix)
        .collect()
}

fn txids_by_funding_output(
    store: &dyn ReadStore,
    txn_id: &Txid,
    output_index: usize,
) -> Vec<HashPrefix> {
    store
        .scan(&TxInRow::filter(&txn_id, output_index))
        .iter()
        .map(|row| TxInRow::from_row(row).txid_prefix)
        .collect()
}

pub struct Query {
    app: Arc<App>,
    tracker: RwLock<Tracker>,
    tx_cache: TransactionCache,
    asset_cache: OpenAssetCache,
    txid_limit: usize,
    duration: HistogramVec,
}

impl Query {
    pub fn new(
        app: Arc<App>,
        metrics: &Metrics,
        tx_cache: TransactionCache,
        asset_cache: OpenAssetCache,
        txid_limit: usize,
    ) -> Arc<Query> {
        Arc::new(Query {
            app,
            tracker: RwLock::new(Tracker::new(metrics)),
            tx_cache,
            asset_cache,
            txid_limit,
            duration: metrics.histogram_vec(
                HistogramOpts::new(
                    "electrs_query_duration",
                    "Time to update mempool (in seconds)",
                ),
                &["type"],
            ),
        })
    }

    fn load_txns_by_prefix(
        &self,
        store: &dyn ReadStore,
        prefixes: Vec<HashPrefix>,
    ) -> Result<Vec<TxnHeight>> {
        let mut txns = vec![];
        for txid_prefix in prefixes {
            for tx_row in txrows_by_prefix(store, txid_prefix) {
                let txid: Txid = deserialize(&tx_row.key.txid).unwrap();
                let txn = self.load_txn(&txid, Some(tx_row.height))?;
                txns.push(TxnHeight {
                    txn,
                    height: tx_row.height,
                })
            }
        }
        Ok(txns)
    }

    fn find_spending_input(
        &self,
        store: &dyn ReadStore,
        funding: &FundingOutput,
    ) -> Result<Option<SpendingInput>> {
        let spending_txns: Vec<TxnHeight> = self.load_txns_by_prefix(
            store,
            txids_by_funding_output(store, &funding.txn_id, funding.output_index),
        )?;
        let mut spending_inputs = vec![];
        for t in &spending_txns {
            for input in t.txn.input.iter() {
                if input.previous_output.txid == funding.txn_id
                    && input.previous_output.vout == funding.output_index as u32
                {
                    spending_inputs.push(SpendingInput {
                        txn_id: t.txn.malfix_txid(),
                        height: t.height,
                        funding_output: (funding.txn_id, funding.output_index),
                        value: funding.value,
                    })
                }
            }
        }
        assert!(spending_inputs.len() <= 1);
        Ok(if spending_inputs.len() == 1 {
            Some(spending_inputs.remove(0))
        } else {
            None
        })
    }

    fn find_funding_outputs(&self, t: &TxnHeight, script_hash: &[u8]) -> Vec<FundingOutput> {
        let mut result = vec![];
        let txn_id = t.txn.malfix_txid();
        let open_assets_colored_outputs = self.get_open_assets_colored_outputs(self.app.network_type(), &t.txn);
        for (index, output) in t.txn.output.iter().enumerate() {
            if output.script_pubkey.is_colored() {
                // For Colored Coin
                if let Some((color_id, script)) = split_colored_script(&output.script_pubkey) {
                    if compute_script_hash(&script[..]) == script_hash {
                        result.push(FundingOutput::build(
                            txn_id,
                            t.height,
                            index,
                            output.value,
                            Some(color_id),
                            open_assets_colored_outputs[index].clone(),
                        ))
                    }
                }
            } else {
                // For Native TPC
                if compute_script_hash(&output.script_pubkey[..]) == script_hash {
                    result.push(FundingOutput::build(
                        txn_id,
                        t.height,
                        index,
                        output.value,
                        None,
                        open_assets_colored_outputs[index].clone(),
                    ))
                }
            }
        }
        result
    }

    fn confirmed_status(
        &self,
        script_hash: &[u8],
    ) -> Result<(Vec<FundingOutput>, Vec<SpendingInput>)> {
        let mut funding = vec![];
        let mut spending = vec![];
        let read_store = self.app.read_store();
        let txid_prefixes = txids_by_script_hash(read_store, script_hash);
        // if the limit is enabled
        if self.txid_limit > 0 && txid_prefixes.len() > self.txid_limit {
            bail!(
                "{}+ transactions found, query may take a long time",
                txid_prefixes.len()
            );
        }
        for t in self.load_txns_by_prefix(read_store, txid_prefixes)? {
            funding.extend(self.find_funding_outputs(&t, script_hash));
        }
        for funding_output in &funding {
            if let Some(spent) = self.find_spending_input(read_store, &funding_output)? {
                spending.push(spent);
            }
        }
        Ok((funding, spending))
    }

    fn mempool_status(
        &self,
        script_hash: &[u8],
        confirmed_funding: &[FundingOutput],
    ) -> Result<(Vec<FundingOutput>, Vec<SpendingInput>)> {
        let mut funding = vec![];
        let mut spending = vec![];
        let tracker = self.tracker.read().unwrap();
        let txid_prefixes = txids_by_script_hash(tracker.index(), script_hash);
        for t in self.load_txns_by_prefix(tracker.index(), txid_prefixes)? {
            funding.extend(self.find_funding_outputs(&t, script_hash));
        }
        // // TODO: dedup outputs (somehow) both confirmed and in mempool (e.g. reorg?)
        for funding_output in funding.iter().chain(confirmed_funding.iter()) {
            if let Some(spent) = self.find_spending_input(tracker.index(), &funding_output)? {
                spending.push(spent);
            }
        }
        Ok((funding, spending))
    }

    pub fn status(&self, script_hash: &[u8]) -> Result<Status> {
        let timer = self
            .duration
            .with_label_values(&["confirmed_status"])
            .start_timer();
        let confirmed = self
            .confirmed_status(script_hash)
            .chain_err(|| "failed to get confirmed status")?;
        timer.observe_duration();

        let timer = self
            .duration
            .with_label_values(&["mempool_status"])
            .start_timer();
        let mempool = self
            .mempool_status(script_hash, &confirmed.0)
            .chain_err(|| "failed to get mempool status")?;
        timer.observe_duration();

        Ok(Status { confirmed, mempool })
    }

    fn lookup_confirmed_blockhash(
        &self,
        tx_hash: &Txid,
        block_height: Option<u32>,
    ) -> Result<Option<BlockHash>> {
        let blockhash = if self.tracker.read().unwrap().get_txn(&tx_hash).is_some() {
            None // found in mempool (as unconfirmed transaction)
        } else {
            // Lookup in confirmed transactions' index
            let height = match block_height {
                Some(height) => height,
                None => {
                    txrow_by_txid(self.app.read_store(), &tx_hash)
                        .chain_err(|| format!("not indexed tx {}", tx_hash))?
                        .height
                }
            };
            let header = self
                .app
                .index()
                .get_header(height as usize)
                .chain_err(|| format!("missing header at height {}", height))?;
            Some(*header.hash())
        };
        Ok(blockhash)
    }

    // Internal API for transaction retrieval
    pub(crate) fn load_txn(&self, txid: &Txid, block_height: Option<u32>) -> Result<Transaction> {
        let _timer = self.duration.with_label_values(&["load_txn"]).start_timer();
        self.tx_cache.get_or_else(&txid, || {
            let blockhash = self.lookup_confirmed_blockhash(txid, block_height)?;
            let value: Value = self
                .app
                .daemon()
                .gettransaction_raw(txid, blockhash, /*verbose*/ false)?;
            let value_hex: &str = value.as_str().chain_err(|| "non-string tx")?;
            hex::decode(&value_hex).chain_err(|| "non-hex tx")
        })
    }

    pub(crate) fn load_assets(&self, txn: &Transaction) -> Result<Vec<Option<OpenAsset>>> {
        // TODO: use DBStore for improving performance.
        let txid = txn.malfix_txid();
        self.asset_cache.get_or_else(&txid, || {
            Ok(self.get_open_assets_colored_outputs(self.app.network_type(), &txn))
        })
    }

    // Public API for transaction retrieval (for Electrum RPC)
    pub fn get_transaction(&self, tx_hash: &Txid, verbose: bool) -> Result<Value> {
        let _timer = self
            .duration
            .with_label_values(&["get_transaction"])
            .start_timer();
        let blockhash = self.lookup_confirmed_blockhash(tx_hash, /*block_height*/ None)?;
        self.app
            .daemon()
            .gettransaction_raw(tx_hash, blockhash, verbose)
    }

    pub fn get_headers(&self, heights: &[usize]) -> Vec<HeaderEntry> {
        let _timer = self
            .duration
            .with_label_values(&["get_headers"])
            .start_timer();
        let index = self.app.index();
        heights
            .iter()
            .filter_map(|height| index.get_header(*height))
            .collect()
    }

    pub fn get_best_header(&self) -> Result<HeaderEntry> {
        let last_header = self.app.index().best_header();
        Ok(last_header.chain_err(|| "no headers indexed")?.clone())
    }

    pub fn get_merkle_proof(&self, tx_hash: &Txid, height: usize) -> Result<(Vec<Txid>, usize)> {
        let header_entry = self
            .app
            .index()
            .get_header(height)
            .chain_err(|| format!("missing block #{}", height))?;
        let txids = self.app.daemon().getblocktxids(&header_entry.hash())?;
        let pos = txids
            .iter()
            .position(|txid| txid == tx_hash)
            .chain_err(|| format!("missing txid {}", tx_hash))?;
        let hashes = txids.iter().map(|txid| txid.as_hash()).collect();
        let (branch, _root) = create_merkle_branch_and_root(hashes, pos);
        Ok((branch.iter().map(|&h| Txid::from_hash(h)).collect(), pos))
    }

    pub fn get_header_merkle_proof(
        &self,
        height: usize,
        cp_height: usize,
    ) -> Result<(Vec<BlockHash>, BlockHash)> {
        if cp_height < height {
            bail!("cp_height #{} < height #{}", cp_height, height);
        }

        let best_height = self.get_best_header()?.height();
        if best_height < cp_height {
            bail!(
                "cp_height #{} above best block height #{}",
                cp_height,
                best_height
            );
        }

        let heights: Vec<usize> = (0..=cp_height).collect();
        let header_hashes: Vec<Sha256dHash> = self
            .get_headers(&heights)
            .into_iter()
            .map(|h| *h.hash())
            .map(|h| h.as_hash())
            .collect();
        assert_eq!(header_hashes.len(), heights.len());
        let (branch, root) = create_merkle_branch_and_root(header_hashes, height);
        Ok((
            branch.iter().map(|&h| BlockHash::from_hash(h)).collect(),
            BlockHash::from_hash(root),
        ))
    }

    pub fn get_id_from_pos(
        &self,
        height: usize,
        tx_pos: usize,
        want_merkle: bool,
    ) -> Result<(Txid, Vec<Txid>)> {
        let header_entry = self
            .app
            .index()
            .get_header(height)
            .chain_err(|| format!("missing block #{}", height))?;

        let txids = self.app.daemon().getblocktxids(header_entry.hash())?;
        let txid = *txids
            .get(tx_pos)
            .chain_err(|| format!("No tx in position #{} in block #{}", tx_pos, height))?;
        let hashes = txids.iter().map(|txid| txid.as_hash()).collect();

        let branch = if want_merkle {
            create_merkle_branch_and_root(hashes, tx_pos).0
        } else {
            vec![]
        };
        Ok((txid, branch.iter().map(|&h| Txid::from_hash(h)).collect()))
    }

    pub fn broadcast(&self, txn: &Transaction) -> Result<Txid> {
        self.app.daemon().broadcast(txn)
    }

    pub fn update_mempool(&self) -> Result<()> {
        let _timer = self
            .duration
            .with_label_values(&["update_mempool"])
            .start_timer();
        self.tracker.write().unwrap().update(self.app.daemon())
    }

    /// Returns [vsize, fee_rate] pairs (measured in vbytes and satoshis).
    pub fn get_fee_histogram(&self) -> Vec<(f32, u32)> {
        self.tracker.read().unwrap().fee_histogram().clone()
    }

    // Fee rate [BTC/kB] to be confirmed in `blocks` from now.
    pub fn estimate_fee(&self, blocks: usize) -> f64 {
        let mut total_vsize = 0u32;
        let mut last_fee_rate = 0.0;
        let blocks_in_vbytes = (blocks * 1_000_000) as u32; // assume ~1MB blocks
        for (fee_rate, vsize) in self.tracker.read().unwrap().fee_histogram() {
            last_fee_rate = *fee_rate;
            total_vsize += vsize;
            if total_vsize >= blocks_in_vbytes {
                break; // under-estimate the fee rate a bit
            }
        }
        (last_fee_rate as f64) * 1e-5 // [BTC/kB] = 10^5 [sat/B]
    }

    pub fn get_banner(&self) -> Result<String> {
        self.app.get_banner()
    }

    pub fn get_relayfee(&self) -> Result<f64> {
        self.app.daemon().get_relayfee()
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;
    use tapyrus::hash_types::Txid;
    use tapyrus::blockdata::script::{ColorIdentifier, Builder};
    use tapyrus::blockdata::transaction::OutPoint;

    use crate::open_assets::test_helper::*;
    use crate::open_assets::OpenAssetFilter;
    use crate::query::{FundingOutput, SpendingInput, Status};


    fn status() -> Status {
        let txid1 =
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let txid2 =
            Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();

        let reissuable = ColorIdentifier::reissuable(Builder::default().into_script());
        let nft = ColorIdentifier::nft(OutPoint::default());
        
        let confirmed_fundings: Vec<FundingOutput> = vec![
            FundingOutput::build(txid1, 10, 0, 10, Some(reissuable.clone()), None),
            FundingOutput::build(txid1, 10, 1, 1, Some(nft.clone()), None),
            FundingOutput::build(txid1, 10, 2, 20, None, None),
            FundingOutput::build(txid1, 10, 3, 30, Some(reissuable.clone()), None),
            FundingOutput::build(txid1, 10, 4, 40, None, None),
        ];
        let confirmed_spendings: Vec<SpendingInput> = Vec::new();
        let unconfirmed_fundings: Vec<FundingOutput> = vec![
            FundingOutput::build(txid2, 0, 0, 50, Some(reissuable.clone()), None),
            FundingOutput::build(txid2, 0, 1, 20, None, None),
            FundingOutput::build(txid2, 0, 2, 15, Some(reissuable.clone()), None),
            FundingOutput::build(txid2, 0, 3, 20, None, None),
        ];
        let unconfirmed_spendings: Vec<SpendingInput> = Vec::new();
        Status {
            confirmed: (confirmed_fundings, confirmed_spendings),
            mempool: (unconfirmed_fundings, unconfirmed_spendings),
        }
    }

    fn status_with_openassets() -> Status {
        let txid1 =
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let txid2 =
            Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();

        let confirmed_fundings: Vec<FundingOutput> = vec![
            FundingOutput::build(txid1, 0, 1, 2, None, None),
            FundingOutput::build(txid1, 3, 4, 5, None, asset_1(6, empty_metadata())),
            FundingOutput::build(txid1, 7, 8, 9, None, asset_1(10, empty_metadata())),
        ];
        let confirmed_spendings: Vec<SpendingInput> = Vec::new();
        let unconfirmed_fundings: Vec<FundingOutput> = vec![
            FundingOutput::build(txid2, 11, 12, 13, None, None),
            FundingOutput::build(txid2, 14, 15, 16, None, asset_1(17, empty_metadata())),
            FundingOutput::build(txid2, 18, 19, 20, None, asset_1(21, empty_metadata())),
        ];
        let unconfirmed_spendings: Vec<SpendingInput> = Vec::new();
        Status {
            confirmed: (confirmed_fundings, confirmed_spendings),
            mempool: (unconfirmed_fundings, unconfirmed_spendings),
        }
    }

    #[test]
    fn test_balance() {
        let status = status();
        let balances = status.balances();
        assert_eq!(balances.len(), 3);
        assert!(balances[0].color_id.is_none());
        assert_eq!(balances[0].confirmed, 60);
        assert_eq!(balances[0].unconfirmed, 40);
        assert_eq!(balances[1].color_id, Some(ColorIdentifier::reissuable(Builder::default().into_script())));
        assert_eq!(balances[1].confirmed, 40);
        assert_eq!(balances[1].unconfirmed, 65);
        assert_eq!(balances[2].color_id, Some(ColorIdentifier::nft(OutPoint::default())));
        assert_eq!(balances[2].confirmed, 1);
        assert_eq!(balances[2].unconfirmed, 0);
    }

    #[test]
    fn test_open_assets_colored_unspent() {
        let txid1 =
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let txid2 =
            Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();

        let status = status_with_openassets();
        let unspents = status.open_assets_colored_unspent();
        assert_eq!(unspents.len(), 4);
        assert_eq!(unspents[0].txn_id, txid1);
        assert_eq!(unspents[0].height, 3);
        assert_eq!(unspents[0].value, 5);
        assert_eq!(unspents[0].asset.as_ref().unwrap().asset_quantity, 6);
        assert_eq!(unspents[1].txn_id, txid1);
        assert_eq!(unspents[1].height, 7);
        assert_eq!(unspents[1].value, 9);
        assert_eq!(unspents[1].asset.as_ref().unwrap().asset_quantity, 10);
        assert_eq!(unspents[2].txn_id, txid2);
        assert_eq!(unspents[2].height, 14);
        assert_eq!(unspents[2].value, 16);
        assert_eq!(unspents[2].asset.as_ref().unwrap().asset_quantity, 17);
        assert_eq!(unspents[3].txn_id, txid2);
        assert_eq!(unspents[3].height, 18);
        assert_eq!(unspents[3].value, 20);
        assert_eq!(unspents[3].asset.as_ref().unwrap().asset_quantity, 21);
    }

    #[test]
    fn test_open_assets_uncolored_unspent() {
        let txid1 =
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let txid2 =
            Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();

        let status = status_with_openassets();
        let unspents = status.open_assets_uncolored_unspent();
        assert_eq!(unspents.len(), 2);
        assert_eq!(unspents[0].txn_id, txid1);
        assert_eq!(unspents[0].height, 0);
        assert_eq!(unspents[0].value, 2);
        assert_eq!(unspents[0].asset, None);
        assert_eq!(unspents[1].txn_id, txid2);
        assert_eq!(unspents[1].height, 11);
        assert_eq!(unspents[1].value, 13);
        assert_eq!(unspents[1].asset, None);
    }

    #[test]
    fn test_to_json() {
        let txid =
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let output = FundingOutput::build(txid, 0, 1, 2, None, None);
        let value = output.to_json(false);
        assert_json_eq!(
            value,
            json!({
                "height": 0,
                "tx_pos": 1,
                "value": 2,
                "tx_hash": "0000000000000000000000000000000000000000000000000000000000000000"
            }),
        );
    }

    #[test]
    fn test_asset_to_json() {
        let txid =
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let output = FundingOutput::build(txid, 0, 1, 2, None, asset_1(3, url_metadata()));
        let value = output.to_json(true);
        assert_json_eq!(
            value,
            json!({
                "height": 0,
                "tx_pos": 1,
                "value": 2,
                "tx_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                "asset": {
                    "asset_id": "ALn3aK1fSuG27N96UGYB1kUYUpGKRhBuBC",
                    "asset_quantity": 3,
                    "metadata": {
                        "hex": "753d68747470733a2f2f6370722e736d2f35596753553150672d71",
                        "utf8": "u=https://cpr.sm/5YgSU1Pg-q"
                    }
                }
            }),
        );
    }
}
