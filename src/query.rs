use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin_hashes::Hash;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use lru::LruCache;
use openassets_tapyrus::openassets::asset_id::AssetId;
use openassets_tapyrus::openassets::marker_output::{Metadata, TxOutExt};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use tapyrus::blockdata::transaction::Transaction;
use tapyrus::blockdata::transaction::TxOut;
use tapyrus::consensus::encode::deserialize;
use tapyrus::hash_types::{BlockHash, Txid};
use tapyrus::network::constants::Network;

use crate::app::App;
use crate::cache::TransactionCache;
use crate::errors::*;
use crate::index::{compute_script_hash, TxInRow, TxOutRow, TxRow};
use crate::mempool::Tracker;
use crate::metrics::{HistogramOpts, HistogramVec, Metrics};
use crate::store::{ReadStore, Row};
use crate::util::{FullHash, HashPrefix, HeaderEntry};

pub struct FundingOutput {
    pub txn_id: Txid,
    pub height: u32,
    pub output_index: usize,
    pub value: u64,
    pub asset: Option<OpenAsset>,
}

impl FundingOutput {
    pub fn build(
        txn_id: Txid,
        height: u32,
        output_index: usize,
        value: u64,
        asset: Option<OpenAsset>,
    ) -> Self {
        FundingOutput {
            txn_id,
            height,
            output_index,
            value,
            asset,
        }
    }

    pub fn colored(&self) -> Option<&Self> {
        if self.asset.is_some() {
            Some(self)
        } else {
            None
        }
    }

    pub fn uncolored(&self) -> Option<&Self> {
        if self.asset.is_none() {
            Some(self)
        } else {
            None
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

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct OpenAsset {
    pub asset_id: AssetId,
    pub asset_quantity: u64,
    pub metadata: Metadata,
}

impl Serialize for OpenAsset {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("OpenAsset", 3)?;
        state.serialize_field("asset_id", &format!("{}", &self.asset_id))?;
        state.serialize_field("asset_quantity", &self.asset_quantity)?;
        state.serialize_field("metadata", &self.metadata)?;
        state.end()
    }
}

type OutPoint = (Txid, usize); // (txid, output_index)

struct SpendingInput {
    txn_id: Txid,
    height: u32,
    funding_output: OutPoint,
    value: u64,
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

    pub fn colored_unspent(&self) -> Vec<&FundingOutput> {
        self.unspent().iter().filter_map(|&o| o.colored()).collect()
    }

    pub fn uncolored_unspent(&self) -> Vec<&FundingOutput> {
        self.unspent()
            .iter()
            .filter_map(|&o| o.uncolored())
            .collect()
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

pub struct OpenAssetCache {
    map: Mutex<LruCache<Txid, Vec<Option<OpenAsset>>>>,
}

impl OpenAssetCache {
    pub fn new(capacity: usize) -> OpenAssetCache {
        OpenAssetCache {
            map: Mutex::new(LruCache::new(capacity)),
        }
    }

    fn get_or_else<F>(&self, txid: &Txid, load_assets_func: F) -> Result<Vec<Option<OpenAsset>>>
    where
        F: FnOnce() -> Result<Vec<Option<OpenAsset>>>,
    {
        if let Some(assets) = self.map.lock().unwrap().get(txid) {
            return Ok(assets.clone());
        }
        let assets = load_assets_func()?;
        self.map.lock().unwrap().put(*txid, assets.clone());
        Ok(assets)
    }
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
        let colored_outputs = self.get_colored_outputs(&t.txn);
        for (index, output) in t.txn.output.iter().enumerate() {
            if compute_script_hash(&output.script_pubkey[..]) == script_hash {
                result.push(FundingOutput::build(
                    txn_id,
                    t.height,
                    index,
                    output.value,
                    colored_outputs[index].clone(),
                ))
            }
        }
        result
    }

    fn get_colored_outputs(&self, txn: &Transaction) -> Vec<Option<OpenAsset>> {
        if txn.is_coin_base() {
            txn.output.iter().map(|_| None).collect()
        } else {
            for (i, val) in txn.output.iter().enumerate() {
                let payload = val.get_oa_payload();
                if let Ok(marker) = payload {
                    let prev_outs = txn
                        .input
                        .iter()
                        .map(|input| {
                            self.get_output(&input.previous_output.txid, input.previous_output.vout)
                        })
                        .collect();
                    return Query::compute_assets(
                        prev_outs,
                        i,
                        txn,
                        marker.quantities,
                        self.app.network_type(),
                        &marker.metadata,
                    );
                }
            }
            txn.output.iter().map(|_| None).collect()
        }
    }

    fn compute_assets(
        prev_outs: Vec<(TxOut, Option<OpenAsset>)>,
        marker_output_index: usize,
        txn: &Transaction,
        quantities: Vec<u64>,
        network_type: Network,
        metadata: &Metadata,
    ) -> Vec<Option<OpenAsset>> {
        assert!(quantities.len() <= txn.output.len() - 1);
        assert!(!prev_outs.is_empty());

        let mut result = Vec::new();

        //Issuance outputs
        let issuance_asset_id = AssetId::new(
            &prev_outs
                .first()
                .expect("previous outputs is not found")
                .0
                .script_pubkey,
            network_type,
        );
        for i in 0..marker_output_index {
            let asset = if i < quantities.len() && quantities[i] > 0 {
                Some(OpenAsset {
                    asset_id: issuance_asset_id.clone(),
                    asset_quantity: quantities[i],
                    metadata: metadata.clone(),
                })
            } else {
                None
            };
            result.push(asset);
        }

        //Marker outputs
        result.push(None);

        //Transfer outputs
        let mut input_enum = prev_outs.iter();
        let mut input_units_left = 0;
        let mut current_input = None;
        for i in (marker_output_index + 1)..(quantities.len() + 1) {
            let quantity = quantities[i - 1];
            let mut output_units_left = quantity;
            let mut asset_id: Option<AssetId> = None;
            while output_units_left > 0 {
                if input_units_left == 0 {
                    current_input = input_enum.next();
                    if let Some((_, Some(asset))) = current_input {
                        input_units_left = asset.asset_quantity;
                    }
                }
                if let Some((_, Some(asset))) = current_input {
                    let progress = if input_units_left < output_units_left {
                        input_units_left
                    } else {
                        output_units_left
                    };
                    output_units_left -= progress;
                    input_units_left -= progress;
                    if asset_id.is_none() {
                        asset_id = Some(asset.asset_id.clone());
                    } else if asset_id != Some(asset.asset_id.clone()) {
                        panic!("invalid asset");
                    }
                }
            }
            let asset = if asset_id.is_some() && quantity > 0 {
                Some(OpenAsset {
                    asset_id: asset_id.unwrap(),
                    asset_quantity: quantity,
                    metadata: metadata.clone(),
                })
            } else {
                None
            };
            result.push(asset);
        }

        //Uncolored outputs
        for _ in (quantities.len() + 1)..txn.output.len() {
            result.push(None);
        }
        result
    }

    fn get_output(&self, txid: &Txid, index: u32) -> (TxOut, Option<OpenAsset>) {
        let txn = self.load_txn(txid, None).expect("txn not found");
        let colored_outputs = self.load_assets(&txn).expect("asset not found");
        (
            txn.output[index as usize].clone(),
            colored_outputs[index as usize].clone(),
        )
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
    fn load_txn(&self, txid: &Txid, block_height: Option<u32>) -> Result<Transaction> {
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

    fn load_assets(&self, txn: &Transaction) -> Result<Vec<Option<OpenAsset>>> {
        // TODO: use DBStore for improving performance.
        let txid = txn.malfix_txid();
        self.asset_cache
            .get_or_else(&txid, || Ok(self.get_colored_outputs(&txn)))
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
    use hex;
    use openassets_tapyrus::openassets::marker_output::{Metadata, Payload};
    use std::str::FromStr;
    use tapyrus::blockdata::script::Builder;
    use tapyrus::blockdata::script::Script;
    use tapyrus::blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut};
    use tapyrus::consensus::deserialize;
    use tapyrus::hash_types::Txid;
    use tapyrus::network::constants::Network;

    use crate::errors::*;
    use crate::query::{OpenAsset, OpenAssetCache, AssetId, FundingOutput, Query, SpendingInput, Status};

    fn status() -> Status {
        let txid1 =
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let txid2 =
            Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();

        let confirmed_fundings: Vec<FundingOutput> = vec![
            FundingOutput::build(txid1, 0, 1, 2, None),
            FundingOutput::build(txid1, 3, 4, 5, asset_1(6, empty_metadata())),
            FundingOutput::build(txid1, 7, 8, 9, asset_1(10, empty_metadata())),
        ];
        let confirmed_spendings: Vec<SpendingInput> = Vec::new();
        let unconfirmed_fundings: Vec<FundingOutput> = vec![
            FundingOutput::build(txid2, 11, 12, 13, None),
            FundingOutput::build(txid2, 14, 15, 16, asset_1(17, empty_metadata())),
            FundingOutput::build(txid2, 18, 19, 20, asset_1(21, empty_metadata())),
        ];
        let unconfirmed_spendings: Vec<SpendingInput> = Vec::new();
        Status {
            confirmed: (confirmed_fundings, confirmed_spendings),
            mempool: (unconfirmed_fundings, unconfirmed_spendings),
        }
    }

    #[test]
    fn test_colored_unspent() {
        let txid1 =
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let txid2 =
            Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();

        let status = status();
        let unspents = status.colored_unspent();
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
    fn test_uncolored_unspent() {
        let txid1 =
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let txid2 =
            Txid::from_str("1111111111111111111111111111111111111111111111111111111111111111")
                .unwrap();

        let status = status();
        let unspents = status.uncolored_unspent();
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
        let output = FundingOutput::build(txid, 0, 1, 2, None);
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
        let output = FundingOutput::build(txid, 0, 1, 2, asset_1(3, url_metadata()));
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

    #[test]
    fn test_open_asset_cache() {
        let asset_cache = OpenAssetCache::new(10);
        let txid =
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap();
        let asset = OpenAsset {
            asset_id: AssetId::new(&Script::new(), Network::Prod),
            asset_quantity: 1,
            metadata: empty_metadata(),
        };
        let result = asset_cache.get_or_else(&txid, || Ok(vec![Some(asset.clone())]));
        match result {
            Ok(assets) => {
                let expected = assets.first().unwrap().as_ref().unwrap();
                assert!(*expected == asset);
            }
            _ => {
                panic!("error");
            }
        }
        //Use openassets in cache
        let result2 = asset_cache.get_or_else(&txid, || {
            Err(Error(
                ErrorKind::Connection("test".to_string()),
                error_chain::State::default(),
            ))
        });
        match result2 {
            Ok(assets) => {
                let expected = assets.first().unwrap().as_ref().unwrap();
                assert!(*expected == asset);
            }
            _ => panic!("error"),
        }
    }

    fn asset_1(quantity: u64, metadata: Metadata) -> Option<OpenAsset> {
        let hex = "76a914010966776006953d5567439e5e39f86a0d273bee88ac";
        let script = Builder::from(hex::decode(hex).unwrap()).into_script();
        Some(OpenAsset {
            asset_id: AssetId::new(&script, Network::Prod),
            asset_quantity: quantity,
            metadata: metadata,
        })
    }

    fn asset_2(quantity: u64, metadata: Metadata) -> Option<OpenAsset> {
        let hex = "76a914b60fd86c7464b08d83d98ebeb59655d71be3b22688ac";
        let script = Builder::from(hex::decode(hex).unwrap()).into_script();
        Some(OpenAsset {
            asset_id: AssetId::new(&script, Network::Prod),
            asset_quantity: quantity,
            metadata: metadata,
        })
    }

    fn asset_3(quantity: u64, metadata: Metadata) -> Option<OpenAsset> {
        let hex = "76a9149f00983b75904599a5e9c2e53c8b1002fc42e9ac88ac";
        let script = Builder::from(hex::decode(hex).unwrap()).into_script();
        Some(OpenAsset {
            asset_id: AssetId::new(&script, Network::Prod),
            asset_quantity: quantity,
            metadata: metadata,
        })
    }

    fn default_input(index: u32) -> TxIn {
        let out_point = OutPoint::new(
            Txid::from_str("0000000000000000000000000000000000000000000000000000000000000000")
                .unwrap(),
            index,
        );
        TxIn {
            previous_output: out_point,
            script_sig: Script::new(),
            sequence: 0,
            witness: vec![],
        }
    }

    fn empty_metadata() -> Metadata {
        let payload_bytes = hex::decode("4f4101000000").unwrap();
        let payload: std::result::Result<Payload, tapyrus::consensus::encode::Error> =
            deserialize(&payload_bytes);
        payload.unwrap().metadata
    }

    fn url_metadata() -> Metadata {
        let payload_bytes =
            hex::decode("4f4101000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71")
                .unwrap();
        let payload: std::result::Result<Payload, tapyrus::consensus::encode::Error> =
            deserialize(&payload_bytes);
        payload.unwrap().metadata
    }

    #[test]
    fn test_compute_assets_transfer() {
        let prev_outs = vec![
            (TxOut::default(), asset_1(10, empty_metadata())),
            (TxOut::default(), asset_2(20, empty_metadata())),
        ];
        let index = 0;

        let valid_marker = TxOut {
            value: 0,
            script_pubkey: Builder::from(
                hex::decode(
                    "6a244f410100030a01131b753d68747470733a2f2f6370722e736d2f35596753553150672d71",
                )
                .unwrap(),
            )
            .into_script(),
        };
        let txn = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![default_input(0), default_input(1)],
            output: vec![
                valid_marker,
                TxOut::default(),
                TxOut::default(),
                TxOut::default(),
            ],
        };
        let quantities = vec![10, 1, 19];
        let assets = Query::compute_assets(
            prev_outs,
            index,
            &txn,
            quantities,
            Network::Prod,
            &url_metadata(),
        );
        assert_eq!(assets.len(), 4);
        assert_eq!(assets[0], None);
        assert_eq!(assets[1], asset_1(10, url_metadata()));
        assert_eq!(assets[2], asset_2(1, url_metadata()));
        assert_eq!(assets[3], asset_2(19, url_metadata()));
    }

    #[test]
    fn test_compute_assets_issuance() {
        let p2pkh = Builder::from(
            hex::decode("76a914010966776006953d5567439e5e39f86a0d273bee88ac").unwrap(),
        )
        .into_script();
        let prev_outs = vec![
            (
                TxOut {
                    value: 1000,
                    script_pubkey: p2pkh,
                },
                None,
            ),
            (TxOut::default(), None),
        ];
        let index = 3;
        let valid_marker = TxOut {
            value: 0,
            script_pubkey: Builder::from(
                hex::decode(
                    "6a244f410100030a01131b753d68747470733a2f2f6370722e736d2f35596753553150672d71",
                )
                .unwrap(),
            )
            .into_script(),
        };

        let txn = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![default_input(0), default_input(1)],
            output: vec![
                TxOut::default(),
                TxOut::default(),
                TxOut::default(),
                valid_marker,
            ],
        };
        let quantities = vec![10, 1, 19];
        let assets = Query::compute_assets(
            prev_outs,
            index,
            &txn,
            quantities,
            Network::Prod,
            &url_metadata(),
        );
        assert_eq!(assets.len(), 4);
        assert_eq!(assets[0], asset_1(10, url_metadata()));
        assert_eq!(assets[1], asset_1(1, url_metadata()));
        assert_eq!(assets[2], asset_1(19, url_metadata()));
        assert_eq!(assets[3], None);
    }

    #[test]
    fn test_compute_assets_both() {
        // Open Assets transaction in
        // https://github.com/OpenAssets/open-assets-protocol/blob/master/specification.mediawiki#example-1
        let p2pkh = Builder::from(
            hex::decode("76a914010966776006953d5567439e5e39f86a0d273bee88ac").unwrap(),
        )
        .into_script();
        let prev_outs = vec![
            (
                TxOut {
                    value: 1000,
                    script_pubkey: p2pkh,
                },
                asset_2(3, empty_metadata()),
            ),
            (TxOut::default(), asset_2(2, empty_metadata())),
            (TxOut::default(), None),
            (TxOut::default(), asset_2(5, empty_metadata())),
            (TxOut::default(), asset_2(3, empty_metadata())),
            (TxOut::default(), asset_3(9, empty_metadata())),
        ];
        let index = 2;
        let valid_marker = TxOut {
            value: 0,
            script_pubkey: Builder::from(
                hex::decode(
                    "6a244f41010006000a060007031b753d68747470733a2f2f6370722e736d2f35596753553150672d71",
                )
                .unwrap(),
            )
            .into_script(),
        };

        let txn = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![
                default_input(0),
                default_input(1),
                default_input(2),
                default_input(3),
                default_input(4),
                default_input(5),
            ],
            output: vec![
                TxOut::default(),
                TxOut::default(),
                valid_marker,
                TxOut::default(),
                TxOut::default(),
                TxOut::default(),
                TxOut::default(),
            ],
        };
        let quantities = vec![0, 10, 6, 0, 7, 3];
        let assets = Query::compute_assets(
            prev_outs,
            index,
            &txn,
            quantities,
            Network::Prod,
            &empty_metadata(),
        );
        assert_eq!(assets.len(), 7);
        assert_eq!(assets[0], None);
        assert_eq!(assets[1], asset_1(10, empty_metadata()));
        assert_eq!(assets[2], None);
        assert_eq!(assets[3], asset_2(6, empty_metadata()));
        assert_eq!(assets[4], None);
        assert_eq!(assets[5], asset_2(7, empty_metadata()));
        assert_eq!(assets[6], asset_3(3, empty_metadata()));
    }

    #[test]
    fn test_compute_assets_contains_uncolored() {
        let prev_outs = vec![
            (TxOut::default(), asset_1(2, empty_metadata())),
            (TxOut::default(), asset_1(5, empty_metadata())),
            (TxOut::default(), asset_2(9, empty_metadata())),
        ];
        let index = 0;
        let valid_marker = TxOut {
            value: 0,
            script_pubkey: Builder::from(
                hex::decode(
                    "6a244f410100030703031b753d68747470733a2f2f6370722e736d2f35596753553150672d71",
                )
                .unwrap(),
            )
            .into_script(),
        };

        let txn = Transaction {
            version: 1,
            lock_time: 0,
            input: vec![default_input(0), default_input(1), default_input(2)],
            output: vec![
                valid_marker,
                TxOut::default(),
                TxOut::default(),
                TxOut::default(),
                TxOut::default(),
                TxOut::default(),
            ],
        };
        let quantities = vec![7, 3, 3];
        let assets = Query::compute_assets(
            prev_outs,
            index,
            &txn,
            quantities,
            Network::Prod,
            &url_metadata(),
        );
        assert_eq!(assets.len(), 6);
        assert_eq!(assets[0], None);
        assert_eq!(assets[1], asset_1(7, url_metadata()));
        assert_eq!(assets[2], asset_2(3, url_metadata()));
        assert_eq!(assets[3], asset_2(3, url_metadata()));
        assert_eq!(assets[4], None);
        assert_eq!(assets[5], None);
    }
}
