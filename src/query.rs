use bitcoin_hashes::hex::ToHex;
use bitcoin_hashes::sha256d::Hash as Sha256dHash;
use bitcoin_hashes::Hash;
use crypto::digest::Digest;
use crypto::sha2::Sha256;
use lru::LruCache;
use openassets::openassets::asset_id::AssetId;
use openassets::openassets::marker_output::TxOutExt;
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use serde_json::Value;
use std::collections::HashMap;
use std::sync::{Arc, Mutex, RwLock};
use tapyrus::blockdata::transaction::Transaction;
use tapyrus::blockdata::transaction::TxOut;
use tapyrus::consensus::encode::deserialize;
use tapyrus::network::constants::Network;

use crate::app::App;
use crate::errors::*;
use crate::index::{compute_script_hash, TxInRow, TxOutRow, TxRow};
use crate::mempool::Tracker;
use crate::metrics::Metrics;
use crate::store::{ReadStore, Row};
use crate::util::{FullHash, HashPrefix, HeaderEntry};

pub struct FundingOutput {
    pub txn_id: Sha256dHash,
    pub height: u32,
    pub output_index: usize,
    pub value: u64,
    pub asset: Option<Asset>,
}

impl FundingOutput {
    pub fn build(
        txn_id: Sha256dHash,
        height: u32,
        output_index: usize,
        value: u64,
        asset: Option<Asset>,
    ) -> Self {
        FundingOutput {
            txn_id,
            height,
            output_index,
            value,
            asset,
        }
    }
}

impl FundingOutput {
    pub fn to_json(&self) -> Value {
        if self.asset.is_none() {
            json!({
                "height": self.height,
                "tx_pos": self.output_index,
                "tx_hash": self.txn_id.to_hex(),
                "value": self.value,
            })
        } else {
            json!({
                "height": self.height,
                "tx_pos": self.output_index,
                "tx_hash": self.txn_id.to_hex(),
                "value": self.value,
                "asset": self.asset.as_ref().expect("failed to read asset"),
            })
        }
    }
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Asset {
    pub asset_id: AssetId,
    pub asset_quantity: u64,
}

impl Serialize for Asset {
    fn serialize<S>(&self, serializer: S) -> std::result::Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut state = serializer.serialize_struct("Asset", 2)?;
        state.serialize_field("asset_id", &format!("{}", &self.asset_id))?;
        state.serialize_field("asset_quantity", &self.asset_quantity)?;
        state.end()
    }
}

type OutPoint = (Sha256dHash, usize); // (txid, output_index)

struct SpendingInput {
    txn_id: Sha256dHash,
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

    pub fn history(&self) -> Vec<(i32, Sha256dHash)> {
        let mut txns_map = HashMap::<Sha256dHash, i32>::new();
        for f in self.funding() {
            txns_map.insert(f.txn_id, f.height as i32);
        }
        for s in self.spending() {
            txns_map.insert(s.txn_id, s.height as i32);
        }
        let mut txns: Vec<(i32, Sha256dHash)> =
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
fn txrow_by_txid(store: &dyn ReadStore, txid: &Sha256dHash) -> Option<TxRow> {
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
    txn_id: &Sha256dHash,
    output_index: usize,
) -> Vec<HashPrefix> {
    store
        .scan(&TxInRow::filter(&txn_id, output_index))
        .iter()
        .map(|row| TxInRow::from_row(row).txid_prefix)
        .collect()
}

pub struct TransactionCache {
    map: Mutex<LruCache<Sha256dHash, Transaction>>,
}

impl TransactionCache {
    pub fn new(capacity: usize) -> TransactionCache {
        TransactionCache {
            map: Mutex::new(LruCache::new(capacity)),
        }
    }

    fn get_or_else<F>(&self, txid: &Sha256dHash, load_txn_func: F) -> Result<Transaction>
    where
        F: FnOnce() -> Result<Transaction>,
    {
        if let Some(txn) = self.map.lock().unwrap().get(txid) {
            return Ok(txn.clone());
        }
        let txn = load_txn_func()?;
        self.map.lock().unwrap().put(*txid, txn.clone());
        Ok(txn)
    }
}

pub struct AssetCache {
    map: Mutex<LruCache<Sha256dHash, Vec<Option<Asset>>>>,
}

impl AssetCache {
    pub fn new(capacity: usize) -> AssetCache {
        AssetCache {
            map: Mutex::new(LruCache::new(capacity)),
        }
    }

    fn get_or_else<F>(&self, txid: &Sha256dHash, load_assets_func: F) -> Result<Vec<Option<Asset>>>
    where
        F: FnOnce() -> Result<Vec<Option<Asset>>>,
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
    asset_cache: AssetCache,
    txid_limit: usize,
}

impl Query {
    pub fn new(
        app: Arc<App>,
        metrics: &Metrics,
        tx_cache: TransactionCache,
        asset_cache: AssetCache,
        txid_limit: usize,
    ) -> Arc<Query> {
        Arc::new(Query {
            app,
            tracker: RwLock::new(Tracker::new(metrics)),
            tx_cache,
            asset_cache,
            txid_limit,
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
                let txid: Sha256dHash = deserialize(&tx_row.key.txid).unwrap();
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

    fn get_colored_outputs(&self, txn: &Transaction) -> Vec<Option<Asset>> {
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
                    );
                }
            }
            txn.output.iter().map(|_| None).collect()
        }
    }

    fn compute_assets(
        prev_outs: Vec<(TxOut, Option<Asset>)>,
        marker_output_index: usize,
        txn: &Transaction,
        quantities: Vec<u64>,
        network_type: Network,
    ) -> Vec<Option<Asset>> {
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
                Some(Asset {
                    asset_id: issuance_asset_id.clone(),
                    asset_quantity: quantities[i],
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
                Some(Asset {
                    asset_id: asset_id.unwrap(),
                    asset_quantity: quantity,
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

    fn get_output(&self, txid: &Sha256dHash, index: u32) -> (TxOut, Option<Asset>) {
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
        let confirmed = self
            .confirmed_status(script_hash)
            .chain_err(|| "failed to get confirmed status")?;
        let mempool = self
            .mempool_status(script_hash, &confirmed.0)
            .chain_err(|| "failed to get mempool status")?;
        Ok(Status { confirmed, mempool })
    }

    fn lookup_confirmed_blockhash(
        &self,
        tx_hash: &Sha256dHash,
        block_height: Option<u32>,
    ) -> Result<Option<Sha256dHash>> {
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
    fn load_txn(&self, txid: &Sha256dHash, block_height: Option<u32>) -> Result<Transaction> {
        self.tx_cache.get_or_else(&txid, || {
            let blockhash = self.lookup_confirmed_blockhash(txid, block_height)?;
            self.app.daemon().gettransaction(txid, blockhash)
        })
    }

    fn load_assets(&self, txn: &Transaction) -> Result<Vec<Option<Asset>>> {
        // TODO: use DBStore for improving performance.
        let txid = txn.malfix_txid();
        self.asset_cache
            .get_or_else(&txid, || Ok(self.get_colored_outputs(&txn)))
    }

    // Public API for transaction retrieval (for Electrum RPC)
    pub fn get_transaction(&self, tx_hash: &Sha256dHash, verbose: bool) -> Result<Value> {
        let blockhash = self.lookup_confirmed_blockhash(tx_hash, /*block_height*/ None)?;
        self.app
            .daemon()
            .gettransaction_raw(tx_hash, blockhash, verbose)
    }

    pub fn get_headers(&self, heights: &[usize]) -> Vec<HeaderEntry> {
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

    pub fn get_merkle_proof(
        &self,
        tx_hash: &Sha256dHash,
        height: usize,
    ) -> Result<(Vec<Sha256dHash>, usize)> {
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
        let (branch, _root) = create_merkle_branch_and_root(txids, pos);
        Ok((branch, pos))
    }

    pub fn get_header_merkle_proof(
        &self,
        height: usize,
        cp_height: usize,
    ) -> Result<(Vec<Sha256dHash>, Sha256dHash)> {
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
            .collect();
        assert_eq!(header_hashes.len(), heights.len());
        Ok(create_merkle_branch_and_root(header_hashes, height))
    }

    pub fn get_id_from_pos(
        &self,
        height: usize,
        tx_pos: usize,
        want_merkle: bool,
    ) -> Result<(Sha256dHash, Vec<Sha256dHash>)> {
        let header_entry = self
            .app
            .index()
            .get_header(height)
            .chain_err(|| format!("missing block #{}", height))?;

        let txids = self.app.daemon().getblocktxids(header_entry.hash())?;
        let txid = *txids
            .get(tx_pos)
            .chain_err(|| format!("No tx in position #{} in block #{}", tx_pos, height))?;

        let branch = if want_merkle {
            create_merkle_branch_and_root(txids, tx_pos).0
        } else {
            vec![]
        };
        Ok((txid, branch))
    }

    pub fn broadcast(&self, txn: &Transaction) -> Result<Sha256dHash> {
        self.app.daemon().broadcast(txn)
    }

    pub fn update_mempool(&self) -> Result<()> {
        self.tracker.write().unwrap().update(self.app.daemon())
    }

    /// Returns [vsize, fee_rate] pairs (measured in vbytes and satoshis).
    pub fn get_fee_histogram(&self) -> Vec<(f32, u32)> {
        self.tracker.read().unwrap().fee_histogram().clone()
    }

    // Fee rate [BTC/kB] to be confirmed in `blocks` from now.
    pub fn estimate_fee(&self, blocks: usize) -> f32 {
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
        last_fee_rate * 1e-5 // [BTC/kB] = 10^5 [sat/B]
    }

    pub fn get_banner(&self) -> Result<String> {
        self.app.get_banner()
    }
}

#[cfg(test)]
mod tests {
    use bitcoin_hashes::sha256d::Hash as Sha256dHash;
    use hex;
    use std::str::FromStr;
    use tapyrus::blockdata::script::Builder;
    use tapyrus::blockdata::script::Script;
    use tapyrus::blockdata::transaction::{OutPoint, Transaction, TxIn, TxOut};
    use tapyrus::network::constants::Network;

    use crate::errors::*;
    use crate::query::FundingOutput;
    use crate::query::{Asset, AssetId};
    use crate::query::{AssetCache, Query};

    #[test]
    fn test_to_json() {
        let txid = Sha256dHash::from_str(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let output = FundingOutput::build(txid, 0, 1, 2, None);
        let value = output.to_json();
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
        let txid = Sha256dHash::from_str(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let output = FundingOutput::build(txid, 0, 1, 2, asset_1(3));
        let value = output.to_json();
        assert_json_eq!(
            value,
            json!({
                "height": 0,
                "tx_pos": 1,
                "value": 2,
                "tx_hash": "0000000000000000000000000000000000000000000000000000000000000000",
                "asset": json!({
                    "asset_id": "ALn3aK1fSuG27N96UGYB1kUYUpGKRhBuBC",
                    "asset_quantity": 3
                })
            }),
        );
    }

    #[test]
    fn test_asset_cache() {
        let asset_cache = AssetCache::new(10);
        let txid = Sha256dHash::from_str(
            "0000000000000000000000000000000000000000000000000000000000000000",
        )
        .unwrap();
        let asset = Asset {
            asset_id: AssetId::new(&Script::new(), Network::Bitcoin),
            asset_quantity: 1,
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
        //Use assets in cache
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

    fn asset_1(quantity: u64) -> Option<Asset> {
        let hex = "76a914010966776006953d5567439e5e39f86a0d273bee88ac";
        let script = Builder::from(hex::decode(hex).unwrap()).into_script();
        Some(Asset {
            asset_id: AssetId::new(&script, Network::Bitcoin),
            asset_quantity: quantity,
        })
    }

    fn asset_2(quantity: u64) -> Option<Asset> {
        let hex = "76a914b60fd86c7464b08d83d98ebeb59655d71be3b22688ac";
        let script = Builder::from(hex::decode(hex).unwrap()).into_script();
        Some(Asset {
            asset_id: AssetId::new(&script, Network::Bitcoin),
            asset_quantity: quantity,
        })
    }

    fn asset_3(quantity: u64) -> Option<Asset> {
        let hex = "76a9149f00983b75904599a5e9c2e53c8b1002fc42e9ac88ac";
        let script = Builder::from(hex::decode(hex).unwrap()).into_script();
        Some(Asset {
            asset_id: AssetId::new(&script, Network::Bitcoin),
            asset_quantity: quantity,
        })
    }

    fn default_input(index: u32) -> TxIn {
        let out_point = OutPoint::new(
            Sha256dHash::from_str(
                "0000000000000000000000000000000000000000000000000000000000000000",
            )
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

    #[test]
    fn test_compute_assets_transfer() {
        let prev_outs = vec![
            (TxOut::default(), asset_1(10)),
            (TxOut::default(), asset_2(20)),
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
        let assets = Query::compute_assets(prev_outs, index, &txn, quantities, Network::Bitcoin);
        assert_eq!(assets.len(), 4);
        assert_eq!(assets[0], None);
        assert_eq!(assets[1], asset_1(10));
        assert_eq!(assets[2], asset_2(1));
        assert_eq!(assets[3], asset_2(19));
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
        let assets = Query::compute_assets(prev_outs, index, &txn, quantities, Network::Bitcoin);
        assert_eq!(assets.len(), 4);
        assert_eq!(assets[0], asset_1(10));
        assert_eq!(assets[1], asset_1(1));
        assert_eq!(assets[2], asset_1(19));
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
                asset_2(3),
            ),
            (TxOut::default(), asset_2(2)),
            (TxOut::default(), None),
            (TxOut::default(), asset_2(5)),
            (TxOut::default(), asset_2(3)),
            (TxOut::default(), asset_3(9)),
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
        let assets = Query::compute_assets(prev_outs, index, &txn, quantities, Network::Bitcoin);
        assert_eq!(assets.len(), 7);
        assert_eq!(assets[0], None);
        assert_eq!(assets[1], asset_1(10));
        assert_eq!(assets[2], None);
        assert_eq!(assets[3], asset_2(6));
        assert_eq!(assets[4], None);
        assert_eq!(assets[5], asset_2(7));
        assert_eq!(assets[6], asset_3(3));
    }

    #[test]
    fn test_compute_assets_contains_uncolored() {
        let prev_outs = vec![
            (TxOut::default(), asset_1(2)),
            (TxOut::default(), asset_1(5)),
            (TxOut::default(), asset_2(9)),
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
        let assets = Query::compute_assets(prev_outs, index, &txn, quantities, Network::Bitcoin);
        assert_eq!(assets.len(), 6);
        assert_eq!(assets[0], None);
        assert_eq!(assets[1], asset_1(7));
        assert_eq!(assets[2], asset_2(3));
        assert_eq!(assets[3], asset_2(3));
        assert_eq!(assets[4], None);
        assert_eq!(assets[5], None);
    }
}
