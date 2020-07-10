use crate::errors::*;
use crate::query::{FundingOutput, Query, Status};
use lru::LruCache;
use openassets_tapyrus::openassets::asset_id::AssetId;
use openassets_tapyrus::openassets::marker_output::{Metadata, TxOutExt};
use serde::ser::SerializeStruct;
use serde::{Serialize, Serializer};
use std::sync::Mutex;
use tapyrus::blockdata::transaction::{Transaction, TxOut};
use tapyrus::hash_types::Txid;
use tapyrus::network::constants::Network;

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

pub struct OpenAssetCache {
    map: Mutex<LruCache<Txid, Vec<Option<OpenAsset>>>>,
}

impl OpenAssetCache {
    pub fn new(capacity: usize) -> OpenAssetCache {
        OpenAssetCache {
            map: Mutex::new(LruCache::new(capacity)),
        }
    }

    pub fn get_or_else<F>(&self, txid: &Txid, load_assets_func: F) -> Result<Vec<Option<OpenAsset>>>
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

pub trait OpenAssetFilter {
    fn open_assets_colored_unspent(&self) -> Vec<&FundingOutput>;
    fn open_assets_uncolored_unspent(&self) -> Vec<&FundingOutput>;
}

impl OpenAssetFilter for Status {
    fn open_assets_colored_unspent(&self) -> Vec<&FundingOutput> {
        self.unspent().iter().filter_map(|&o| o.open_assets_colored()).collect()
    }

    fn open_assets_uncolored_unspent(&self) -> Vec<&FundingOutput> {
        self.unspent()
            .iter()
            .filter_map(|&o| o.open_assets_uncolored())
            .collect()
    }
}

pub trait OpenAssetOutput {
    fn open_assets_colored(&self) -> Option<&Self>;
    fn open_assets_uncolored(&self) -> Option<&Self>;
}

impl OpenAssetOutput for FundingOutput {
    fn open_assets_colored(&self) -> Option<&Self> {
        if self.asset.is_some() {
            Some(self)
        } else {
            None
        }
    }

    fn open_assets_uncolored(&self) -> Option<&Self> {
        if self.asset.is_none() {
            Some(self)
        } else {
            None
        }
    }
}

pub trait OpenAssetQuery {
    fn get_open_assets_colored_outputs(
        &self,
        network_type: Network,
        txn: &Transaction,
    ) -> Vec<Option<OpenAsset>>;
    fn get_output(&self, txid: &Txid, index: u32) -> (TxOut, Option<OpenAsset>);
}

impl OpenAssetQuery for Query {
    fn get_open_assets_colored_outputs(
        &self,
        network_type: Network,
        txn: &Transaction,
    ) -> Vec<Option<OpenAsset>> {
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
                    return compute_assets(
                        prev_outs,
                        i,
                        txn,
                        marker.quantities,
                        network_type,
                        &marker.metadata,
                    );
                }
            }
            txn.output.iter().map(|_| None).collect()
        }
    }

    fn get_output(&self, txid: &Txid, index: u32) -> (TxOut, Option<OpenAsset>) {
        let txn = self.load_txn(txid, None).expect("txn not found");
        let colored_outputs = self.load_assets(&txn).expect("asset not found");
        (
            txn.output[index as usize].clone(),
            colored_outputs[index as usize].clone(),
        )
    }
}
pub fn compute_assets(
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

#[cfg(test)]
pub mod test_helper {
    use super::*;

    use openassets_tapyrus::openassets::marker_output::{Metadata, Payload};
    use std::str::FromStr;
    use tapyrus::blockdata::script::{Builder, Script};
    use tapyrus::blockdata::transaction::{OutPoint, TxIn};
    use tapyrus::consensus::deserialize;
    use tapyrus::hash_types::Txid;
    use tapyrus::network::constants::Network;

    pub fn asset_1(quantity: u64, metadata: Metadata) -> Option<OpenAsset> {
        let hex = "76a914010966776006953d5567439e5e39f86a0d273bee88ac";
        let script = Builder::from(hex::decode(hex).unwrap()).into_script();
        Some(OpenAsset {
            asset_id: AssetId::new(&script, Network::Prod),
            asset_quantity: quantity,
            metadata: metadata,
        })
    }

    pub fn asset_2(quantity: u64, metadata: Metadata) -> Option<OpenAsset> {
        let hex = "76a914b60fd86c7464b08d83d98ebeb59655d71be3b22688ac";
        let script = Builder::from(hex::decode(hex).unwrap()).into_script();
        Some(OpenAsset {
            asset_id: AssetId::new(&script, Network::Prod),
            asset_quantity: quantity,
            metadata: metadata,
        })
    }

    pub fn asset_3(quantity: u64, metadata: Metadata) -> Option<OpenAsset> {
        let hex = "76a9149f00983b75904599a5e9c2e53c8b1002fc42e9ac88ac";
        let script = Builder::from(hex::decode(hex).unwrap()).into_script();
        Some(OpenAsset {
            asset_id: AssetId::new(&script, Network::Prod),
            asset_quantity: quantity,
            metadata: metadata,
        })
    }

    pub fn default_input(index: u32) -> TxIn {
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

    pub fn empty_metadata() -> Metadata {
        let payload_bytes = hex::decode("4f4101000000").unwrap();
        let payload: std::result::Result<Payload, tapyrus::consensus::encode::Error> =
            deserialize(&payload_bytes);
        payload.unwrap().metadata
    }

    pub fn url_metadata() -> Metadata {
        let payload_bytes =
            hex::decode("4f4101000364007b1b753d68747470733a2f2f6370722e736d2f35596753553150672d71")
                .unwrap();
        let payload: std::result::Result<Payload, tapyrus::consensus::encode::Error> =
            deserialize(&payload_bytes);
        payload.unwrap().metadata
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use hex;
    use openassets_tapyrus::openassets::asset_id::AssetId;
    use std::str::FromStr;
    use tapyrus::blockdata::script::Builder;
    use tapyrus::blockdata::script::Script;
    use tapyrus::blockdata::transaction::{Transaction, TxOut};
    use tapyrus::hash_types::Txid;
    use tapyrus::network::constants::Network;

    use crate::open_assets::test_helper::*;

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
        let assets = compute_assets(
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
        let assets = compute_assets(
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
        let assets = compute_assets(
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
        let assets = compute_assets(
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
