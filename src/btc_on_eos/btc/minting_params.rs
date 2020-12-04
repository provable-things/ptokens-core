use crate::{
    btc_on_eos::utils::{convert_eos_asset_to_u64, convert_u64_to_8_decimal_eos_asset},
    chains::{
        btc::{
            btc_constants::MINIMUM_REQUIRED_SATOSHIS,
            btc_database_utils::get_btc_network_from_db,
            btc_state::BtcState,
            deposit_address_info::DepositInfoHashMap,
        },
        eos::eos_database_utils::get_eos_token_symbol_from_db,
    },
    constants::SAFE_EOS_ADDRESS,
    traits::DatabaseInterface,
    types::{Byte, Bytes, NoneError, Result},
};
use bitcoin::{
    blockdata::transaction::Transaction as BtcTransaction,
    hashes::sha256d,
    network::constants::Network as BtcNetwork,
    util::address::Address as BtcAddress,
};
use derive_more::{Constructor, Deref, DerefMut};
use eos_primitives::AccountName as EosAccountName;
use std::str::FromStr;

pub fn parse_minting_params_from_p2sh_deposits_and_add_to_state<D: DatabaseInterface>(
    state: BtcState<D>,
) -> Result<BtcState<D>> {
    info!("✔ Parsing minting params from `p2sh` deposit txs in state...");
    BtcOnEosMintingParams::from_btc_txs(
        state.get_p2sh_deposit_txs()?,
        state.get_deposit_info_hash_map()?,
        get_btc_network_from_db(&state.db)?,
        &get_eos_token_symbol_from_db(&state.db)?,
    )
    .and_then(|minting_params| minting_params.filter_params())
    .and_then(|filtered_params| state.add_btc_on_eos_minting_params(filtered_params))
}

#[derive(Debug, Clone, PartialEq, Eq, Deref, DerefMut, Constructor, Serialize, Deserialize)]
pub struct BtcOnEosMintingParams(pub Vec<BtcOnEosMintingParamStruct>);

impl BtcOnEosMintingParams {
    pub fn to_bytes(&self) -> Result<Bytes> {
        Ok(serde_json::to_vec(&self.0)?)
    }

    pub fn from_bytes(bytes: &[Byte]) -> Result<Self> {
        Ok(serde_json::from_slice(bytes)?)
    }

    pub fn filter_out_value_too_low(&self) -> Result<Self> {
        info!(
            "✔ Filtering out any minting params below a minimum of {} Satoshis...",
            MINIMUM_REQUIRED_SATOSHIS
        );
        Ok(BtcOnEosMintingParams::new(
            self.iter()
                .map(|params| convert_eos_asset_to_u64(&params.amount))
                .collect::<Result<Vec<u64>>>()?
                .into_iter()
                .zip(self.iter())
                .filter(|(amount, params)| match amount >= &MINIMUM_REQUIRED_SATOSHIS {
                    true => true,
                    false => {
                        info!("✘ Filtering minting params ∵ value too low: {:?}", params);
                        false
                    },
                })
                .map(|(_, params)| params)
                .cloned()
                .collect::<Vec<BtcOnEosMintingParamStruct>>(),
        ))
    }

    pub fn fix_params_with_too_short_account_names(&self) -> Result<Self> {
        Ok(BtcOnEosMintingParams::new(
            self.iter()
                .map(|params| match params.to.is_empty() {
                    false => params.clone(),
                    true => {
                        info!("✘ Redirecting to safe address {:?} ∵ name too short:", params);
                        BtcOnEosMintingParamStruct {
                            amount: params.amount.clone(),
                            to: SAFE_EOS_ADDRESS.to_string(),
                            originating_tx_hash: params.originating_tx_hash.clone(),
                            originating_tx_address: params.originating_tx_address.clone(),
                        }
                    },
                })
                .collect::<Vec<BtcOnEosMintingParamStruct>>(),
        ))
    }

    pub fn filter_params(&self) -> Result<Self> {
        self.fix_params_with_too_short_account_names()
            .and_then(|params| params.filter_out_value_too_low())
    }

    fn from_btc_tx(
        p2sh_deposit_containing_tx: &BtcTransaction,
        deposit_info_hash_map: &DepositInfoHashMap,
        btc_network: BtcNetwork,
        eos_token_symbol: &str,
    ) -> Result<BtcOnEosMintingParams> {
        info!("✔ Parsing minting params from single `p2sh` transaction...");
        Ok(BtcOnEosMintingParams::new(
            p2sh_deposit_containing_tx
                .output
                .iter()
                .filter(|tx_out| tx_out.script_pubkey.is_p2sh())
                .map(|p2sh_tx_out| -> Option<BtcOnEosMintingParamStruct> {
                    match BtcAddress::from_script(&p2sh_tx_out.script_pubkey, btc_network) {
                        None => {
                            info!(
                                "✘ Could not derive BTC address from tx: {:?}",
                                p2sh_deposit_containing_tx
                            );
                            None
                        },
                        Some(btc_address) => {
                            info!("✔ BTC address extracted from `tx_out`: {}", btc_address);
                            match deposit_info_hash_map.get(&btc_address) {
                                None => {
                                    info!("✘ BTC address {} not in deposit hash map!", btc_address);
                                    None
                                },
                                Some(deposit_info) => {
                                    info!("✔ Deposit info extracted from hash map: {:?}", deposit_info);
                                    Some(BtcOnEosMintingParamStruct::new(
                                        p2sh_tx_out.value,
                                        deposit_info.address.clone(),
                                        p2sh_deposit_containing_tx.txid(),
                                        btc_address,
                                        eos_token_symbol,
                                    ))
                                },
                            }
                        },
                    }
                })
                .filter(|maybe_minting_params| maybe_minting_params.is_some())
                .map(|maybe_minting_params| {
                    Ok(maybe_minting_params.ok_or(NoneError("Could not unwrap minting params!"))?)
                })
                .collect::<Result<Vec<BtcOnEosMintingParamStruct>>>()?,
        ))
    }

    pub fn from_btc_txs(
        p2sh_deposit_containing_txs: &[BtcTransaction],
        deposit_info_hash_map: &DepositInfoHashMap,
        btc_network: BtcNetwork,
        eos_token_symbol: &str,
    ) -> Result<BtcOnEosMintingParams> {
        info!("✔ Parsing minting params from `p2sh` transactions...");
        Ok(Self::new(
            p2sh_deposit_containing_txs
                .iter()
                .flat_map(|tx| Self::from_btc_tx(tx, deposit_info_hash_map, btc_network, eos_token_symbol))
                .map(|minting_params| minting_params.0)
                .flatten()
                .collect::<Vec<BtcOnEosMintingParamStruct>>(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BtcOnEosMintingParamStruct {
    pub to: String,
    pub amount: String,
    pub originating_tx_hash: String,
    pub originating_tx_address: String,
}

impl BtcOnEosMintingParamStruct {
    pub fn new(
        amount: u64,
        to: String,
        originating_tx_hash: sha256d::Hash,
        originating_tx_address: BtcAddress,
        symbol: &str,
    ) -> BtcOnEosMintingParamStruct {
        BtcOnEosMintingParamStruct {
            to: match EosAccountName::from_str(&to) {
                Ok(_) => to,
                Err(_) => {
                    info!("✘ Error converting '{}' to EOS address!", to);
                    info!("✔ Defaulting to safe EOS address: '{}'", SAFE_EOS_ADDRESS);
                    SAFE_EOS_ADDRESS.to_string()
                },
            },
            amount: convert_u64_to_8_decimal_eos_asset(amount, symbol),
            originating_tx_hash: originating_tx_hash.to_string(),
            originating_tx_address: originating_tx_address.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::btc::btc_test_utils::get_sample_btc_on_eos_minting_params;

    #[test]
    fn should_filter_minting_params() {
        let expected_length_before = 3;
        let expected_length_after = 2;
        let minting_params = get_sample_btc_on_eos_minting_params();
        let length_before = minting_params.len();
        assert_eq!(length_before, expected_length_before);
        let result = minting_params.filter_out_value_too_low().unwrap();
        let length_after = result.len();
        assert_eq!(length_after, expected_length_after);
        result
            .iter()
            .for_each(|params| assert!(convert_eos_asset_to_u64(&params.amount).unwrap() >= MINIMUM_REQUIRED_SATOSHIS));
    }
}
