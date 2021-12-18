use std::str::FromStr;

use bitcoin::{
    blockdata::transaction::Transaction as BtcTransaction,
    network::constants::Network as BtcNetwork,
    util::address::Address as BtcAddress,
    Txid,
};
use derive_more::{Constructor, Deref, DerefMut};
use eos_chain::AccountName as EosAccountName;
use serde::{Deserialize, Serialize};

use crate::{
    btc_on_eos::utils::convert_u64_to_8_decimal_eos_asset,
    chains::{
        btc::{
            btc_constants::MINIMUM_REQUIRED_SATOSHIS,
            btc_database_utils::get_btc_network_from_db,
            btc_state::BtcState,
            deposit_address_info::DepositInfoHashMap,
        },
        eos::{
            eos_database_utils::get_eos_token_symbol_from_db,
            eos_unit_conversions::convert_eos_asset_to_u64,
            eos_utils::get_symbol_from_eos_asset,
        },
    },
    constants::{FEE_BASIS_POINTS_DIVISOR, SAFE_EOS_ADDRESS},
    fees::fee_utils::sanity_check_basis_points_value,
    traits::DatabaseInterface,
    types::{Byte, Bytes, NoneError, Result},
};

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
    #[cfg(test)]
    pub fn sum(&self) -> u64 {
        self.iter()
            .map(|params| convert_eos_asset_to_u64(&params.amount))
            .collect::<Result<Vec<u64>>>()
            .unwrap()
            .iter()
            .sum()
    }

    pub fn subtract_fees(&self, fee_basis_points: u64) -> Result<Self> {
        self.calculate_fees(sanity_check_basis_points_value(fee_basis_points)?)
            .and_then(|(fees, _)| {
                info!("`BtcOnEosMintingParams` fees: {:?}", fees);
                Ok(Self::new(
                    fees.iter()
                        .zip(self.iter())
                        .map(|(fee, params)| params.subtract_amount(*fee))
                        .collect::<Result<Vec<BtcOnEosMintingParamStruct>>>()?,
                ))
            })
    }

    pub fn calculate_fees(&self, basis_points: u64) -> Result<(Vec<u64>, u64)> {
        info!("✔ Calculating fees in `BtcOnEosMintingParams`...");
        let fees = self
            .iter()
            .map(|minting_params| minting_params.calculate_fee(basis_points))
            .collect::<Result<Vec<u64>>>()?;
        let total_fee = fees.iter().sum();
        info!("✔      Fees: {:?}", fees);
        info!("✔ Total fee: {:?}", fees);
        Ok((fees, total_fee))
    }

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
                .map(|maybe_minting_params| maybe_minting_params.ok_or(NoneError("Could not unwrap minting params!")))
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
    pub fn calculate_fee(&self, basis_points: u64) -> Result<u64> {
        convert_eos_asset_to_u64(&self.amount).map(|amount| (amount * basis_points) / FEE_BASIS_POINTS_DIVISOR)
    }

    pub fn subtract_amount(&self, subtrahend: u64) -> Result<Self> {
        info!("✔ Subtracting {} from `BtcOnEosMintingParamStruct`...", subtrahend);
        let symbol = get_symbol_from_eos_asset(&self.amount);
        let amount = convert_eos_asset_to_u64(&self.amount)?;
        if subtrahend > amount {
            Err(format!("Cannot subtract {} from {}!", subtrahend, amount).into())
        } else {
            let amount_minus_fee = amount - subtrahend;
            info!(
                "✔ Subtracted amount of {} from current minting params amount of {} to get final amount of {}",
                subtrahend, amount, amount_minus_fee
            );
            Ok(Self {
                to: self.to.clone(),
                originating_tx_hash: self.originating_tx_hash.clone(),
                originating_tx_address: self.originating_tx_address.clone(),
                amount: convert_u64_to_8_decimal_eos_asset(amount_minus_fee, symbol),
            })
        }
    }

    pub fn new(
        amount: u64,
        to: String,
        originating_tx_hash: Txid,
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
    use crate::{chains::btc::btc_test_utils::get_sample_btc_on_eos_minting_params, errors::AppError};

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

    #[test]
    fn should_subtract_amount_from_btc_on_eos_minting_params() {
        let params = get_sample_btc_on_eos_minting_params()[0].clone();
        let subtrahend = 1337;
        let result = params.subtract_amount(subtrahend).unwrap();
        let expected_result = "0.00003663 PBTC".to_string();
        assert_eq!(result.to, params.to);
        assert_eq!(result.originating_tx_hash, params.originating_tx_hash);
        assert_eq!(result.originating_tx_address, params.originating_tx_address);
        assert_eq!(result.amount, expected_result);
    }

    #[test]
    fn should_calculate_fee_from_btc_on_eos_minting_param() {
        let params = get_sample_btc_on_eos_minting_params()[0].clone();
        let basis_points = 25;
        let result = params.calculate_fee(basis_points).unwrap();
        let expected_result = 12;
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_calculate_fee_from_btc_on_eos_minting_params() {
        let params = get_sample_btc_on_eos_minting_params();
        let basis_points = 25;
        let (fees, total) = params.calculate_fees(basis_points).unwrap();
        let expected_fees = vec![12, 12, 12];
        let expected_total: u64 = expected_fees.iter().sum();
        assert_eq!(total, expected_total);
        assert_eq!(fees, expected_fees);
    }

    #[test]
    fn should_subtract_fees_from_btc_on_eos_minting_params() {
        let params = get_sample_btc_on_eos_minting_params();
        let basis_points = 25;
        let result = params.subtract_fees(basis_points).unwrap();
        let expected_amount_0 = 4988;
        let expected_amount_1 = 4989;
        assert_eq!(convert_eos_asset_to_u64(&result[0].amount).unwrap(), expected_amount_0);
        assert_eq!(convert_eos_asset_to_u64(&result[1].amount).unwrap(), expected_amount_1);
    }

    #[test]
    fn should_fail_to_subtact_too_large_an_amount_from_btc_on_eos_minting_params() {
        let params = get_sample_btc_on_eos_minting_params()[0].clone();
        let amount = convert_eos_asset_to_u64(&params.amount).unwrap();
        let subtrahend = amount + 1;
        let expected_err = format!("Cannot subtract {} from {}!", subtrahend, amount);
        match params.subtract_amount(subtrahend) {
            Ok(_) => panic!("Should not have suceeded!"),
            Err(AppError::Custom(err)) => assert_eq!(err, expected_err),
            Err(_) => panic!("Wrong error received!"),
        };
    }
}
