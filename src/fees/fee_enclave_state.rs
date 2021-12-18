use derive_more::{Constructor, Deref};
use serde::{Deserialize, Serialize};

use crate::{
    core_type::CoreType,
    fees::{
        fee_constants::DISABLE_FEES,
        fee_database_utils::FeeDatabaseUtils,
        fee_utils::get_last_withdrawal_date_as_human_readable_string,
    },
    traits::DatabaseInterface,
    types::Result,
};

#[derive(Serialize, Deserialize)]
pub struct FeesEnclaveState {
    fees_enabled: bool,
    fees: FeeStateForTokens,
}

impl FeesEnclaveState {
    pub fn new_for_btc_on_eth<D: DatabaseInterface>(db: &D) -> Result<Self> {
        Ok(Self {
            fees_enabled: !DISABLE_FEES,
            fees: FeeStateForTokens::new_for_btc_on_eth(db)?,
        })
    }

    pub fn new_for_btc_on_eos<D: DatabaseInterface>(db: &D) -> Result<Self> {
        Ok(Self {
            fees_enabled: !DISABLE_FEES,
            fees: FeeStateForTokens::new_for_btc_on_eos(db)?,
        })
    }
}

#[derive(Serialize, Deserialize)]
pub struct FeeStateForToken {
    token_symbol: String,
    accrued_fees: u64,
    peg_in_basis_points: u64,
    peg_out_basis_points: u64,
    accrued_fees_db_key: String,
    last_withdrawal: String,
}

#[derive(Serialize, Deserialize, Deref, Constructor)]
pub struct FeeStateForTokens(Vec<FeeStateForToken>);

impl FeeStateForTokens {
    fn get_core_type_error_msg(core_type: &CoreType) -> String {
        format!(
            "✘ `FeeEnclaveState` not implemented for core type: {}",
            core_type.to_string()
        )
    }

    fn get_fee_db_utils_for_core_type(core_type: &CoreType) -> Result<FeeDatabaseUtils> {
        match core_type {
            CoreType::BtcOnEth => Ok(FeeDatabaseUtils::new_for_btc_on_eth()),
            CoreType::BtcOnEos => Ok(FeeDatabaseUtils::new_for_btc_on_eos()),
            _ => Err(Self::get_core_type_error_msg(core_type).into()),
        }
    }

    fn get_fee_token_symbol_for_core_type(core_type: &CoreType) -> Result<String> {
        match core_type {
            CoreType::BtcOnEth | CoreType::BtcOnEos => Ok("BTC".to_string()),
            _ => Err(Self::get_core_type_error_msg(core_type).into()),
        }
    }

    pub fn new_for_core_type<D: DatabaseInterface>(core_type: &CoreType, db: &D) -> Result<Self> {
        info!("✔ Getting `FeesEnclaveState` for core type: {}", core_type.to_string());
        Self::get_fee_db_utils_for_core_type(core_type).and_then(|fee_db_utils| {
            Ok(Self::new(vec![FeeStateForToken {
                token_symbol: Self::get_fee_token_symbol_for_core_type(core_type)?,
                accrued_fees: fee_db_utils.get_accrued_fees_from_db(db)?,
                accrued_fees_db_key: hex::encode(&fee_db_utils.db_keys.accrued_fees_db_key),
                peg_in_basis_points: fee_db_utils.get_peg_in_basis_points_from_db(db)?,
                peg_out_basis_points: fee_db_utils.get_peg_out_basis_points_from_db(db)?,
                last_withdrawal: get_last_withdrawal_date_as_human_readable_string(
                    fee_db_utils.get_last_fee_withdrawal_timestamp_from_db(db)?,
                ),
            }]))
        })
    }

    pub fn new_for_btc_on_eth<D: DatabaseInterface>(db: &D) -> Result<Self> {
        Self::new_for_core_type(&CoreType::BtcOnEth, db)
    }

    pub fn new_for_btc_on_eos<D: DatabaseInterface>(db: &D) -> Result<Self> {
        Self::new_for_core_type(&CoreType::BtcOnEos, db)
    }
}
