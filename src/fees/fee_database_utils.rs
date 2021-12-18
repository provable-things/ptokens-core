use crate::{
    core_type::CoreType,
    database_utils::{get_u64_from_db, put_u64_in_db},
    fees::fee_constants::FeeConstantDbKeys,
    traits::DatabaseInterface,
    types::{Byte, Result},
};

pub struct FeeDatabaseUtils {
    pub core_type: CoreType,
    pub db_keys: FeeConstantDbKeys,
}

impl FeeDatabaseUtils {
    pub fn new_for_core_type(core_type: &CoreType) -> Result<Self> {
        match core_type {
            CoreType::BtcOnEth => Ok(Self::new_for_btc_on_eth()),
            CoreType::BtcOnEos => Ok(Self::new_for_btc_on_eos()),
            _ => Err(format!("`FeeDatabaseUtils` no implemented for core type: {}", core_type).into()),
        }
    }

    pub fn new_for_btc_on_eth() -> Self {
        Self {
            core_type: CoreType::BtcOnEth,
            db_keys: FeeConstantDbKeys::new_for_btc_on_eth(),
        }
    }

    pub fn new_for_btc_on_eos() -> Self {
        Self {
            core_type: CoreType::BtcOnEos,
            db_keys: FeeConstantDbKeys::new_for_btc_on_eos(),
        }
    }

    fn get_u64_from_db_or_else_return_zero<D: DatabaseInterface>(
        db: &D,
        key: &[Byte],
        debug_msg: &str,
        debug_err_msg: &str,
    ) -> Result<u64> {
        debug!("{}", debug_msg);
        get_u64_from_db(db, key).or_else(|_| {
            debug!("{}", debug_err_msg);
            Ok(0)
        })
    }

    pub fn get_accrued_fees_from_db<D: DatabaseInterface>(&self, db: &D) -> Result<u64> {
        match self.core_type {
            CoreType::BtcOnEth => Self::get_u64_from_db_or_else_return_zero(
                db,
                &self.db_keys.accrued_fees_db_key,
                "✔ Getting `btc-on-eth` accrued fees from db...",
                "✔ No `BTC_ON_ETH_ACCRUED_FEES_KEY` value set in db, defaulting to 0!",
            ),
            CoreType::BtcOnEos => Self::get_u64_from_db_or_else_return_zero(
                db,
                &self.db_keys.accrued_fees_db_key,
                "✔ Getting `btc-on-eos` accrued fees from db...",
                "✔ No `BTC_ON_EOS_ACCRUED_FEES_KEY` value set in db, defaulting to 0!",
            ),
            _ => Err(format!(
                "`get_accrued_fees_from_db` not implemented for core type: {}",
                self.core_type
            )
            .into()),
        }
    }

    pub fn get_peg_in_basis_points_from_db<D: DatabaseInterface>(&self, db: &D) -> Result<u64> {
        match self.core_type {
            CoreType::BtcOnEth => Self::get_u64_from_db_or_else_return_zero(
                db,
                &self.db_keys.peg_in_basis_points_db_key,
                "✔ Getting `BTC_ON_ETH_PEG_IN_BASIS_POINTS_KEY` from db...",
                "✔ No `BTC_ON_ETH_PEG_IN_BASIS_POINTS_KEY` value set in db, defaulting to 0!",
            ),
            CoreType::BtcOnEos => Self::get_u64_from_db_or_else_return_zero(
                db,
                &self.db_keys.peg_in_basis_points_db_key,
                "✔ Getting `BTC_ON_EOS_PEG_IN_BASIS_POINTS_KEY` from db...",
                "✔ No `BTC_ON_EOS_PEG_IN_BASIS_POINTS_KEY` value set in db, defaulting to 0!",
            ),
            _ => Err(format!(
                "`get_peg_in_basis_points_from_db` not implemented for core type: {}",
                self.core_type
            )
            .into()),
        }
    }

    pub fn get_peg_out_basis_points_from_db<D: DatabaseInterface>(&self, db: &D) -> Result<u64> {
        match self.core_type {
            CoreType::BtcOnEth => Self::get_u64_from_db_or_else_return_zero(
                db,
                &self.db_keys.peg_out_basis_points_db_key,
                "✔ Getting `BTC_ON_ETH_PEG_OUT_BASIS_POINTS_KEY` from db...",
                "✔ No `BTC_ON_ETH_PEG_OUT_BASIS_POINTS_KEY` value set in db, defaulting to 0!",
            ),
            CoreType::BtcOnEos => Self::get_u64_from_db_or_else_return_zero(
                db,
                &self.db_keys.peg_out_basis_points_db_key,
                "✔ Getting `BTC_ON_EOS_PEG_OUT_BASIS_POINTS_KEY` from db...",
                "✔ No `BTC_ON_EOS_PEG_OUT_BASIS_POINTS_KEY` value set in db, defaulting to 0!",
            ),
            _ => Err(format!(
                "`get_peg_out_basis_points_from_db` not implemented for core type: {}",
                self.core_type
            )
            .into()),
        }
    }

    pub fn put_peg_in_basis_points_in_db<D: DatabaseInterface>(&self, db: &D, basis_points: u64) -> Result<()> {
        match self.core_type {
            CoreType::BtcOnEth => {
                debug!(
                    "✔ Putting `BTC_ON_ETH_PEG_IN_BASIS_POINTS_KEY` of {} in db...",
                    basis_points
                );
                put_u64_in_db(db, &self.db_keys.peg_in_basis_points_db_key, basis_points)
            },
            CoreType::BtcOnEos => {
                debug!(
                    "✔ Putting `BTC_ON_EOS_PEG_IN_BASIS_POINTS_KEY` of {} in db...",
                    basis_points
                );
                put_u64_in_db(db, &self.db_keys.peg_in_basis_points_db_key, basis_points)
            },
            _ => Err(format!(
                "`put_peg_in_basis_points_in_db` not implemented for core type: {}",
                self.core_type
            )
            .into()),
        }
    }

    pub fn put_peg_out_basis_points_in_db<D: DatabaseInterface>(&self, db: &D, basis_points: u64) -> Result<()> {
        match self.core_type {
            CoreType::BtcOnEth => {
                debug!(
                    "✔ Putting `BTC_ON_ETH_PEG_OUT_BASIS_POINTS_KEY` of {} in db...",
                    basis_points
                );
                put_u64_in_db(db, &self.db_keys.peg_out_basis_points_db_key, basis_points)
            },
            CoreType::BtcOnEos => {
                debug!(
                    "✔ Putting `BTC_ON_EOS_PEG_OUT_BASIS_POINTS_KEY` of {} in db...",
                    basis_points
                );
                put_u64_in_db(db, &self.db_keys.peg_out_basis_points_db_key, basis_points)
            },
            _ => Err(format!(
                "`put_peg_out_basis_points_in_db` not implemented for core type: {}",
                self.core_type
            )
            .into()),
        }
    }

    pub fn put_accrued_fees_in_db<D: DatabaseInterface>(&self, db: &D, amount: u64) -> Result<()> {
        match self.core_type {
            CoreType::BtcOnEth => {
                debug!("✔ Putting `btc-on-eth` accrued fee value of {} in db...", amount);
                put_u64_in_db(db, &self.db_keys.accrued_fees_db_key, amount)
            },
            CoreType::BtcOnEos => {
                debug!("✔ Putting `btc-on-eos` accrued fee value of {} in db...", amount);
                put_u64_in_db(db, &self.db_keys.accrued_fees_db_key, amount)
            },
            _ => Err(format!(
                "`put_accrued_fees_in_db` not implemented for core type: {}",
                self.core_type
            )
            .into()),
        }
    }

    pub fn reset_accrued_fees<D: DatabaseInterface>(&self, db: &D) -> Result<()> {
        match self.core_type {
            CoreType::BtcOnEth => Self::new_for_btc_on_eth().put_accrued_fees_in_db(db, 0),
            CoreType::BtcOnEos => Self::new_for_btc_on_eos().put_accrued_fees_in_db(db, 0),
            _ => Err(format!("`reset_accrued_fees` not implemented for core type: {}", self.core_type).into()),
        }
    }

    pub fn increment_accrued_fees<D: DatabaseInterface>(&self, db: &D, increment_amount: u64) -> Result<()> {
        debug!("✔ Incrementing accrued fees in db...");
        self.get_accrued_fees_from_db(db).and_then(|accrued_fees| {
            let total_after_incrementing = accrued_fees + increment_amount;
            debug!("✔ Accrued fees before incrementing: {}", accrued_fees);
            debug!("✔           Incrementing by amount: {}", increment_amount);
            debug!("✔        Total after incremeneting: {}", total_after_incrementing);
            self.put_accrued_fees_in_db(db, total_after_incrementing)
        })
    }

    pub fn put_last_fee_withdrawal_timestamp_in_db<D: DatabaseInterface>(&self, db: &D, timestamp: u64) -> Result<()> {
        match self.core_type {
            CoreType::BtcOnEth => {
                debug!("✔ Putting `btc-on-eth` last fee withdrawal timestamp into db...");
                put_u64_in_db(db, &self.db_keys.last_fee_withdrawal_db_key, timestamp)
            },
            CoreType::BtcOnEos => {
                debug!("✔ Putting `btc-on-eos` last fee withdrawal timestamp into db...");
                put_u64_in_db(db, &self.db_keys.last_fee_withdrawal_db_key, timestamp)
            },
            _ => Err(format!(
                "`put_last_fee_withdrawal_timestamp_in_db` not implemented for core type: {}",
                self.core_type
            )
            .into()),
        }
    }

    pub fn get_last_fee_withdrawal_timestamp_from_db<D: DatabaseInterface>(&self, db: &D) -> Result<u64> {
        match self.core_type {
            CoreType::BtcOnEth => {
                debug!("✔ Getting `btc-on-eth` last fee withdrawal timestamp from db...");
                Ok(get_u64_from_db(db, &self.db_keys.last_fee_withdrawal_db_key).unwrap_or_default())
            },
            CoreType::BtcOnEos => {
                debug!("✔ Getting `btc-on-eos` last fee withdrawal timestamp from db...");
                Ok(get_u64_from_db(db, &self.db_keys.last_fee_withdrawal_db_key).unwrap_or_default())
            },
            _ => Err(format!(
                "`get_last_fee_withdrawal_timestamp_from_db` not implemented for core type: {}",
                self.core_type
            )
            .into()),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::get_test_database;

    #[test]
    fn should_put_and_get_btc_on_eth_peg_in_basis_points_in_db() {
        let basis_points: u64 = 1337;
        let db = get_test_database();
        FeeDatabaseUtils::new_for_btc_on_eth()
            .put_peg_in_basis_points_in_db(&db, basis_points)
            .unwrap();
        let result = FeeDatabaseUtils::new_for_btc_on_eth()
            .get_peg_in_basis_points_from_db(&db)
            .unwrap();
        assert_eq!(result, basis_points);
    }

    #[test]
    fn should_put_and_get_btc_on_eth_peg_out_basis_points_in_db() {
        let basis_points: u64 = 1337;
        let db = get_test_database();
        FeeDatabaseUtils::new_for_btc_on_eth()
            .put_peg_out_basis_points_in_db(&db, basis_points)
            .unwrap();
        let result = FeeDatabaseUtils::new_for_btc_on_eth()
            .get_peg_out_basis_points_from_db(&db)
            .unwrap();
        assert_eq!(result, basis_points);
    }

    #[test]
    fn should_put_and_get_accrued_fees_in_db() {
        let fees: u64 = 1337;
        let db = get_test_database();
        FeeDatabaseUtils::new_for_btc_on_eth()
            .put_accrued_fees_in_db(&db, fees)
            .unwrap();
        let result = FeeDatabaseUtils::new_for_btc_on_eth()
            .get_accrued_fees_from_db(&db)
            .unwrap();
        assert_eq!(result, fees);
    }

    #[test]
    fn get_btc_on_eth_peg_in_basis_points_from_db_should_default_to_zero() {
        let db = get_test_database();
        let expected_result = 0;
        let result = FeeDatabaseUtils::new_for_btc_on_eth()
            .get_peg_in_basis_points_from_db(&db)
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn get_btc_on_eth_peg_out_basis_points_from_db_should_default_to_zero() {
        let db = get_test_database();
        let expected_result = 0;
        let result = FeeDatabaseUtils::new_for_btc_on_eth()
            .get_peg_out_basis_points_from_db(&db)
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn get_accrued_fees_from_db_should_default_to_zero() {
        let db = get_test_database();
        let expected_result = 0;
        let result = FeeDatabaseUtils::new_for_btc_on_eth()
            .get_accrued_fees_from_db(&db)
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_increment_accrued_fees_in_db() {
        let db = get_test_database();
        let start_value = 1337;
        let increment_amount = 1;
        FeeDatabaseUtils::new_for_btc_on_eth()
            .put_accrued_fees_in_db(&db, start_value)
            .unwrap();
        FeeDatabaseUtils::new_for_btc_on_eth()
            .increment_accrued_fees(&db, increment_amount)
            .unwrap();
        let result = FeeDatabaseUtils::new_for_btc_on_eth()
            .get_accrued_fees_from_db(&db)
            .unwrap();
        assert_eq!(result, start_value + increment_amount);
    }

    #[test]
    fn should_reset_accrued_fees() {
        let fees = 1337;
        let db = get_test_database();
        FeeDatabaseUtils::new_for_btc_on_eth()
            .put_accrued_fees_in_db(&db, fees)
            .unwrap();
        let fees_in_db_before = FeeDatabaseUtils::new_for_btc_on_eth()
            .get_accrued_fees_from_db(&db)
            .unwrap();
        assert_eq!(fees_in_db_before, fees);
        FeeDatabaseUtils::new_for_btc_on_eth().reset_accrued_fees(&db).unwrap();
        let fees_in_db_after = FeeDatabaseUtils::new_for_btc_on_eth()
            .get_accrued_fees_from_db(&db)
            .unwrap();
        assert_eq!(fees_in_db_after, 0)
    }

    #[test]
    fn should_get_and_put_btc_on_eth_last_fee_withdrawal_timestamp_in_db() {
        let timestamp = 1337;
        let db = get_test_database();
        FeeDatabaseUtils::new_for_btc_on_eth()
            .put_last_fee_withdrawal_timestamp_in_db(&db, timestamp)
            .unwrap();
        let result = FeeDatabaseUtils::new_for_btc_on_eth()
            .get_last_fee_withdrawal_timestamp_from_db(&db)
            .unwrap();
        assert_eq!(result, timestamp);
    }

    #[test]
    fn get_u64_from_db_or_else_return_zero_should_return_zero_if_nothing_in_db() {
        let db = get_test_database();
        let expected_result = 0;
        let bytes = vec![0xde, 0xca, 0xff];
        let result = FeeDatabaseUtils::get_u64_from_db_or_else_return_zero(&db, &bytes, "", "").unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn get_u64_from_db_or_else_return_zero_should_return_value_if_in_db() {
        let db = get_test_database();
        let expected_result = 1337;
        let key = vec![0xde, 0xca, 0xff];
        put_u64_in_db(&db, &key, expected_result).unwrap();
        let result = FeeDatabaseUtils::get_u64_from_db_or_else_return_zero(&db, &key, "", "").unwrap();
        assert_eq!(result, expected_result);
    }
}
