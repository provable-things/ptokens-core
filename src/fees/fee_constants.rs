pub use serde_json::{json, Value as JsonValue};

use crate::{core_type::CoreType, types::Bytes, utils::get_prefixed_db_key};

#[cfg(not(feature = "disable-fees"))]
pub const DISABLE_FEES: bool = false;

#[cfg(feature = "disable-fees")]
pub const DISABLE_FEES: bool = true;

pub const MAX_FEE_BASIS_POINTS: u64 = 100;

lazy_static! {
    pub static ref BTC_ON_ETH_FEE_DB_KEYS: FeeConstantDbKeys = FeeConstantDbKeys::new_for_btc_on_eth();
    pub static ref BTC_ON_EOS_FEE_DB_KEYS: FeeConstantDbKeys = FeeConstantDbKeys::new_for_btc_on_eos();
}

#[derive(Clone)]
pub struct FeeConstantDbKeys {
    pub core_type: CoreType,
    pub accrued_fees_db_key: Bytes,
    pub peg_in_basis_points_db_key: Bytes,
    pub last_fee_withdrawal_db_key: Bytes,
    pub peg_out_basis_points_db_key: Bytes,
}

impl FeeConstantDbKeys {
    pub fn new(core_type: CoreType) -> Self {
        Self {
            core_type,
            accrued_fees_db_key: get_prefixed_db_key(&format!("{}-accrued-fees-key", core_type.as_db_key_prefix()))
                .to_vec(),
            peg_in_basis_points_db_key: get_prefixed_db_key(&format!(
                "{}-peg-in-basis-points-key",
                core_type.as_db_key_prefix()
            ))
            .to_vec(),
            last_fee_withdrawal_db_key: get_prefixed_db_key(&format!(
                "{}-last-fee-withdrawal-timestamp",
                core_type.as_db_key_prefix()
            ))
            .to_vec(),
            peg_out_basis_points_db_key: get_prefixed_db_key(&format!(
                "{}-peg-out-basis-points-key",
                core_type.as_db_key_prefix()
            ))
            .to_vec(),
        }
    }

    pub fn new_for_btc_on_eth() -> Self {
        Self::new(CoreType::BtcOnEth)
    }

    pub fn new_for_btc_on_eos() -> Self {
        Self::new(CoreType::BtcOnEos)
    }

    pub fn to_json(&self) -> JsonValue {
        let prefix = self.core_type.to_string();
        json!({
            format!("{}_ACCRUED_FEES_KEY", prefix): hex::encode(&self.accrued_fees_db_key),
            format!("{}_PEG_IN_BASIS_POINTS_KEY", prefix): hex::encode(&self.peg_in_basis_points_db_key),
            format!("{}_PEG_OUT_BASIS_POINTS_KEY", prefix): hex::encode(&self.peg_out_basis_points_db_key),
            format!("{}_LAST_FEE_WITHDRAWAL_TIMESTAMP_KEY", prefix): hex::encode(&self.last_fee_withdrawal_db_key),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_btc_on_eth_db_keys_should_match_legacy_btc_on_eth_keys() {
        let legacy_accrued_fees =
            hex::decode("626d2b6de033e05f52ed6b3ab214484f84dc1a86e214fc30ad1dad158a43424c").unwrap();
        let legacy_peg_in_basis_points =
            hex::decode("f915482bab3d6a1a2bd96fd33bde683ad309ccec9abce091f105298c035e221b").unwrap();
        let legacy_peg_out_basis_points =
            hex::decode("4d9e96d275542aa1c988a3f5318a6cb69eb967947535de2426a99ce7a366d26f").unwrap();
        let legacy_last_withdrawal_timestamp =
            hex::decode("a19a8ce32d96ed7c0b37521cba54a05bb11a0c64ecb657806aba4b6cab394cd2").unwrap();
        let btc_keys = FeeConstantDbKeys::new_for_btc_on_eth();
        assert_eq!(legacy_accrued_fees, btc_keys.accrued_fees_db_key);
        assert_eq!(legacy_peg_in_basis_points, btc_keys.peg_in_basis_points_db_key);
        assert_eq!(legacy_peg_out_basis_points, btc_keys.peg_out_basis_points_db_key);
        assert_eq!(legacy_last_withdrawal_timestamp, btc_keys.last_fee_withdrawal_db_key);
    }
}
