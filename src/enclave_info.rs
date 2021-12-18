use serde::{Deserialize, Serialize};

use crate::{
    constants::{CORE_IS_VALIDATING, DB_KEY_PREFIX, DEBUG_MODE},
    fees::fee_constants::MAX_FEE_BASIS_POINTS,
    utils::get_core_version,
};

#[derive(Serialize, Deserialize)]
pub struct EnclaveInfo {
    debug_mode: bool,
    db_key_prefix: String,
    core_is_validating: bool,
    core_version: String,
    max_fee_basis_points: u64,
}

impl EnclaveInfo {
    pub fn new() -> Self {
        Self {
            debug_mode: DEBUG_MODE,
            core_version: get_core_version(),
            core_is_validating: CORE_IS_VALIDATING,
            db_key_prefix: DB_KEY_PREFIX.to_string(),
            max_fee_basis_points: MAX_FEE_BASIS_POINTS,
        }
    }
}
