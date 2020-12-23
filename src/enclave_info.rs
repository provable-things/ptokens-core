use crate::constants::{CORE_IS_VALIDATING, DB_KEY_PREFIX, DEBUG_MODE};

#[derive(Serialize, Deserialize)]
pub struct EnclaveInfo {
    debug_mode: bool,
    db_key_prefix: String,
    core_is_validating: bool,
}

impl EnclaveInfo {
    pub fn new() -> Self {
        Self {
            debug_mode: DEBUG_MODE,
            core_is_validating: CORE_IS_VALIDATING,
            db_key_prefix: DB_KEY_PREFIX.to_string(),
        }
    }
}
