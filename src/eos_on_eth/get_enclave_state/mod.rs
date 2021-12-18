use serde::{Deserialize, Serialize};

use crate::{
    chains::{eos::eos_enclave_state::EosEnclaveState, eth::eth_enclave_state::EthEnclaveState},
    enclave_info::EnclaveInfo,
    eos_on_eth::check_core_is_initialized::check_core_is_initialized,
    traits::DatabaseInterface,
    types::Result,
};

#[derive(Serialize, Deserialize)]
struct EnclaveState {
    info: EnclaveInfo,
    eos: EosEnclaveState,
    eth: EthEnclaveState,
}

impl EnclaveState {
    pub fn new<D: DatabaseInterface>(db: &D) -> Result<Self> {
        Ok(Self {
            info: EnclaveInfo::new(),
            eos: EosEnclaveState::new(db)?,
            eth: EthEnclaveState::new_for_eos_on_eth(db)?,
        })
    }

    pub fn to_string(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

/// # Get Enclave State
///
/// This function returns a JSON containing the enclave state, including state relevant to each
/// blockchain controlled by this instance.
pub fn get_enclave_state<D: DatabaseInterface>(db: D) -> Result<String> {
    info!("✔ Getting core state...");
    check_core_is_initialized(&db).and_then(|_| EnclaveState::new(&db)?.to_string())
}
