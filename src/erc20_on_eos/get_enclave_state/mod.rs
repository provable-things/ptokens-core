use serde::{Deserialize, Serialize};

use crate::{
    chains::{eos::eos_enclave_state::EosEnclaveState, eth::eth_enclave_state::EthEnclaveState},
    enclave_info::EnclaveInfo,
    erc20_on_eos::check_core_is_initialized::check_core_is_initialized,
    traits::DatabaseInterface,
    types::Result,
};

#[derive(Serialize, Deserialize)]
struct EnclaveState {
    info: EnclaveInfo,
    eth: EthEnclaveState,
    eos: EosEnclaveState,
}

impl EnclaveState {
    pub fn new<D: DatabaseInterface>(db: &D) -> Result<Self> {
        Ok(Self {
            info: EnclaveInfo::new(),
            eth: EthEnclaveState::new_for_erc20_on_eos(db)?,
            eos: EosEnclaveState::new_without_account_name(db)?,
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
    info!("✔ Getting enclave state...");
    check_core_is_initialized(&db).and_then(|_| EnclaveState::new(&db)?.to_string())
}
