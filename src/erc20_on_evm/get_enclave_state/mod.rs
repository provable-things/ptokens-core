use serde::{Deserialize, Serialize};

use crate::{
    chains::{eth::eth_enclave_state::EthEnclaveState, evm::eth_enclave_state::EthEnclaveState as EvmEnclaveState},
    dictionaries::eth_evm::EthEvmTokenDictionary,
    enclave_info::EnclaveInfo,
    erc20_on_evm::check_core_is_initialized::check_core_is_initialized,
    traits::DatabaseInterface,
    types::Result,
};

#[derive(Serialize, Deserialize)]
struct EnclaveState {
    info: EnclaveInfo,
    eth: EthEnclaveState,
    evm: EvmEnclaveState,
    token_dictionary: EthEvmTokenDictionary,
}

impl EnclaveState {
    pub fn new<D: DatabaseInterface>(db: &D) -> Result<Self> {
        Ok(Self {
            info: EnclaveInfo::new(),
            evm: EvmEnclaveState::new_for_erc20_on_evm(db)?,
            eth: EthEnclaveState::new_for_erc20_on_evm(db)?,
            token_dictionary: EthEvmTokenDictionary::get_from_db(db)?,
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
