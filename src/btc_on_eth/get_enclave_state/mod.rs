use crate::{
    btc_on_eth::check_core_is_initialized::check_core_is_initialized,
    chains::{btc::btc_enclave_state::BtcEnclaveState, eth::eth_enclave_state::EthEnclaveState},
    enclave_info::EnclaveInfo,
    traits::DatabaseInterface,
    types::Result,
};

#[derive(Serialize, Deserialize)]
struct EnclaveState {
    info: EnclaveInfo,
    btc: BtcEnclaveState,
    eth: EthEnclaveState,
}

impl EnclaveState {
    pub fn new<D: DatabaseInterface>(db: &D) -> Result<Self> {
        Ok(Self {
            info: EnclaveInfo::new(),
            btc: BtcEnclaveState::new(db)?,
            eth: EthEnclaveState::new_for_btc_on_eth(db)?,
        })
    }

    pub fn to_string(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

pub fn get_enclave_state<D: DatabaseInterface>(db: D) -> Result<String> {
    info!("✔ Getting enclave state...");
    check_core_is_initialized(&db).and_then(|_| EnclaveState::new(&db)?.to_string())
}
