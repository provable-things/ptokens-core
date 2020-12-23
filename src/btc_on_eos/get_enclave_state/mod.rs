use crate::{
    btc_on_eos::check_core_is_initialized::check_core_is_initialized,
    chains::{btc::btc_enclave_state::BtcEnclaveState, eos::eos_enclave_state::EosEnclaveState},
    enclave_info::EnclaveInfo,
    traits::DatabaseInterface,
    types::Result,
};

#[derive(Serialize, Deserialize)]
struct EnclaveState {
    info: EnclaveInfo,
    eos: EosEnclaveState,
    btc: BtcEnclaveState,
}

impl EnclaveState {
    pub fn new<D: DatabaseInterface>(db: &D) -> Result<Self> {
        Ok(Self {
            info: EnclaveInfo::new(),
            eos: EosEnclaveState::new(db)?,
            btc: BtcEnclaveState::new(db)?,
        })
    }

    pub fn to_string(&self) -> Result<String> {
        Ok(serde_json::to_string(self)?)
    }
}

pub fn get_enclave_state<D: DatabaseInterface>(db: D) -> Result<String> {
    info!("✔ Getting core state...");
    check_core_is_initialized(&db).and_then(|_| EnclaveState::new(&db)?.to_string())
}
