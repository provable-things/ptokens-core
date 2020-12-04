use crate::{
    chains::{
        btc::{btc_state::BtcState, core_initialization::is_btc_initialized::is_btc_enclave_initialized},
        eos::{check_eos_core_is_initialized::is_eos_core_initialized, eos_state::EosState},
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn check_btc_core_is_initialized<D>(db: &D) -> Result<()>
where
    D: DatabaseInterface,
{
    info!("✔ Checking BTC core is initialized...");
    match is_btc_enclave_initialized(db) {
        false => Err("✘ BTC side of core not initialized!".into()),
        true => Ok(()),
    }
}

pub fn check_eos_core_is_initialized<D>(db: &D) -> Result<()>
where
    D: DatabaseInterface,
{
    info!("✔ Checking EOS core is initialized...");
    match is_eos_core_initialized(db) {
        false => Err("✘ EOS side of core not initialized!".into()),
        true => Ok(()),
    }
}

pub fn check_core_is_initialized<D>(db: &D) -> Result<()>
where
    D: DatabaseInterface,
{
    check_btc_core_is_initialized(db).and_then(|_| check_eos_core_is_initialized(db))
}

pub fn check_core_is_initialized_and_return_eos_state<D: DatabaseInterface>(state: EosState<D>) -> Result<EosState<D>> {
    check_core_is_initialized(&state.db).and(Ok(state))
}

pub fn check_core_is_initialized_and_return_btc_state<D: DatabaseInterface>(state: BtcState<D>) -> Result<BtcState<D>> {
    check_core_is_initialized(&state.db).and(Ok(state))
}
