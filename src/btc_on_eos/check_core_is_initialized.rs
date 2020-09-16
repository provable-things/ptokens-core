use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::{
        btc::{
            btc_state::BtcState,
            initialize_btc::is_btc_core_initialized::is_btc_core_initialized,
        },
        eos::{
            eos_state::EosState,
            initialize_eos::is_eos_core_initialized::is_eos_core_initialized,
        },
    },
};

pub fn check_btc_core_is_initialized<D>(
    db: &D
) -> Result<()>
    where D: DatabaseInterface
{
    info!("✔ Checking BTC core is initialized...");
    match is_btc_core_initialized(db) {
        false => Err("✘ BTC side of core not initialized!".into()),
        true => Ok(())
    }
}

pub fn check_eos_core_is_initialized<D>(
    db: &D
) -> Result<()>
    where D: DatabaseInterface
{
    info!("✔ Checking EOS core is initialized...");
    match is_eos_core_initialized(db) {
        false => Err("✘ EOS side of core not initialized!".into()),
        true => Ok(())
    }
}

pub fn check_core_is_initialized<D>(
    db: &D
) -> Result<()>
    where D: DatabaseInterface
{
    check_btc_core_is_initialized(db)
        .and_then(|_| check_eos_core_is_initialized(db))
}

pub fn check_core_is_initialized_and_return_eos_state<D>(
    state: EosState<D>,
) -> Result<EosState<D>>
    where D: DatabaseInterface
{
    check_core_is_initialized(&state.db)
        .map(|_| state)
}

pub fn check_core_is_initialized_and_return_btc_state<D>(
    state: BtcState<D>,
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    check_core_is_initialized(&state.db)
        .map(|_| state)
}
