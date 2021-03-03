use crate::{
    chains::{
        eos::{core_initialization::check_eos_core_is_initialized::is_eos_core_initialized, eos_state::EosState},
        eth::{core_initialization::check_eth_core_is_initialized::is_eth_core_initialized, eth_state::EthState},
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn check_core_is_initialized<D: DatabaseInterface>(db: &D) -> Result<()> {
    info!("✔ Checking pERC20 core is initialized...");
    match is_eos_core_initialized(db) {
        false => Err("EOS core not initialized!".into()),
        true => match is_eth_core_initialized(db) {
            false => Err("ETH core not initialized!".into()),
            true => Ok(()),
        },
    }
}

pub fn check_core_is_initialized_and_return_eth_state<D: DatabaseInterface>(state: EthState<D>) -> Result<EthState<D>> {
    check_core_is_initialized(&state.db).and(Ok(state))
}

pub fn check_core_is_initialized_and_return_eos_state<D: DatabaseInterface>(state: EosState<D>) -> Result<EosState<D>> {
    check_core_is_initialized(&state.db).and(Ok(state))
}
