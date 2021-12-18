use crate::{
    chains::{
        eth::{core_initialization::check_eth_core_is_initialized::is_eth_core_initialized, eth_state::EthState},
        evm::{
            core_initialization::check_eth_core_is_initialized::is_eth_core_initialized as is_evm_core_initialized,
            eth_state::EthState as EvmState,
        },
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn check_core_is_initialized<D: DatabaseInterface>(db: &D) -> Result<()> {
    info!("✔ Checking `erc20-on-evm` core is initialized...");
    match is_evm_core_initialized(db) {
        false => Err("EVM core not initialized!".into()),
        true => match is_eth_core_initialized(db) {
            false => Err("ETH core not initialized!".into()),
            true => Ok(()),
        },
    }
}

pub fn check_core_is_initialized_and_return_eth_state<D: DatabaseInterface>(state: EthState<D>) -> Result<EthState<D>> {
    check_core_is_initialized(&state.db).and(Ok(state))
}

pub fn check_core_is_initialized_and_return_evm_state<D: DatabaseInterface>(state: EvmState<D>) -> Result<EvmState<D>> {
    check_core_is_initialized(&state.db).and(Ok(state))
}
