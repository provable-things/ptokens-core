use crate::{chains::eth::eth_state::EthState, traits::DatabaseInterface, types::Result};

pub fn start_eth_db_transaction_and_return_state<D: DatabaseInterface>(state: EthState<D>) -> Result<EthState<D>> {
    state.db.start_transaction().map(|_| {
        info!("✔ ETH database transaction begun!");
        state
    })
}

pub fn end_eth_db_transaction_and_return_state<D: DatabaseInterface>(state: EthState<D>) -> Result<EthState<D>> {
    state.db.end_transaction().map(|_| {
        info!("✔ Eth database transaction ended!");
        state
    })
}
