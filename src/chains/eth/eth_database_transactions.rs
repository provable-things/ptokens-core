use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::eth::eth_state::EthState,
};

pub fn start_eth_db_transaction_and_return_state<D>(
    state: EthState<D>,
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    state.db.start_transaction().map(|_| { info!("✔ ETH database transaction begun!"); state })
}

pub fn end_eth_db_transaction_and_return_state<D>(
    state: EthState<D>,
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    state.db.end_transaction().map(|_| { info!("✔ Eth database transaction ended!"); state })
}
