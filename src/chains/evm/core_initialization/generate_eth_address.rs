use crate::{
    chains::evm::{
        eth_database_utils::{get_eth_private_key_from_db, put_public_eth_address_in_db},
        eth_state::EthState,
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn generate_and_store_eth_address<D: DatabaseInterface>(state: EthState<D>) -> Result<EthState<D>> {
    info!("✔ Generating ETH address...");
    get_eth_private_key_from_db(&state.db)
        .map(|pk| pk.to_public_key().to_address())
        .and_then(|address| put_public_eth_address_in_db(&state.db, &address))
        .and(Ok(state))
}
