use crate::{
    types::Result,
    traits::DatabaseInterface,
    eth::{
        eth_state::EthState,
        eth_database_utils::{
            get_eth_private_key_from_db,
            put_public_eth_address_in_db,
        },
    },
};

pub fn generate_and_store_eth_address<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Generating ETH address...");
    get_eth_private_key_from_db(&state.db)
        .map(|pk| pk.to_public_key().to_address())
        .and_then(|address| put_public_eth_address_in_db(&state.db, &address))
        .map(|_| state)
}
