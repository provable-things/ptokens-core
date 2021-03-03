use crate::{
    chains::eth::{
        eth_crypto::eth_private_key::EthPrivateKey,
        eth_database_utils::put_eth_private_key_in_db,
        eth_state::EthState,
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn generate_and_store_eth_private_key<D: DatabaseInterface>(state: EthState<D>) -> Result<EthState<D>> {
    info!("✔ Generating & storing ETH private key...");
    put_eth_private_key_in_db(&state.db, &EthPrivateKey::generate_random()?).and(Ok(state))
}
