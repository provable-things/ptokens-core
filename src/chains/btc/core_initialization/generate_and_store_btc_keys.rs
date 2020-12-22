use crate::{
    chains::btc::{
        btc_crypto::btc_private_key::BtcPrivateKey,
        btc_database_utils::{put_btc_address_in_db, put_btc_private_key_in_db, put_btc_pub_key_slice_in_db},
        btc_state::BtcState,
        core_initialization::btc_init_utils::get_btc_network_from_arg,
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn generate_and_store_btc_keys<D>(network: &str, state: BtcState<D>) -> Result<BtcState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Generating & storing BTC private key...");
    let pk = BtcPrivateKey::generate_random(get_btc_network_from_arg(network))?;
    put_btc_private_key_in_db(&state.db, &pk)
        .and_then(|_| put_btc_pub_key_slice_in_db(&state.db, &pk.to_public_key_slice()))
        .and_then(|_| put_btc_address_in_db(&state.db, &pk.to_p2pkh_btc_address()))
        .and(Ok(state))
}
