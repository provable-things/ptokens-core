use crate::{
    chains::btc::{
        btc_crypto::btc_private_key::BtcPrivateKey,
        btc_database_utils::{
            get_btc_private_key_from_db,
            put_btc_address_in_db,
            put_btc_private_key_in_db,
            put_btc_pub_key_slice_in_db,
        },
        btc_state::BtcState,
        core_initialization::btc_init_utils::get_btc_network_from_arg,
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn generate_and_store_btc_keys<D: DatabaseInterface>(network: &str, db: &D) -> Result<()> {
    let pk = BtcPrivateKey::generate_random(get_btc_network_from_arg(network))?;
    put_btc_private_key_in_db(db, &pk)
        .and_then(|_| put_btc_pub_key_slice_in_db(db, &get_btc_private_key_from_db(db)?.to_public_key_slice()))
        .and_then(|_| put_btc_address_in_db(db, &get_btc_private_key_from_db(db)?.to_p2pkh_btc_address()))
}

pub fn generate_and_store_btc_keys_and_return_state<D: DatabaseInterface>(
    network: &str,
    state: BtcState<D>,
) -> Result<BtcState<D>> {
    info!("✔ Generating & storing BTC private key...");
    generate_and_store_btc_keys(network, &state.db).and(Ok(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::btc::btc_database_utils::{get_btc_address_from_db, put_btc_network_in_db},
        test_utils::get_test_database,
    };

    // NOTE: This was the original way the BTC keys were stored. Note the ignored test below to
    // show how it fails. Note also the hack above in the real function and how its test passes.
    fn generate_and_store_btc_keys_broken<D: DatabaseInterface>(network: &str, db: &D) -> Result<()> {
        let pk = BtcPrivateKey::generate_random(get_btc_network_from_arg(network))?;
        put_btc_private_key_in_db(db, &pk)
            .and_then(|_| put_btc_pub_key_slice_in_db(db, &pk.to_public_key_slice()))
            .and_then(|_| put_btc_address_in_db(db, &pk.to_p2pkh_btc_address()))
    }

    #[ignore]
    #[test]
    fn should_show_btc_private_key_db_save_bug() {
        let db = get_test_database();
        let network_str = "Bitcoin";
        let network = get_btc_network_from_arg(network_str);
        put_btc_network_in_db(&db, network).unwrap();
        generate_and_store_btc_keys_broken(network_str, &db).unwrap();
        let pk_from_db = get_btc_private_key_from_db(&db).unwrap();
        let address_from_db = get_btc_address_from_db(&db).unwrap();
        let address_from_pk_from_db = pk_from_db.to_p2pkh_btc_address();
        assert_eq!(address_from_db, address_from_pk_from_db); // FIXME: This should not fail!
    }

    #[test]
    fn should_generate_and_store_btc_keys() {
        let db = get_test_database();
        let network_str = "Bitcoin";
        let network = get_btc_network_from_arg(network_str);
        put_btc_network_in_db(&db, network).unwrap();
        generate_and_store_btc_keys(network_str, &db).unwrap();
        let pk_from_db = get_btc_private_key_from_db(&db).unwrap();
        let address_from_db = get_btc_address_from_db(&db).unwrap();
        let address_from_pk_from_db = pk_from_db.to_p2pkh_btc_address();
        assert_eq!(address_from_db, address_from_pk_from_db);
    }
}
