use serde_json::json;

use crate::{
    chains::eth::eth_database_utils::{
        put_any_sender_nonce_in_db,
        put_eth_account_nonce_in_db,
        put_eth_gas_price_in_db,
    },
    check_debug_mode::check_debug_mode,
    traits::DatabaseInterface,
    types::Result,
    utils::prepend_debug_output_marker_to_string,
};

/// # Debug Set ETH Account Nonce
///
/// This function set to the given value BTC account nonce in the encryped database.
pub fn debug_set_eth_account_nonce<D: DatabaseInterface>(db: &D, new_nonce: u64) -> Result<String> {
    info!("✔ Debug setting ETH account nonce...");
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| put_eth_account_nonce_in_db(db, new_nonce))
        .and_then(|_| db.end_transaction())
        .and(Ok(json!({"set_eth_account_nonce":true}).to_string()))
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Set ETH AnySender Nonce
///
/// This function set to the given value AnySender nonce in the encryped database.
pub fn debug_set_eth_any_sender_nonce<D: DatabaseInterface>(db: &D, new_nonce: u64) -> Result<String> {
    info!("✔ Debug setting ETH AnySender nonce...");
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| put_any_sender_nonce_in_db(db, new_nonce))
        .and_then(|_| db.end_transaction())
        .and(Ok(json!({"set_eth_any_sender_nonce":true}).to_string()))
        .map(prepend_debug_output_marker_to_string)
}

/// Debug Set ETH Gas Price
///
/// This function sets the ETH gas price to use when making ETH transactions. It's unit is `Wei`.
pub fn debug_set_eth_gas_price_in_db<D: DatabaseInterface>(db: &D, gas_price: u64) -> Result<String> {
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| put_eth_gas_price_in_db(db, gas_price))
        .and_then(|_| db.end_transaction())
        .map(|_| json!({"sucess":true,"new_eth_gas_price":gas_price}).to_string())
        .map(prepend_debug_output_marker_to_string)
}

#[cfg(all(test, feature = "debug"))]
mod tests {
    use super::*;
    use crate::{
        chains::eth::eth_database_utils::{
            get_any_sender_nonce_from_db,
            get_eth_account_nonce_from_db,
            get_eth_gas_price_from_db,
        },
        test_utils::get_test_database,
    };

    #[test]
    fn should_set_eth_account_nonce() {
        let db = get_test_database();
        let nonce = 6;
        put_eth_account_nonce_in_db(&db, nonce).unwrap();
        assert_eq!(get_eth_account_nonce_from_db(&db).unwrap(), nonce);
        let new_nonce = 4;
        debug_set_eth_account_nonce(&db, new_nonce).unwrap();
        assert_eq!(get_eth_account_nonce_from_db(&db).unwrap(), new_nonce);
    }

    #[test]
    fn should_set_eth_any_sender_nonce() {
        let db = get_test_database();
        let nonce = 6;
        put_any_sender_nonce_in_db(&db, nonce).unwrap();
        assert_eq!(get_any_sender_nonce_from_db(&db).unwrap(), nonce);
        let new_nonce = 4;
        debug_set_eth_any_sender_nonce(&db, new_nonce).unwrap();
        assert_eq!(get_any_sender_nonce_from_db(&db).unwrap(), new_nonce);
    }

    #[test]
    fn should_set_eth_gas_price_in_db() {
        let db = get_test_database();
        let gas_price = 6;
        put_eth_gas_price_in_db(&db, gas_price).unwrap();
        assert_eq!(get_eth_gas_price_from_db(&db).unwrap(), gas_price);
        let new_gas_price = 4;
        debug_set_eth_gas_price_in_db(&db, new_gas_price).unwrap();
        assert_eq!(get_eth_gas_price_from_db(&db).unwrap(), new_gas_price);
    }
}
