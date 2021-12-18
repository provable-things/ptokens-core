use serde_json::json;

use crate::{
    chains::btc::{
        btc_database_utils::{put_btc_account_nonce_in_db, put_btc_fee_in_db},
        utxo_manager::utxo_database_utils::put_utxo_nonce_in_db,
    },
    check_debug_mode::check_debug_mode,
    traits::DatabaseInterface,
    types::Result,
    utils::prepend_debug_output_marker_to_string,
};

/// # Debug Set BTC Account Nonce
///
/// This function set to the given value BTC account nonce in the encryped database.
pub fn debug_set_btc_account_nonce<D: DatabaseInterface>(db: &D, new_nonce: u64) -> Result<String> {
    info!("✔ Debug setting BTC account nonce...");
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| put_btc_account_nonce_in_db(db, new_nonce))
        .and_then(|_| db.end_transaction())
        .and(Ok(json!({"set_btc_account_nonce":true}).to_string()))
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Set BTC UTXO Nonce
///
/// This function set to the given value BTC UTXO nonce in the encryped database.
pub fn debug_set_btc_utxo_nonce<D: DatabaseInterface>(db: &D, new_nonce: u64) -> Result<String> {
    info!("✔ Debug setting BTC UTXO nonce...");
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| put_utxo_nonce_in_db(db, new_nonce))
        .and_then(|_| db.end_transaction())
        .and(Ok(json!({"set_btc_utxo_nonce":true}).to_string()))
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Put BTC Fee In Db
///
/// This function sets the BTC fee in the encrypted database to the given value. The unit is
/// satoshis-per-byte.
pub fn debug_put_btc_fee_in_db<D: DatabaseInterface>(db: &D, fee: u64) -> Result<String> {
    info!("✔ Debug putting BTC fee in db...");
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| put_btc_fee_in_db(db, fee))
        .and_then(|_| db.end_transaction())
        .and(Ok(json!({"sucess":true,"new_btc_fee":fee}).to_string()))
        .map(prepend_debug_output_marker_to_string)
}

#[cfg(all(test, feature = "debug"))]
mod tests {
    use super::*;
    use crate::{
        chains::btc::{
            btc_database_utils::{get_btc_account_nonce_from_db, get_btc_fee_from_db},
            utxo_manager::utxo_database_utils::get_utxo_nonce_from_db,
        },
        test_utils::get_test_database,
    };

    #[test]
    fn should_set_btc_account_nonce() {
        let db = get_test_database();
        let nonce = 6;
        put_btc_account_nonce_in_db(&db, nonce).unwrap();
        assert_eq!(get_btc_account_nonce_from_db(&db).unwrap(), nonce);
        let new_nonce = 4;
        debug_set_btc_account_nonce(&db, new_nonce).unwrap();
        assert_eq!(get_btc_account_nonce_from_db(&db).unwrap(), new_nonce);
    }

    #[test]
    fn should_set_btc_utxo_nonce() {
        let db = get_test_database();
        let nonce = 6;
        put_utxo_nonce_in_db(&db, nonce).unwrap();
        assert_eq!(get_utxo_nonce_from_db(&db).unwrap(), nonce);
        let new_nonce = 4;
        debug_set_btc_utxo_nonce(&db, new_nonce).unwrap();
        assert_eq!(get_utxo_nonce_from_db(&db).unwrap(), new_nonce);
    }

    #[test]
    fn should_put_btc_fee_in_db() {
        let db = get_test_database();
        let fee = 6;
        put_btc_fee_in_db(&db, fee).unwrap();
        assert_eq!(get_btc_fee_from_db(&db).unwrap(), fee);
        let new_fee = 4;
        debug_put_btc_fee_in_db(&db, new_fee).unwrap();
        assert_eq!(get_btc_fee_from_db(&db).unwrap(), new_fee);
    }
}
