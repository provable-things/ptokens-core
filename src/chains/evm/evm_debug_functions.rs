use serde_json::json;

use crate::{
    chains::evm::eth_database_utils::{
        put_any_sender_nonce_in_db,
        put_eth_account_nonce_in_db as put_evm_account_nonce_in_db,
    },
    check_debug_mode::check_debug_mode,
    traits::DatabaseInterface,
    types::Result,
    utils::prepend_debug_output_marker_to_string,
};

/// # Debug Set EVM Account Nonce
///
/// This function set to the given value BTC account nonce in the encryped database.
pub fn debug_set_evm_account_nonce<D: DatabaseInterface>(db: &D, new_nonce: u64) -> Result<String> {
    info!("✔ Debug setting EVM account nonce...");
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| put_evm_account_nonce_in_db(db, new_nonce))
        .and_then(|_| db.end_transaction())
        .and(Ok(json!({"set_evm_account_nonce":true}).to_string()))
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Set EVM AnySender Nonce
///
/// This function set to the given value AnySender nonce in the encryped database.
pub fn debug_set_evm_any_sender_nonce<D: DatabaseInterface>(db: &D, new_nonce: u64) -> Result<String> {
    info!("✔ Debug setting EVM AnySender nonce...");
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| put_any_sender_nonce_in_db(db, new_nonce))
        .and_then(|_| db.end_transaction())
        .and(Ok(json!({"set_evm_any_sender_nonce":true}).to_string()))
        .map(prepend_debug_output_marker_to_string)
}

#[cfg(all(test, feature = "debug"))]
mod tests {
    use super::*;
    use crate::{
        chains::evm::eth_database_utils::{
            get_any_sender_nonce_from_db,
            get_eth_account_nonce_from_db as get_evm_account_nonce_from_db,
        },
        test_utils::get_test_database,
    };

    #[test]
    fn should_set_evm_account_nonce() {
        let db = get_test_database();
        let nonce = 6;
        put_evm_account_nonce_in_db(&db, nonce).unwrap();
        assert_eq!(get_evm_account_nonce_from_db(&db).unwrap(), nonce);
        let new_nonce = 4;
        debug_set_evm_account_nonce(&db, new_nonce).unwrap();
        assert_eq!(get_evm_account_nonce_from_db(&db).unwrap(), new_nonce);
    }

    #[test]
    fn should_set_evm_any_sender_nonce() {
        let db = get_test_database();
        let nonce = 6;
        put_any_sender_nonce_in_db(&db, nonce).unwrap();
        assert_eq!(get_any_sender_nonce_from_db(&db).unwrap(), nonce);
        let new_nonce = 4;
        debug_set_evm_any_sender_nonce(&db, new_nonce).unwrap();
        assert_eq!(get_any_sender_nonce_from_db(&db).unwrap(), new_nonce);
    }
}
