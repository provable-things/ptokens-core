use crate::{chains::btc::btc_database_utils::get_btc_address_from_db, traits::DatabaseInterface};

pub fn is_btc_enclave_initialized<D: DatabaseInterface>(db: &D) -> bool {
    trace!("✔ Checking if BTC enclave has been initialized...");
    match get_btc_address_from_db(db) {
        Ok(_) => {
            trace!("✔ BTC enclave *HAS* been initialized!");
            true
        },
        _ => {
            trace!("✔ BTC enclave has *NOT* been initialized!");
            false
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::btc::{btc_database_utils::put_btc_address_in_db, btc_test_utils::SAMPLE_TARGET_BTC_ADDRESS},
        test_utils::get_test_database,
    };

    #[test]
    fn should_return_false_if_btc_enc_not_initialized() {
        let db = get_test_database();
        assert!(!is_btc_enclave_initialized(&db));
    }

    #[test]
    fn should_return_true_if_btc_enc_initialized() {
        let db = get_test_database();
        put_btc_address_in_db(&db, &SAMPLE_TARGET_BTC_ADDRESS.to_string()).unwrap();
        assert!(is_btc_enclave_initialized(&db));
    }
}
