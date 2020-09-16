use crate::{
    traits::DatabaseInterface,
    btc_on_eth::btc::btc_database_utils::get_btc_address_from_db,
};

pub fn is_btc_enclave_initialized<D>(
    db: &D
) -> bool
    where D: DatabaseInterface
{
    trace!("✔ Checking if BTC enclave has been initialized...");
    match get_btc_address_from_db(db) {
        Ok(_)=> {
            trace!("✔ BTC enclave *HAS* been initialized!");
            true
        }
        _ => {
            trace!("✔ BTC enclave has *NOT* been initialized!");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::get_test_database,
        btc_on_eth::btc::{
            btc_test_utils::SAMPLE_TARGET_BTC_ADDRESS,
            btc_database_utils::put_btc_address_in_db,
        },
    };

    #[test]
    fn should_return_false_if_btc_enc_not_initialized() {
        let db = get_test_database();
        let result = is_btc_enclave_initialized(&db);
        assert!(!result);
    }

    #[test]
    fn should_return_true_if_btc_enc_initialized() {
        let db = get_test_database();
        if let Err(e) = put_btc_address_in_db(
            &db,
            &SAMPLE_TARGET_BTC_ADDRESS.to_string(),
        ) {
            panic!("Error putting pk in db: {}", e);
        };
        let result = is_btc_enclave_initialized(&db);
        assert!(result);
    }
}
