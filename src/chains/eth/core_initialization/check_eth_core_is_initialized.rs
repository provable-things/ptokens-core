use crate::{
    chains::eth::eth_database_utils::get_public_eth_address_from_db,
    traits::DatabaseInterface,
    types::Result,
};

pub fn is_eth_core_initialized<D: DatabaseInterface>(db: &D) -> bool {
    get_public_eth_address_from_db(db).is_ok()
}

pub fn check_eth_core_is_initialized<D: DatabaseInterface>(db: &D) -> Result<()> {
    info!("✔ Checking ETH core is initialized...");
    match is_eth_core_initialized(db) {
        false => Err("✘ ETH side of core not initialized!".into()),
        true => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::eth::{eth_database_utils::put_public_eth_address_in_db, eth_test_utils::get_sample_eth_address},
        errors::AppError,
        test_utils::get_test_database,
    };

    #[test]
    fn should_return_false_if_eth_core_not_initialized() {
        let db = get_test_database();
        let result = is_eth_core_initialized(&db);
        assert!(!result);
    }

    #[test]
    fn should_return_true_if_eth_core_initialized() {
        let db = get_test_database();
        put_public_eth_address_in_db(&db, &get_sample_eth_address()).unwrap();
        let result = is_eth_core_initialized(&db);
        assert!(result);
    }

    #[test]
    fn should_not_err_if_core_initialized() {
        let db = get_test_database();
        put_public_eth_address_in_db(&db, &get_sample_eth_address()).unwrap();
        let result = check_eth_core_is_initialized(&db);
        assert!(result.is_ok());
    }

    #[test]
    fn should_err_if_core_not_initialized() {
        let db = get_test_database();
        let expected_err = "✘ ETH side of core not initialized!".to_string();
        match check_eth_core_is_initialized(&db) {
            Err(AppError::Custom(err)) => assert_eq!(err, expected_err),
            Ok(_) => panic!("Should not have succeeded!"),
            Err(_) => panic!("Wrong error received!"),
        }
    }
}
