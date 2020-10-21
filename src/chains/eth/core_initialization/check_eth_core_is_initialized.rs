use crate::{
    traits::DatabaseInterface,
    chains::eth::eth_database_utils::get_public_eth_address_from_db,
};


pub fn is_eth_core_initialized<D>(db: &D) -> bool where D: DatabaseInterface {
    trace!("✔ Checking if ETH enclave has been initialized...");
    match get_public_eth_address_from_db(db) {
        Ok(_)=> {
            debug!("✔ ETH enclave *HAS* been initialized!");
            true
        }
        _ => {
            debug!("✔ ETH enclave has *NOT* been initialized!");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::get_test_database,
        btc_on_eth::eth::eth_test_utils::get_sample_eth_address,
        chains::eth::eth_database_utils::put_public_eth_address_in_db,
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
}
