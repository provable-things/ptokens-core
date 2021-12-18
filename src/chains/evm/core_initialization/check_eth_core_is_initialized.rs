use crate::{chains::evm::eth_database_utils::get_public_eth_address_from_db, traits::DatabaseInterface};

pub fn is_eth_core_initialized<D: DatabaseInterface>(db: &D) -> bool {
    get_public_eth_address_from_db(db).is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::evm::{eth_database_utils::put_public_eth_address_in_db, eth_test_utils::get_sample_eth_address},
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
}
