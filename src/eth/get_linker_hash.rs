use crate::{
    types::Result,
    errors::AppError,
    traits::DatabaseInterface,
    eth::{
        eth_types::EthHash,
        eth_database_utils::get_hash_from_db_via_hash_key,
        eth_constants::{
            ETH_LINKER_HASH_KEY,
            PTOKEN_GENESIS_HASH,
        },
    },
};

pub fn get_linker_hash_or_genesis_hash<D>(db: &D) -> Result<EthHash>
    where D: DatabaseInterface
{
    match get_hash_from_db_via_hash_key(
        db,
        EthHash::from(ETH_LINKER_HASH_KEY)
    )? {
        Some(hash) => Ok(hash),
        None => {
            info!("✔ No linker-hash set yet, using pToken genesis hash...");
            Ok(EthHash::from(PTOKEN_GENESIS_HASH))
        }
    }
}

pub fn get_linker_hash_from_db<D>(
    db: &D
) -> Result<EthHash>
    where D: DatabaseInterface
{
    match get_hash_from_db_via_hash_key(
        db,
        EthHash::from(ETH_LINKER_HASH_KEY)
    )? {
        Some(hash) => Ok(hash),
        None => Err(AppError::Custom(
            format!("✘ The linker hash is not yet set in db!")
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::get_test_database,
        eth::eth_database_utils::put_eth_linker_hash_in_db,
    };

    #[test]
    fn should_get_linker_hash_from_db_if_extant() {
        let db = get_test_database();
        let linker_hash = EthHash::random();
        put_eth_linker_hash_in_db(&db, linker_hash)
            .unwrap();
        let result = get_linker_hash_from_db(&db)
            .unwrap();
        assert!(result == linker_hash);
    }

    #[test]
    fn should_get_linker_hash_from_db() {
        let db = get_test_database();
        let expected_error = format!("✘ The linker hash is not yet set in db!");
        match get_linker_hash_from_db(&db) {
            Err(AppError::Custom(e)) => assert!(e == expected_error),
            Ok(_) => panic!("Should not have got linker hash!"),
            Err(e) => panic!("Wrong error received: {}", e),
        }
    }

    #[test]
    fn get_linker_or_genesis_should_get_linker_hash_from_db_if_extant() {
        let db = get_test_database();
        let linker_hash = EthHash::random();
        put_eth_linker_hash_in_db(&db, linker_hash)
            .unwrap();
        let result = get_linker_hash_or_genesis_hash(&db)
            .unwrap();
        assert!(result == linker_hash);
    }


    #[test]
    fn get_linker_or_genesis_should_get_genesis_hash_if_linker_not_set() {
        let db = get_test_database();
        let result = get_linker_hash_or_genesis_hash(&db)
            .unwrap();
        assert!(result == EthHash::from(PTOKEN_GENESIS_HASH));
    }
}
