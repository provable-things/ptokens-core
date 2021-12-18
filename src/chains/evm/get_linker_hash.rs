use crate::{
    chains::evm::{
        eth_constants::PTOKEN_GENESIS_HASH_KEY,
        eth_database_utils::get_eth_linker_hash_from_db,
        eth_types::EthHash,
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn get_linker_hash_or_genesis_hash<D: DatabaseInterface>(db: &D) -> Result<EthHash> {
    match get_eth_linker_hash_from_db(db) {
        Ok(hash) => Ok(hash),
        Err(_) => {
            info!("✔ No linker-hash set yet, using pToken genesis hash...");
            Ok(EthHash::from_slice(&PTOKEN_GENESIS_HASH_KEY[..]))
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chains::evm::eth_database_utils::put_eth_linker_hash_in_db, test_utils::get_test_database};

    #[test]
    fn get_linker_or_genesis_should_get_linker_hash_from_db_if_extant() {
        let db = get_test_database();
        let linker_hash = EthHash::random();
        put_eth_linker_hash_in_db(&db, linker_hash).unwrap();
        let result = get_linker_hash_or_genesis_hash(&db).unwrap();
        assert_eq!(result, linker_hash);
    }

    #[test]
    fn get_linker_or_genesis_should_get_genesis_hash_if_linker_not_set() {
        let db = get_test_database();
        let result = get_linker_hash_or_genesis_hash(&db).unwrap();
        assert_eq!(result, EthHash::from_slice(&PTOKEN_GENESIS_HASH_KEY[..]));
    }
}
