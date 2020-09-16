use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::eth::eth_constants::{
        ETH_LINKER_HASH_KEY,
        PTOKEN_GENESIS_HASH,
    },
    btc_on_eth::eth::{
        eth_types::EthHash,
        eth_database_utils::get_hash_from_db_via_hash_key,
    },
};

pub fn get_linker_hash_or_genesis_hash<D>(db: &D) -> Result<EthHash>
    where D: DatabaseInterface
{
    match get_hash_from_db_via_hash_key(
        db,
        EthHash::from_slice(&ETH_LINKER_HASH_KEY[..])
    )? {
        Some(hash) => Ok(hash),
        None => {
            info!("✔ No linker-hash set yet, using pToken genesis hash...");
            Ok(EthHash::from_slice(&PTOKEN_GENESIS_HASH[..]))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::get_test_database,
        btc_on_eth::eth::eth_database_utils::put_eth_linker_hash_in_db,
    };

    #[test]
    fn get_linker_or_genesis_should_get_linker_hash_from_db_if_extant() {
        let db = get_test_database();
        let linker_hash = EthHash::random();
        put_eth_linker_hash_in_db(&db, linker_hash)
            .unwrap();
        let result = get_linker_hash_or_genesis_hash(&db)
            .unwrap();
        assert_eq!(result, linker_hash);
    }


    #[test]
    fn get_linker_or_genesis_should_get_genesis_hash_if_linker_not_set() {
        let db = get_test_database();
        let result = get_linker_hash_or_genesis_hash(&db)
            .unwrap();
        assert_eq!(result, EthHash::from_slice(&PTOKEN_GENESIS_HASH[..]));
    }
}
