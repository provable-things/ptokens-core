use ethereum_types::H256;

use crate::{
    chains::eth::eth_types::TrieHashMap,
    types::{Bytes, Result},
};

pub fn get_new_trie_hash_map() -> Result<TrieHashMap> {
    Ok(std::collections::HashMap::new())
}

pub fn put_thing_in_trie_hash_map(mut trie_hash_map: TrieHashMap, key: H256, value: Bytes) -> Result<TrieHashMap> {
    trie_hash_map.insert(key, value);
    Ok(trie_hash_map)
}

pub fn remove_thing_from_trie_hash_map(mut trie_hash_map: TrieHashMap, key: &H256) -> Result<TrieHashMap> {
    match trie_hash_map.remove(&key) {
        Some(_) => Ok(trie_hash_map),
        None => Ok(trie_hash_map),
    }
}

pub fn get_thing_from_trie_hash_map(trie_hash_map: &TrieHashMap, key: &H256) -> Option<Bytes> {
    trie_hash_map.get(&key).map(|thing| thing.to_vec())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::eth::eth_test_utils::{
        get_expected_key_of_thing_in_trie_hash_map,
        get_thing_to_put_in_trie_hash_map,
        get_trie_hash_map_with_thing_in_it,
    };

    #[test]
    fn should_get_new_empty_trie_hash_map() {
        let trie_hash_map = get_new_trie_hash_map().unwrap();
        assert!(trie_hash_map.is_empty())
    }

    #[test]
    fn should_insert_thing_in_trie_hash_map() {
        let trie_hash_map = get_new_trie_hash_map().unwrap();
        let expected_result = get_thing_to_put_in_trie_hash_map();
        put_thing_in_trie_hash_map(
            trie_hash_map,
            get_expected_key_of_thing_in_trie_hash_map(),
            expected_result,
        )
        .unwrap();
    }

    #[test]
    fn should_get_thing_from_trie_hash_map() {
        let expected_thing = get_thing_to_put_in_trie_hash_map();
        let trie_hash_map = get_trie_hash_map_with_thing_in_it().unwrap();
        let key = get_expected_key_of_thing_in_trie_hash_map();
        let result = get_thing_from_trie_hash_map(&trie_hash_map, &key).unwrap();
        assert_eq!(result, expected_thing);
    }

    #[test]
    fn should_remove_thing_from_trie_hash_map() {
        let key = get_expected_key_of_thing_in_trie_hash_map();
        let trie_hash_map = get_new_trie_hash_map().unwrap();
        let updated_trie_hash_map =
            put_thing_in_trie_hash_map(trie_hash_map, key, get_thing_to_put_in_trie_hash_map()).unwrap();
        assert!(updated_trie_hash_map.contains_key(&key));
        let result = remove_thing_from_trie_hash_map(updated_trie_hash_map, &key).unwrap();
        assert!(!result.contains_key(&key));
    }
}
