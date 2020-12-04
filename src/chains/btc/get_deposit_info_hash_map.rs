use crate::{
    chains::btc::{
        btc_state::BtcState,
        deposit_address_info::{DepositAddressInfo, DepositInfoHashMap},
    },
    traits::DatabaseInterface,
    types::Result,
};
use std::collections::HashMap;

pub fn create_hash_map_from_deposit_info_list(deposit_info_list: &[DepositAddressInfo]) -> Result<DepositInfoHashMap> {
    let mut hash_map = HashMap::new();
    deposit_info_list.iter().for_each(|deposit_info| {
        hash_map.insert(deposit_info.btc_deposit_address.clone(), deposit_info.clone());
    });
    Ok(hash_map)
}

pub fn get_deposit_info_hash_map_and_put_in_state<D: DatabaseInterface>(state: BtcState<D>) -> Result<BtcState<D>> {
    create_hash_map_from_deposit_info_list(&state.get_btc_block_and_id()?.deposit_address_list)
        .and_then(|hash_map| state.add_deposit_info_hash_map(hash_map))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::btc::btc_test_utils::get_sample_btc_block_and_id;

    #[test]
    fn should_create_hash_map_from_deposit_info_list() {
        let address_info_list = get_sample_btc_block_and_id().unwrap().deposit_address_list;
        let result = create_hash_map_from_deposit_info_list(&address_info_list).unwrap();
        assert!(!result.is_empty());
        assert_eq!(result.len(), address_info_list.len());
        result
            .iter()
            .for_each(|(key, value)| assert_eq!(key, &value.btc_deposit_address));
    }
}
