use ethereum_types::H256 as EthHash;
use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eth::{
        utils::convert_h256_to_bytes,
        eth::{
            eth_state::EthState,
            eth_database_utils::key_exists_in_db,
        },
    },
};

fn check_db_for_parent_of_block_in_state<D>(
    db: &D,
    parent_hash: &EthHash
) -> bool
    where D: DatabaseInterface
{
    key_exists_in_db(db, &convert_h256_to_bytes(*parent_hash), None)
}

pub fn check_for_parent_of_block_in_state<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Checking block's parent exists in database...");
    match check_db_for_parent_of_block_in_state(
        &state.db,
        &state.get_parent_hash()?
    ) {
        true => {
            info!("✔ Block's parent exists in database!");
            Ok(state)
        },
        false => Err("✘ Block Rejected - no parent exists in database!".into()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::get_test_database,
        btc_on_eth::eth::eth_test_utils::get_valid_state_with_block_and_receipts,
    };

    #[test]
    fn should_return_false_if_parent_not_in_db() {
        let db = get_test_database();
        let state = get_valid_state_with_block_and_receipts()
            .unwrap();
        let result = check_db_for_parent_of_block_in_state(
            &db,
            &state.get_parent_hash().unwrap(),
        );
        assert!(!result);
    }

    #[test]
    fn should_return_true_if_parent_in_db() {
        let db = get_test_database();
        let state = get_valid_state_with_block_and_receipts()
            .unwrap();
        let parent_hash = state.get_parent_hash()
            .unwrap();
        let key = convert_h256_to_bytes(parent_hash);
        let value = vec![0xc0, 0xff, 0xee];
        db.put(key, value, None)
            .unwrap();
        let result = check_db_for_parent_of_block_in_state(&db, &parent_hash);
        assert!(result);
    }
}
