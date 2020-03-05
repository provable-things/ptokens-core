use crate::{
    types::Result,
    errors::AppError,
    traits::DatabaseInterface,
    eth::{
        eth_state::EthState,
        eth_types::EthBlockAndReceipts,
        eth_database_utils::{
            eth_block_exists_in_db,
            put_eth_block_and_receipts_in_db,
        },
    },
};

fn add_block_and_receipts_to_db_if_not_extant<D>(
    db: &D,
    block_and_receipts: &EthBlockAndReceipts,
) -> Result<()>
    where D: DatabaseInterface
{
    info!("✔ Adding ETH block and receipts if not already in db...");
    match eth_block_exists_in_db(db, &block_and_receipts.block.hash) {
        false => {
            info!("✔ Block & receipts not in db, adding them now...");
            put_eth_block_and_receipts_in_db(db, block_and_receipts)
        }
        true => Err(AppError::Custom(
            format!("✘ Block Rejected - it's already in the db!")
        ))
    }
}

pub fn maybe_add_block_and_receipts_to_db_and_return_state<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe adding ETH block and receipts if not in db...");
    add_block_and_receipts_to_db_if_not_extant(
        &state.db,
        state.get_eth_block_and_receipts()?,
    )
        .map(|_| state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::get_test_database,
        eth::eth_test_utils::get_sample_eth_block_and_receipts_n,
    };


    #[test]
    fn should_maybe_add_block_and_receipts_to_db() {
        let db = get_test_database();
        let block_and_receipts = get_sample_eth_block_and_receipts_n(1)
            .unwrap();
        let eth_block_hash = block_and_receipts
            .block
            .hash
            .clone();
        let bool_before = eth_block_exists_in_db(&db, &eth_block_hash);
        assert!(!bool_before);
        if let Err(e) = add_block_and_receipts_to_db_if_not_extant(
            &db,
            &block_and_receipts
        ) {
            panic!("Error when maybe adding block to database: {}", e);
        }
        let bool_after = eth_block_exists_in_db(&db, &eth_block_hash);
        assert!(bool_after);
    }

    #[test]
    fn should_error_if_block_already_in_db() {
        let db = get_test_database();
        let block_and_receipts = get_sample_eth_block_and_receipts_n(1)
            .unwrap();
        let eth_block_hash = block_and_receipts
            .block
            .hash
            .clone();
        let bool_before = eth_block_exists_in_db(&db, &eth_block_hash);
        assert!(!bool_before);
        if let Err(e) = add_block_and_receipts_to_db_if_not_extant(
            &db,
            &block_and_receipts,
        ) {
            panic!("Error when maybe adding block to database: {}", e);
        };
        let bool_after = eth_block_exists_in_db(&db, &eth_block_hash);
        if let Ok(_) = add_block_and_receipts_to_db_if_not_extant(
            &db,
            &block_and_receipts,
        ) {
            panic!("Should error ∴ block already in db: {}");
        }
        assert!(bool_after);
    }
}
