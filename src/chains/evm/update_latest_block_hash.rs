use crate::{
    chains::evm::{
        eth_database_utils::{get_eth_latest_block_from_db, put_eth_latest_block_hash_in_db},
        eth_state::EthState,
        eth_submission_material::EthSubmissionMaterial,
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn update_latest_block_hash_if_subsequent<D>(
    db: &D,
    maybe_subsequent_submission_material: &EthSubmissionMaterial,
) -> Result<()>
where
    D: DatabaseInterface,
{
    info!("✔ Updating latest ETH block hash if subsequent...");
    get_eth_latest_block_from_db(db)
        .and_then(|latest_submission_material| latest_submission_material.get_block_number())
        .and_then(|latest_block_number| {
            match latest_block_number + 1 == maybe_subsequent_submission_material.get_block_number()? {
                false => {
                    info!("✔ Block NOT subsequent ∴ NOT updating latest block hash!");
                    Ok(())
                },
                true => {
                    info!("✔ Block IS subsequent ∴ updating latest block hash...",);
                    put_eth_latest_block_hash_in_db(db, &maybe_subsequent_submission_material.get_block_hash()?)
                },
            }
        })
}

pub fn maybe_update_latest_block_hash_and_return_state<D>(state: EthState<D>) -> Result<EthState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Maybe updating latest ETH block hash if subsequent...");
    update_latest_block_hash_if_subsequent(&state.db, state.get_eth_submission_material()?).and(Ok(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::evm::{
            eth_database_utils::{get_eth_latest_block_hash_from_db, put_eth_latest_block_in_db},
            eth_test_utils::get_sequential_eth_blocks_and_receipts,
        },
        test_utils::get_test_database,
    };

    #[test]
    fn should_update_latest_block_hash_if_subsequent() {
        let db = get_test_database();
        let latest_submission_material = get_sequential_eth_blocks_and_receipts()[0].clone();
        let latest_block_hash_before = latest_submission_material.get_block_hash().unwrap();
        put_eth_latest_block_in_db(&db, &latest_submission_material).unwrap();
        let subsequent_submission_material = get_sequential_eth_blocks_and_receipts()[1].clone();
        let expected_block_hash_after = subsequent_submission_material.get_block_hash().unwrap();
        update_latest_block_hash_if_subsequent(&db, &subsequent_submission_material).unwrap();
        let latest_block_hash_after = get_eth_latest_block_hash_from_db(&db).unwrap();
        assert_ne!(latest_block_hash_before, latest_block_hash_after);
        assert_eq!(latest_block_hash_after, expected_block_hash_after);
    }

    #[test]
    fn should_not_update_latest_block_hash_if_not_subsequent() {
        let db = get_test_database();
        let latest_submission_material = get_sequential_eth_blocks_and_receipts()[0].clone();
        let latest_block_hash_before = latest_submission_material.get_block_hash().unwrap();
        put_eth_latest_block_in_db(&db, &latest_submission_material).unwrap();
        let non_subsequent_submission_material = get_sequential_eth_blocks_and_receipts()[0].clone();
        update_latest_block_hash_if_subsequent(&db, &non_subsequent_submission_material).unwrap();
        let latest_block_hash_after = get_eth_latest_block_hash_from_db(&db).unwrap();
        assert_eq!(latest_block_hash_before, latest_block_hash_after);
    }
}
