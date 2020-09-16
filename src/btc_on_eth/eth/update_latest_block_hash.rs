use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eth::eth::{
        eth_state::EthState,
        eth_types::EthBlock,
        eth_database_utils::{
            get_eth_latest_block_from_db,
            put_eth_latest_block_hash_in_db,
        },
    },
};

fn is_block_subsequent(
    block_in_question: &EthBlock,
    latest_block_from_database: &EthBlock,
) -> bool {
    latest_block_from_database.number == block_in_question.number + 1
}

fn update_latest_block_hash_if_subsequent<D>(
    db: &D,
    maybe_subsequent_block: &EthBlock,
) -> Result<()>
    where D: DatabaseInterface
{
    info!("✔ Updating latest ETH block hash if subsequent...");
    get_eth_latest_block_from_db(db)
        .and_then(|latest_block_and_receipts|
            match is_block_subsequent(
                &latest_block_and_receipts.block,
                &maybe_subsequent_block,
            ) {
                false => {
                    info!(
                        "✔ Block NOT subsequent {}",
                        "∴ NOT updating latest block hash",
                    );
                    Ok(())
                }
                true => {
                    info!(
                        "✔ Block IS subsequent {}",
                        "∴ updating latest block hash...",
                    );
                    put_eth_latest_block_hash_in_db(
                        db,
                        &maybe_subsequent_block.hash,
                    )
                }
            }
        )
}

pub fn maybe_update_latest_block_hash<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe updating latest ETH block hash if subsequent...");
    update_latest_block_hash_if_subsequent(
        &state.db,
        &state.get_eth_block_and_receipts()?.block,
    )
        .map(|_| state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::get_test_database,
        chains::eth::eth_constants::ETH_LATEST_BLOCK_HASH_KEY,
        btc_on_eth::{
            eth::{
                eth_types::EthHash,
                eth_database_utils::get_hash_from_db_via_hash_key,
                eth_test_utils::{
                    put_eth_latest_block_in_db,
                    get_eth_latest_block_hash_from_db,
                    get_sequential_eth_blocks_and_receipts,
                },
            },
        },
    };

    #[test]
    fn should_return_true_if_block_is_subsequent() {
        let blocks_and_receipts = get_sequential_eth_blocks_and_receipts();
        let result = is_block_subsequent(&blocks_and_receipts[0].block, &blocks_and_receipts[1].block);
        assert!(result);
    }

    #[test]
    fn should_return_false_if_block_is_not_subsequent() {
        let blocks_and_receipts = get_sequential_eth_blocks_and_receipts();
        for i in 2..blocks_and_receipts.len() {
            assert!(!is_block_subsequent(&blocks_and_receipts[0].block, &blocks_and_receipts[i].block));
        }
    }

    #[test]
    fn should_update_latest_block_hash_if_subsequent() {
        let db = get_test_database();
        let latest_block_and_receipts = get_sequential_eth_blocks_and_receipts()[0].clone();
        let latest_block_hash_before = latest_block_and_receipts.block.hash;
        put_eth_latest_block_in_db(&db, &latest_block_and_receipts).unwrap();
        let subsequent_block = get_sequential_eth_blocks_and_receipts()[1].clone();
        let expected_block_hash_after = subsequent_block.block.hash;
        if let Err(e) = update_latest_block_hash_if_subsequent(
            &db,
            &subsequent_block.block,
        ) {
            panic!("Error when maybe updating latest blockhash: {}", e);
        };
        let latest_block_hash_after = get_eth_latest_block_hash_from_db(&db).unwrap();
        assert_ne!(latest_block_hash_before, latest_block_hash_after);
        assert_eq!(latest_block_hash_after, expected_block_hash_after);
    }

    #[test]
    fn should_not_update_latest_block_hash_if_not_subsequent() {
        let db = get_test_database();
        let latest_block_and_receipts = get_sequential_eth_blocks_and_receipts()[0].clone();
        let latest_block_hash_before = latest_block_and_receipts.block.hash;
        put_eth_latest_block_in_db(&db, &latest_block_and_receipts).unwrap();
        let non_subsequent_block = get_sequential_eth_blocks_and_receipts()[0].clone();
        if let Err(e) = update_latest_block_hash_if_subsequent(&db, &non_subsequent_block.block) {
            panic!("Error when maybe updating latest blockhash: {}", e);
        };
        let latest_block_hash_after = get_hash_from_db_via_hash_key(
            &db,
            EthHash::from_slice(&ETH_LATEST_BLOCK_HASH_KEY[..]),
        ).unwrap().unwrap();
        assert_eq!(latest_block_hash_before, latest_block_hash_after);
    }
}
