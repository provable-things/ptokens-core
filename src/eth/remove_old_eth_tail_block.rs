use ethereum_types::H256 as EthHash;
use crate::{
    types::Result,
    errors::AppError,
    traits::DatabaseInterface,
    eth::{
        eth_types::EthBlockAndReceipts,
        eth_state::EthState,
        eth_database_utils::{
            get_eth_block_from_db,
            get_eth_tail_block_from_db,
            get_eth_anchor_block_hash_from_db,
        },
    },
};

fn is_anchor_block<D>(
    db: &D,
    eth_block_hash: &EthHash,
) -> Result<bool>
    where D: DatabaseInterface
{
    match get_eth_anchor_block_hash_from_db(db) {
        Ok(hash) => Ok(&hash == eth_block_hash),
        _ => Err(AppError::Custom(
            format!("✘ No anchor hash found in db!")
        ))
    }
}

fn remove_parents_if_not_anchor<D>(
    db: &D,
    block_whose_parents_to_be_removed: &EthBlockAndReceipts,
) -> Result<()>
    where D: DatabaseInterface
{
    match get_eth_block_from_db(
        db,
        &block_whose_parents_to_be_removed.block.parent_hash,
    ) {
        Err(_) => {
            info!("✔ No block found ∵ doing nothing!");
            Ok(())
        }
        Ok(parent_block) => {
            info!("✔ Block found, checking if it's the anchor block...");
            match is_anchor_block(db, &parent_block.block.hash)? {
                true => {
                    info!("✔ Block IS the anchor block ∴ not removing it!");
                    Ok(())
                }
                false => {
                    info!("✔ Block is NOT the anchor ∴ removing it...");
                    db
                        .delete(parent_block.block.hash.as_bytes().to_vec())
                        .and_then(|_|
                            remove_parents_if_not_anchor(db, &parent_block)
                        )
                }
            }
        }
    }
}

pub fn maybe_remove_old_eth_tail_block<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe removing old ETH tail block...");
    get_eth_tail_block_from_db(&state.db)
        .and_then(|tail_block|
            remove_parents_if_not_anchor(&state.db, &tail_block)
        )
        .and_then(|_| Ok(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::get_test_database,
        eth::{
            eth_test_utils::get_sequential_eth_blocks_and_receipts,
            eth_database_utils::{
                eth_block_exists_in_db,
                put_eth_tail_block_in_db,
                put_eth_anchor_block_in_db,
                put_eth_block_and_receipts_in_db
            },
        },
    };

    #[test]
    fn should_return_false_block_is_not_anchor_block() {
        let db = get_test_database();
        let blocks = get_sequential_eth_blocks_and_receipts();
        let anchor_block = blocks[0]
            .clone();
        let non_anchor_block = blocks[1]
            .clone();
        assert_ne!(anchor_block, non_anchor_block);
        if let Err(e) = put_eth_anchor_block_in_db(&db, &anchor_block) {
            panic!("Error putting btc anchor block in db: {}", e);
        };
        let result = is_anchor_block(&db, &non_anchor_block.block.hash)
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn should_return_true_if_block_is_anchor_block() {
        let db = get_test_database();
        let blocks = get_sequential_eth_blocks_and_receipts();
        let anchor_block = blocks[0]
            .clone();
        if let Err(e) = put_eth_anchor_block_in_db(&db, &anchor_block) {
            panic!("Error putting btc anchor block in db: {}", e);
        };
        let result = is_anchor_block(&db, &anchor_block.block.hash)
            .unwrap();
        assert!(result);
    }

    #[test]
    fn should_remove_parent_block_if_parent_is_not_anchor() {
        let db = get_test_database();
        let blocks = get_sequential_eth_blocks_and_receipts();
        let anchor_block = blocks[0]
            .clone();
        let block = blocks[2]
            .clone();
        let parent_block = blocks[1]
            .clone();
        assert_eq!(parent_block.block.hash, block.block.parent_hash);
        if let Err(e) = put_eth_anchor_block_in_db(&db, &anchor_block) {
            panic!("Error putting btc anchor block in db: {}", e);
        };
        if let Err(e) = put_eth_block_and_receipts_in_db(&db, &block) {
            panic!("Error putting btc block in db: {}", e);
        };
        if let Err(e) = put_eth_block_and_receipts_in_db(&db, &parent_block) {
            panic!("Error putting btc block in db: {}", e);
        };
        assert!(eth_block_exists_in_db(&db, &parent_block.block.hash));
        if let Err(e) = remove_parents_if_not_anchor(&db, &block) {
            panic!("Error removing parent block if not anchor: {}", e);
        };
        assert!(!eth_block_exists_in_db(&db, &parent_block.block.hash));
    }

    #[test]
    fn should_not_remove_parent_block_if_parent_is_anchor() {
        let db = get_test_database();
        let blocks = get_sequential_eth_blocks_and_receipts();
        let anchor_block = blocks[0]
            .clone();
        let block = blocks[1]
            .clone();
        assert_eq!(block.block.parent_hash, anchor_block.block.hash);
        if let Err(e) = put_eth_anchor_block_in_db(&db, &anchor_block) {
            panic!("Error putting btc anchor block in db: {}", e);
        };
        if let Err(e) = put_eth_block_and_receipts_in_db(&db, &block) {
            panic!("Error putting btc block in db: {}", e);
        };
        assert!(eth_block_exists_in_db(&db, &anchor_block.block.hash));
        if let Err(e) = remove_parents_if_not_anchor(&db, &block) {
            panic!("Error removing parent block if not anchor: {}", e);
        };
        assert!(eth_block_exists_in_db(&db, &block.block.hash));
    }

    #[test]
    fn should_remove_parent_blocks_recursively_if_not_anchor_blocks() {
        let db = get_test_database();
        let all_blocks = get_sequential_eth_blocks_and_receipts();
        let blocks = &all_blocks[1..all_blocks.len() - 1];
        let tail_block = all_blocks[all_blocks.len() - 1]
            .clone();
        let anchor_block = all_blocks[0]
            .clone();
        if let Err(e) = put_eth_anchor_block_in_db(&db, &anchor_block) {
            panic!("Error putting btc anchor block in db: {}", e);
        };
        if let Err(e) = put_eth_tail_block_in_db(&db, &tail_block) {
            panic!("Error putting btc tail block in db: {}", e);
        };
        assert!(eth_block_exists_in_db(&db, &anchor_block.block.hash));
        blocks
            .iter()
            .map(|block| put_eth_block_and_receipts_in_db(&db, block))
            .collect::<Result<()>>()
            .unwrap();
        blocks
            .iter()
            .map(|block| {
                assert!(eth_block_exists_in_db(&db, &block.block.hash))
            })
            .for_each(drop);
        if let Err(e) = remove_parents_if_not_anchor(
            &db,
            &tail_block,
        ) {
            panic!("Error removing parent block if not anchor: {}", e);
        };
        blocks
            .iter()
            .map(|block| assert!(!eth_block_exists_in_db(&db, &block.block.hash)))
            .for_each(drop);
        assert!(eth_block_exists_in_db(&db, &tail_block.block.hash));
        assert!(eth_block_exists_in_db(&db, &anchor_block.block.hash));
    }
}
