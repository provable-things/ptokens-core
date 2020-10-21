use bitcoin_hashes::sha256d;
use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eth::btc::{
        btc_state::BtcState,
        btc_types::BtcBlockInDbFormat,
        btc_database_utils::{
            get_btc_block_from_db,
            get_btc_tail_block_from_db,
            get_btc_anchor_block_hash_from_db,
        },
    },
};

fn is_anchor_block<D>(
    db: &D,
    btc_block_hash: &sha256d::Hash,
) -> Result<bool>
    where D: DatabaseInterface
{
    match get_btc_anchor_block_hash_from_db(db) {
        Ok(ref hash) => Ok(hash == btc_block_hash),
        _ => Err("✘ No anchor hash found in db!".into())
    }
}

fn remove_parents_if_not_anchor<D>(
    db: &D,
    block_whose_parents_to_be_removed: &BtcBlockInDbFormat,
) -> Result<()>
    where D: DatabaseInterface
{
    match get_btc_block_from_db(
        db,
        &block_whose_parents_to_be_removed.block.header.prev_blockhash,
    ) {
        Err(_) => {
            info!("✔ No block found ∵ doing nothing!");
            Ok(())
        }
        Ok(parent_block) => {
            info!("✔ Block found, checking if it's the anchor block...");
            match is_anchor_block(db, &parent_block.id)? {
                true => {
                    info!("✔ Block IS the anchor block ∴ not removing it!");
                    Ok(())
                }
                false => {
                    info!("✔ Block is NOT the anchor ∴ removing it...");
                    db
                        .delete(parent_block.id.to_vec())
                        .and_then(|_|
                            remove_parents_if_not_anchor(db, &parent_block)
                        )
                }
            }
        }
    }
}

pub fn maybe_remove_old_btc_tail_block<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe removing old BTC tail block...");
    get_btc_tail_block_from_db(&state.db)
        .and_then(|tail_block|
            remove_parents_if_not_anchor(&state.db, &tail_block)
        ).map(|_| state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::get_test_database,
        btc_on_eth::btc::{
            btc_test_utils::{
                put_btc_tail_block_in_db,
                put_btc_anchor_block_in_db,
                get_sample_sequential_btc_blocks_in_db_format,
            },
            btc_database_utils::{
                put_btc_block_in_db,
                btc_block_exists_in_db,
            },
        },
    };

    #[test]
    fn should_return_false_block_is_not_anchor_block() {
        let db = get_test_database();
        let blocks = get_sample_sequential_btc_blocks_in_db_format();
        let anchor_block = blocks[0]
            .clone();
        let non_anchor_block = blocks[1]
            .clone();
        assert_ne!(anchor_block, non_anchor_block);
        if let Err(e) = put_btc_anchor_block_in_db(&db, &anchor_block) {
            panic!("Error putting btc anchor block in db: {}", e);
        };
        let result = is_anchor_block(&db, &non_anchor_block.id)
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn should_return_true_if_block_is_anchor_block() {
        let db = get_test_database();
        let blocks = get_sample_sequential_btc_blocks_in_db_format();
        let anchor_block = blocks[0]
            .clone();
        if let Err(e) = put_btc_anchor_block_in_db(&db, &anchor_block) {
            panic!("Error putting btc anchor block in db: {}", e);
        };
        let result = is_anchor_block(&db, &anchor_block.id)
            .unwrap();
        assert!(result);
    }

    #[test]
    fn should_remove_parent_block_if_parent_is_not_anchor() {
        let db = get_test_database();
        let blocks = get_sample_sequential_btc_blocks_in_db_format();
        let anchor_block = blocks[0]
            .clone();
        let block = blocks[2]
            .clone();
        let parent_block = blocks[1]
            .clone();
        assert_eq!(parent_block.id, block.block.header.prev_blockhash);
        if let Err(e) = put_btc_anchor_block_in_db(&db, &anchor_block) {
            panic!("Error putting btc anchor block in db: {}", e);
        };
        if let Err(e) = put_btc_block_in_db(&db, &block) {
            panic!("Error putting btc block in db: {}", e);
        };
        if let Err(e) = put_btc_block_in_db(&db, &parent_block) {
            panic!("Error putting btc block in db: {}", e);
        };
        assert!(btc_block_exists_in_db(&db, &parent_block.id));
        if let Err(e) = remove_parents_if_not_anchor(&db, &block) {
            panic!("Error removing parent block if not anchor: {}", e);
        };
        assert!(!btc_block_exists_in_db(&db, &parent_block.id));
    }

    #[test]
    fn should_not_remove_parent_block_if_parent_is_anchor() {
        let db = get_test_database();
        let blocks = get_sample_sequential_btc_blocks_in_db_format();
        let anchor_block = blocks[0]
            .clone();
        let block = blocks[1]
            .clone();
        assert_eq!(block.block.header.prev_blockhash, anchor_block.id);
        if let Err(e) = put_btc_anchor_block_in_db(&db, &anchor_block) {
            panic!("Error putting btc anchor block in db: {}", e);
        };
        if let Err(e) = put_btc_block_in_db(&db, &block) {
            panic!("Error putting btc block in db: {}", e);
        };
        assert!(btc_block_exists_in_db(&db, &anchor_block.id));
        if let Err(e) = remove_parents_if_not_anchor(&db, &block) {
            panic!("Error removing parent block if not anchor: {}", e);
        };
        assert!(btc_block_exists_in_db(&db, &block.id));
    }

    #[test]
    fn should_remove_parent_blocks_recursively_if_not_anchor_blocks() {
        let db = get_test_database();
        let all_blocks = get_sample_sequential_btc_blocks_in_db_format();
        let blocks = &all_blocks[1..all_blocks.len() - 1];
        let tail_block = all_blocks[all_blocks.len() - 1]
            .clone();
        let anchor_block = all_blocks[0]
            .clone();
        if let Err(e) = put_btc_anchor_block_in_db(&db, &anchor_block) {
            panic!("Error putting btc anchor block in db: {}", e);
        };
        if let Err(e) = put_btc_tail_block_in_db(&db, &tail_block) {
            panic!("Error putting btc tail block in db: {}", e);
        };
        assert!(btc_block_exists_in_db(&db, &anchor_block.id));
        blocks
            .iter()
            .map(|block| put_btc_block_in_db(&db, block))
            .collect::<Result<()>>()
            .unwrap();
        blocks
            .iter()
            .map(|block| {
                assert!(btc_block_exists_in_db(&db, &block.id))
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
            .map(|block| assert!(!btc_block_exists_in_db(&db, &block.id)))
            .for_each(drop);
        assert!(btc_block_exists_in_db(&db, &tail_block.id));
        assert!(btc_block_exists_in_db(&db, &anchor_block.id));
    }
}
