use crate::{
    types::Result,
    traits::DatabaseInterface,
    eth::{
        eth_state::EthState,
        calculate_linker_hash::calculate_linker_hash,
        get_linker_hash::get_linker_hash_or_genesis_hash,
        eth_types::{
            EthHash,
            EthBlockAndReceipts,
        },
        eth_database_utils::{
            put_eth_linker_hash_in_db,
            get_eth_tail_block_from_db,
            get_eth_anchor_block_from_db,
            maybe_get_parent_eth_block_and_receipts,
        },
    },
};

fn get_new_linker_hash<D>(
    db: &D,
    block_hash_to_link_to: &EthHash
) -> Result<EthHash>
    where D: DatabaseInterface
{
    info!("✔ Calculating new linker hash...");
    get_eth_anchor_block_from_db(db)
        .and_then(|anchor_block|
            Ok(
                calculate_linker_hash(
                    *block_hash_to_link_to,
                    anchor_block.block.hash,
                    get_linker_hash_or_genesis_hash(db)?,
                )
            )
        )
}

fn maybe_get_parent_of_eth_tail_block<D>(
    db: &D
) -> Result<Option<EthBlockAndReceipts>>
    where D: DatabaseInterface
{
    info!("✔ Maybe getting parent of ETH tail block from db...");
    get_eth_tail_block_from_db(db)
        .map(|eth_canon_block|
            maybe_get_parent_eth_block_and_receipts(
                db,
                &eth_canon_block.block.hash
            )
        )
}

pub fn maybe_update_eth_linker_hash_and_return_state<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe updating the ETH linker hash...");
    maybe_update_linker_hash(&state.db)
        .map(|_| state)
}

fn maybe_update_linker_hash<D>(db: &D) -> Result<()>
    where D: DatabaseInterface
{
    match maybe_get_parent_of_eth_tail_block(db)? {
        Some(parent_of_eth_tail_block) => {
            info!("✔ Updating ETH linker hash...");
            get_new_linker_hash(db, &parent_of_eth_tail_block.block.hash)
                .and_then(|linker_hash|
                    put_eth_linker_hash_in_db(db, linker_hash)
                )
                .and_then(|_| Ok(()))
        }
        None => {
            info!("✔ ETH tail has no parent in db ∴ NOT updating linker hash");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::get_test_database,
        eth::{
            eth_test_utils::get_sequential_eth_blocks_and_receipts,
            eth_database_utils::{
                put_eth_tail_block_in_db,
                put_eth_anchor_block_in_db,
                get_eth_linker_hash_from_db,
                put_eth_block_and_receipts_in_db,
            },
        },
    };

    #[test]
    fn should_get_parent_of_canon_if_extant() {
        let db = get_test_database();
        let blocks_and_receipts = get_sequential_eth_blocks_and_receipts();
        let canon_block = blocks_and_receipts[5].clone();
        let parent_of_eth_tail_block = blocks_and_receipts[4].clone();
        assert!(
            canon_block.block.parent_hash == parent_of_eth_tail_block.block.hash
        );
        put_eth_tail_block_in_db(&db, &canon_block)
            .unwrap();
        put_eth_block_and_receipts_in_db(&db, &parent_of_eth_tail_block)
            .unwrap();
        let result = maybe_get_parent_of_eth_tail_block(&db)
            .unwrap()
            .unwrap();
        assert!(result == parent_of_eth_tail_block);
    }

    #[test]
    fn should_not_get_parent_of_canon_if_extant() {
        let db = get_test_database();
        let blocks_and_receipts = get_sequential_eth_blocks_and_receipts();
        let canon_block = blocks_and_receipts[5].clone();
        put_eth_tail_block_in_db(&db, &canon_block)
            .unwrap();
        let result = maybe_get_parent_of_eth_tail_block(&db)
            .unwrap();
        assert!(result == None);
    }

    #[test]
    fn should_get_new_linker_hash() {
        let db = get_test_database();
        let expected_result_hex =
            "5cfaf026b198808363c898b2f7fcada79d88fe163fa6281211956a5431481ecf";
        let blocks_and_receipts = get_sequential_eth_blocks_and_receipts();
        let block_hash_to_link_to = blocks_and_receipts[5].block.hash.clone();
        let anchor_block = blocks_and_receipts[1].clone();
        let linker_hash = blocks_and_receipts[3].block.hash;
        put_eth_linker_hash_in_db(&db, linker_hash).unwrap();
        put_eth_anchor_block_in_db(&db, &anchor_block)
            .unwrap();
        let result = get_new_linker_hash(&db, &block_hash_to_link_to)
            .unwrap();
        let result_hex = hex::encode(result.as_bytes());
        assert!(result_hex == expected_result_hex);
    }

    #[test]
    fn should_maybe_update_linker_hash_if_canon_parent_extant() {
        let db = get_test_database();
        let expected_result_hex =
            "726d388bff7dd43ccb0f91e995ec83fd56228a3a7cd6f6eae1bc2855c7e942be";
        let blocks_and_receipts = get_sequential_eth_blocks_and_receipts();
        let linker_hash_before = blocks_and_receipts[9].block.hash;
        let anchor_block = blocks_and_receipts[1].clone();
        let canon_block = blocks_and_receipts[5].clone();
        let parent_of_eth_tail_block = blocks_and_receipts[4].clone();
        put_eth_linker_hash_in_db(&db, linker_hash_before)
            .unwrap();
        put_eth_anchor_block_in_db(&db, &anchor_block)
            .unwrap();
        put_eth_tail_block_in_db(&db, &canon_block)
            .unwrap();
        put_eth_block_and_receipts_in_db(&db, &parent_of_eth_tail_block)
            .unwrap();
        maybe_update_linker_hash(&db).unwrap();
        let linker_hash_after = get_eth_linker_hash_from_db(&db)
            .unwrap();
        let result_hex = hex::encode(linker_hash_after.as_bytes());
        assert!(linker_hash_after != linker_hash_before);
        assert!(result_hex == expected_result_hex);
    }

    #[test]
    fn should_not_update_linker_hash_if_canon_parent_not_extant() {
        let db = get_test_database();
        let expected_result_hex =
            "f8e2c3efa74ff5523bcb26c7088d982c60440a7f8ccc9027c548386853f962df";
        let blocks_and_receipts = get_sequential_eth_blocks_and_receipts();
        let linker_hash_before = blocks_and_receipts[9].block.hash;
        let anchor_block = blocks_and_receipts[1].clone();
        let canon_block = blocks_and_receipts[5].clone();
        put_eth_linker_hash_in_db(&db, linker_hash_before).unwrap();
        put_eth_anchor_block_in_db(&db, &anchor_block)
            .unwrap();
        put_eth_tail_block_in_db(&db, &canon_block)
            .unwrap();
        maybe_update_linker_hash(&db).unwrap();
        let linker_hash_after = get_eth_linker_hash_from_db(&db)
            .unwrap();
        let result_hex = hex::encode(linker_hash_after.as_bytes());
        assert!(linker_hash_after == linker_hash_before);
        assert!(result_hex == expected_result_hex);
    }
}
