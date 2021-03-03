use crate::{
    chains::eth::{
        eth_database_utils::{get_eth_canon_block_from_db, put_eth_canon_block_in_db},
        eth_state::EthState,
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn remove_receipts_from_canon_block_and_save_in_db<D>(db: &D) -> Result<()>
where
    D: DatabaseInterface,
{
    get_eth_canon_block_from_db(db).and_then(|block| put_eth_canon_block_in_db(db, &block.remove_receipts()))
}

pub fn maybe_remove_receipts_from_canon_block_and_return_state<D>(state: EthState<D>) -> Result<EthState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Removing receipts from canon block...");
    remove_receipts_from_canon_block_and_save_in_db(&state.db).and(Ok(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chains::eth::eth_test_utils::get_sample_eth_submission_material, test_utils::get_test_database};

    #[test]
    fn should_remove_receipts_from_canon_block() {
        let db = get_test_database();
        let canon_block = get_sample_eth_submission_material();
        put_eth_canon_block_in_db(&db, &canon_block).unwrap();
        let num_receipts_before = get_eth_canon_block_from_db(&db).unwrap().receipts.len();
        if let Err(e) = remove_receipts_from_canon_block_and_save_in_db(&db) {
            panic!("Error maybe removing receipts from canon: {}", e);
        }
        let num_receipts_after = get_eth_canon_block_from_db(&db).unwrap().receipts.len();
        assert!(num_receipts_before > 0);
        assert_eq!(num_receipts_after, 0);
    }

    #[test]
    fn should_not_err_if_canon_has_no_receipts() {
        let db = get_test_database();
        let canon_block = get_sample_eth_submission_material().remove_receipts();
        put_eth_canon_block_in_db(&db, &canon_block).unwrap();
        let num_receipts_before = get_eth_canon_block_from_db(&db).unwrap().receipts.len();
        if let Err(e) = remove_receipts_from_canon_block_and_save_in_db(&db) {
            panic!("Error maybe removing receipts from canon: {}", e);
        }
        let num_receipts_after = get_eth_canon_block_from_db(&db).unwrap().receipts.len();
        assert_eq!(num_receipts_before, 0);
        assert_eq!(num_receipts_after, 0);
    }
}
