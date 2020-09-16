use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eth::eth::{
        eth_state::EthState,
        eth_types::EthBlockAndReceipts,
        eth_database_utils::{
            put_eth_canon_block_in_db,
            get_eth_canon_block_from_db,
        },
    },
};

pub fn remove_receipts_from_block(
    eth_block_and_receipts: EthBlockAndReceipts,
) -> EthBlockAndReceipts {
    EthBlockAndReceipts {
        receipts: Vec::new(),
        block: eth_block_and_receipts.block,
    }
}

pub fn remove_receipts_from_canon_block_and_save_in_db<D>(db: &D) -> Result<()>
    where D: DatabaseInterface
{
    get_eth_canon_block_from_db(db)
        .and_then(|canon_block|
            put_eth_canon_block_in_db(
                db,
                &remove_receipts_from_block(canon_block)
            )
        )

}

pub fn maybe_remove_receipts_from_canon_block_and_return_state<D>(
    state: EthState<D>
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Removing receipts from canon block...");
    remove_receipts_from_canon_block_and_save_in_db(&state.db)
        .map(|_| state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        test_utils::get_test_database,
        btc_on_eth::eth::eth_test_utils::get_sample_eth_block_and_receipts,
    };

    #[test]
    fn should_remove_receipts_from_block_and_receipts() {
        let block_and_receipts = get_sample_eth_block_and_receipts();
        let num_receipts_before = block_and_receipts.receipts.len();
        assert!(num_receipts_before > 0);
        let result_block_and_receipts = remove_receipts_from_block(
            block_and_receipts
        );
        let num_receipts_after = result_block_and_receipts.receipts.len();
        assert_eq!(num_receipts_after, 0);
    }

    #[test]
    fn should_remove_receipts_from_canon_block() {
        let db = get_test_database();
        let canon_block = get_sample_eth_block_and_receipts();
        put_eth_canon_block_in_db(&db, &canon_block)
            .unwrap();
        let num_receipts_before = get_eth_canon_block_from_db(&db)
            .unwrap()
            .receipts
            .len();
        if let Err(e) = remove_receipts_from_canon_block_and_save_in_db(&db) {
            panic!("Error maybe removing receipts from canon: {}", e);
        }
        let num_receipts_after = get_eth_canon_block_from_db(&db)
            .unwrap()
            .receipts
            .len();
        assert!(num_receipts_before > 0);
        assert_eq!(num_receipts_after, 0);
    }

    #[test]
    fn should_not_err_if_canon_has_no_receipts() {
        let db = get_test_database();
        let canon_block = remove_receipts_from_block(
            get_sample_eth_block_and_receipts()
        );
        put_eth_canon_block_in_db(&db, &canon_block)
            .unwrap();
        let num_receipts_before = get_eth_canon_block_from_db(&db)
            .unwrap()
            .receipts
            .len();
        if let Err(e) = remove_receipts_from_canon_block_and_save_in_db(&db) {
            panic!("Error maybe removing receipts from canon: {}", e);
        }
        let num_receipts_after = get_eth_canon_block_from_db(&db)
            .unwrap()
            .receipts
            .len();
        assert_eq!(num_receipts_before, 0);
        assert_eq!(num_receipts_after, 0);
    }
}
