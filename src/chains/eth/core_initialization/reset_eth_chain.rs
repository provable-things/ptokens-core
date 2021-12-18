use ethereum_types::H256 as EthHash;
use serde_json::json;

use crate::{
    chains::eth::{
        core_initialization::eth_core_init_utils::{
            add_eth_block_to_db_and_return_state,
            put_canon_to_tip_length_in_db_and_return_state,
            put_eth_tail_block_hash_in_db_and_return_state,
            remove_receipts_from_block_in_state,
            set_eth_anchor_block_hash_and_return_state,
            set_eth_canon_block_hash_and_return_state,
            set_eth_latest_block_hash_and_return_state,
        },
        eth_constants::{
            ETH_ANCHOR_BLOCK_HASH_KEY,
            ETH_CANON_BLOCK_HASH_KEY,
            ETH_CANON_TO_TIP_LENGTH_KEY,
            ETH_LATEST_BLOCK_HASH_KEY,
            ETH_LINKER_HASH_KEY,
            ETH_TAIL_BLOCK_HASH_KEY,
            PTOKEN_GENESIS_HASH_KEY,
        },
        eth_database_transactions::{
            end_eth_db_transaction_and_return_state,
            start_eth_db_transaction_and_return_state,
        },
        eth_database_utils::{get_eth_latest_block_from_db, get_submission_material_from_db},
        eth_state::EthState,
        eth_submission_material::parse_eth_submission_material_and_put_in_state,
        validate_block_in_state::validate_block_in_state as validate_eth_block_in_state,
    },
    check_debug_mode::check_debug_mode,
    traits::DatabaseInterface,
    types::Result,
};

fn delete_all_eth_blocks<D: DatabaseInterface>(db: &D) -> Result<()> {
    fn recursively_delete_all_eth_blocks<D: DatabaseInterface>(
        db: &D,
        maybe_block_hash: Option<EthHash>,
    ) -> Result<()> {
        match maybe_block_hash {
            None => {
                info!("✔ Deleting all ETH blocks from db, starting with the latest block...");
                recursively_delete_all_eth_blocks(db, Some(get_eth_latest_block_from_db(db)?.get_parent_hash()?))
            },
            Some(ref hash) => match get_submission_material_from_db(db, hash) {
                Ok(submission_material) => {
                    recursively_delete_all_eth_blocks(db, Some(submission_material.get_parent_hash()?))
                },
                Err(_) => {
                    info!("✔ All ETH blocks deleted!");
                    Ok(())
                },
            },
        }
    }
    recursively_delete_all_eth_blocks(db, None)
}

fn delete_all_relevant_db_keys<D: DatabaseInterface>(db: &D) -> Result<()> {
    vec![
        *ETH_LINKER_HASH_KEY,
        *ETH_CANON_BLOCK_HASH_KEY,
        *ETH_TAIL_BLOCK_HASH_KEY,
        *PTOKEN_GENESIS_HASH_KEY,
        *ETH_ANCHOR_BLOCK_HASH_KEY,
        *ETH_LATEST_BLOCK_HASH_KEY,
        *ETH_CANON_BLOCK_HASH_KEY,
        *ETH_CANON_TO_TIP_LENGTH_KEY,
    ]
    .iter()
    .map(|key| db.delete(key.to_vec()))
    .collect::<Result<Vec<()>>>()
    .and(Ok(()))
}

fn delete_all_blocks_and_db_keys_and_return_state<D: DatabaseInterface>(state: EthState<D>) -> Result<EthState<D>> {
    delete_all_eth_blocks(&state.db)
        .and_then(|_| delete_all_relevant_db_keys(&state.db))
        .and(Ok(state))
}

/// Debug Reset ETH Chain
///
/// This function will reset the ETH chain held in the encrypted database. It first deletes the
/// entire chain, working backwards from the current latest block. It then deletes the relevant
/// database keys pertaining to the head, tail, anchor and canon block hashes of the chain.
/// Finally, it uses the passed in submission material to re-initialize these values from the
/// included block.
///
/// ### Beware: The block used to reset the chain must be trusted. Use this function only if you
/// know exactly what you are doing and why.
pub fn debug_reset_eth_chain<D: DatabaseInterface>(
    db: D,
    submission_material_json: &str,
    canon_to_tip_length: u64,
) -> Result<String> {
    info!("Debug resetting ETH chain...");
    check_debug_mode()
        .and_then(|_| parse_eth_submission_material_and_put_in_state(submission_material_json, EthState::init(db)))
        .and_then(validate_eth_block_in_state)
        .and_then(start_eth_db_transaction_and_return_state)
        .and_then(delete_all_blocks_and_db_keys_and_return_state)
        .and_then(remove_receipts_from_block_in_state)
        .and_then(add_eth_block_to_db_and_return_state)
        .and_then(|state| put_canon_to_tip_length_in_db_and_return_state(canon_to_tip_length, state))
        .and_then(set_eth_anchor_block_hash_and_return_state)
        .and_then(set_eth_latest_block_hash_and_return_state)
        .and_then(set_eth_canon_block_hash_and_return_state)
        .and_then(put_eth_tail_block_hash_in_db_and_return_state)
        .and_then(end_eth_db_transaction_and_return_state)
        .map(|_| json!({"eth-chain-reset-success":true}).to_string())
}
