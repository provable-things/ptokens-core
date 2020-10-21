use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eth::eth::{
        parse_redeem_infos::maybe_parse_redeem_infos_and_add_to_state,
        filter_redeem_infos_in_state::maybe_filter_redeem_infos_in_state,
    },
    chains::eth::{
        eth_state::EthState,
        validate_block_in_state::validate_block_in_state,
        validate_receipts_in_state::validate_receipts_in_state,
        check_parent_exists::check_for_parent_of_block_in_state,
        update_eth_linker_hash::maybe_update_eth_linker_hash_and_return_state,
        eth_submission_material::parse_eth_submission_material_and_put_in_state,
        update_latest_block_hash::maybe_update_latest_block_hash_and_return_state,
        remove_old_eth_tail_block::maybe_remove_old_eth_tail_block_and_return_state,
        update_eth_tail_block_hash::maybe_update_eth_tail_block_hash_and_return_state,
        update_eth_canon_block_hash::maybe_update_eth_canon_block_hash_and_return_state,
        filter_receipts_in_state::filter_receipts_for_btc_on_eth_redeem_events_in_state,
        add_block_and_receipts_to_db::maybe_add_block_and_receipts_to_db_and_return_state,
        remove_receipts_from_canon_block::maybe_remove_receipts_from_canon_block_and_return_state,
        eth_database_transactions::{
            end_eth_db_transaction_and_return_state,
            start_eth_db_transaction_and_return_state,
        },
    },
    btc_on_eth::{
        check_core_is_initialized::check_core_is_initialized_and_return_eth_state,
        eth::{
            get_eth_output_json::get_eth_output_json,
            create_btc_transactions::maybe_create_btc_txs_and_add_to_state,
            save_btc_utxos_to_db::maybe_save_btc_utxos_to_db_and_return_state,
            increment_btc_nonce::maybe_increment_btc_nonce_in_db_and_return_state,
            extract_utxos_from_btc_txs::maybe_extract_btc_utxo_from_btc_tx_in_state,
        },
    },
};

/// # Submit ETH Block to Enclave
///
/// The main submission pipeline. Submitting an ETH block to the enclave will - if that block is
/// valid & subsequent to the enclave's current latest block - advanced the piece of the ETH
/// blockchain held by the enclave in it's encrypted database. Should the submitted block
/// contain a redeem event emitted by the smart-contract the enclave is watching, a BTC
/// transaction will be signed & returned to the caller.
///
pub fn submit_eth_block_to_enclave<D: DatabaseInterface>(db: D, block_json_string: &str) -> Result<String> {
    info!("✔ Submitting ETH block to enclave...");
    parse_eth_submission_material_and_put_in_state(block_json_string, EthState::init(db))
        .and_then(check_core_is_initialized_and_return_eth_state)
        .and_then(start_eth_db_transaction_and_return_state)
        .and_then(validate_block_in_state)
        .and_then(check_for_parent_of_block_in_state)
        .and_then(validate_receipts_in_state)
        .and_then(filter_receipts_for_btc_on_eth_redeem_events_in_state)
        .and_then(maybe_add_block_and_receipts_to_db_and_return_state)
        .and_then(maybe_update_latest_block_hash_and_return_state)
        .and_then(maybe_update_eth_canon_block_hash_and_return_state)
        .and_then(maybe_update_eth_tail_block_hash_and_return_state)
        .and_then(maybe_update_eth_linker_hash_and_return_state)
        .and_then(maybe_parse_redeem_infos_and_add_to_state)
        .and_then(maybe_filter_redeem_infos_in_state)
        .and_then(maybe_create_btc_txs_and_add_to_state)
        .and_then(maybe_increment_btc_nonce_in_db_and_return_state)
        .and_then(maybe_extract_btc_utxo_from_btc_tx_in_state)
        .and_then(maybe_save_btc_utxos_to_db_and_return_state)
        .and_then(maybe_remove_old_eth_tail_block_and_return_state)
        .and_then(maybe_remove_receipts_from_canon_block_and_return_state)
        .and_then(end_eth_db_transaction_and_return_state)
        .and_then(get_eth_output_json)
}
