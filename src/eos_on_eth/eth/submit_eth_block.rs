use crate::{
    chains::eth::{
        add_block_and_receipts_to_db::maybe_add_block_and_receipts_to_db_and_return_state,
        check_parent_exists::check_for_parent_of_block_in_state,
        eth_database_transactions::{
            end_eth_db_transaction_and_return_state,
            start_eth_db_transaction_and_return_state,
        },
        eth_state::EthState,
        eth_submission_material::parse_eth_submission_material_and_put_in_state,
        increment_eos_account_nonce::maybe_increment_eos_account_nonce_and_return_state,
        remove_old_eth_tail_block::maybe_remove_old_eth_tail_block_and_return_state,
        remove_receipts_from_canon_block::maybe_remove_receipts_from_canon_block_and_return_state,
        update_eth_canon_block_hash::maybe_update_eth_canon_block_hash_and_return_state,
        update_eth_linker_hash::maybe_update_eth_linker_hash_and_return_state,
        update_eth_tail_block_hash::maybe_update_eth_tail_block_hash_and_return_state,
        update_latest_block_hash::maybe_update_latest_block_hash_and_return_state,
        validate_block_in_state::validate_block_in_state,
        validate_receipts_in_state::validate_receipts_in_state,
    },
    dictionaries::eos_eth::get_eos_eth_token_dictionary_from_db_and_add_to_eth_state,
    eos_on_eth::{
        check_core_is_initialized::check_core_is_initialized_and_return_eth_state,
        eth::{
            eth_tx_info::{
                maybe_filter_out_eth_tx_info_with_value_too_low_in_state,
                maybe_parse_eth_tx_info_from_canon_block_and_add_to_state,
                maybe_sign_eos_txs_and_add_to_eth_state,
            },
            filter_receipts_in_state::filter_receipts_for_eos_on_eth_eth_tx_info_in_state,
            get_output_json::get_output_json,
        },
    },
    traits::DatabaseInterface,
    types::Result,
};

/// # Submit ETH Block to Core
///
/// The main submission pipeline. Submitting an ETH block to the enclave will - if that block is
/// valid & subsequent to the enclave's current latest block - advanced the piece of the ETH
/// blockchain held by the enclave in it's encrypted database. Should the submitted block
/// contain a redeem event emitted by the smart-contract the enclave is watching, an EOS
/// transaction will be signed & returned to the caller.
pub fn submit_eth_block_to_core<D: DatabaseInterface>(db: D, block_json_string: &str) -> Result<String> {
    info!("✔ Submitting ETH block to enclave...");
    parse_eth_submission_material_and_put_in_state(block_json_string, EthState::init(db))
        .and_then(check_core_is_initialized_and_return_eth_state)
        .and_then(start_eth_db_transaction_and_return_state)
        .and_then(get_eos_eth_token_dictionary_from_db_and_add_to_eth_state)
        .and_then(validate_block_in_state)
        .and_then(check_for_parent_of_block_in_state)
        .and_then(validate_receipts_in_state)
        .and_then(filter_receipts_for_eos_on_eth_eth_tx_info_in_state)
        .and_then(maybe_add_block_and_receipts_to_db_and_return_state)
        .and_then(maybe_update_latest_block_hash_and_return_state)
        .and_then(maybe_update_eth_canon_block_hash_and_return_state)
        .and_then(maybe_update_eth_tail_block_hash_and_return_state)
        .and_then(maybe_update_eth_linker_hash_and_return_state)
        .and_then(maybe_parse_eth_tx_info_from_canon_block_and_add_to_state)
        .and_then(maybe_filter_out_eth_tx_info_with_value_too_low_in_state)
        .and_then(maybe_sign_eos_txs_and_add_to_eth_state)
        .and_then(maybe_increment_eos_account_nonce_and_return_state)
        .and_then(maybe_remove_old_eth_tail_block_and_return_state)
        .and_then(maybe_remove_receipts_from_canon_block_and_return_state)
        .and_then(end_eth_db_transaction_and_return_state)
        .and_then(get_output_json)
}
