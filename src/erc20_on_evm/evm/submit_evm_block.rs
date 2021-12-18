use crate::{
    chains::evm::{
        add_block_and_receipts_to_db::maybe_add_block_and_receipts_to_db_and_return_state,
        check_parent_exists::check_for_parent_of_block_in_state,
        eth_database_transactions::{
            end_eth_db_transaction_and_return_state,
            start_eth_db_transaction_and_return_state,
        },
        eth_state::EthState,
        eth_submission_material::parse_eth_submission_material_and_put_in_state,
        increment_eth_account_nonce_and_return_evm_state::maybe_increment_eth_account_nonce_and_return_evm_state,
        remove_old_eth_tail_block::maybe_remove_old_eth_tail_block_and_return_state,
        remove_receipts_from_canon_block::maybe_remove_receipts_from_canon_block_and_return_state,
        update_eth_canon_block_hash::maybe_update_eth_canon_block_hash_and_return_state,
        update_eth_linker_hash::maybe_update_eth_linker_hash_and_return_state,
        update_eth_tail_block_hash::maybe_update_eth_tail_block_hash_and_return_state,
        update_latest_block_hash::maybe_update_latest_block_hash_and_return_state,
        validate_block_in_state::validate_block_in_state,
        validate_receipts_in_state::validate_receipts_in_state,
    },
    dictionaries::eth_evm::get_eth_evm_token_dictionary_from_db_and_add_to_evm_state,
    erc20_on_evm::{
        check_core_is_initialized::check_core_is_initialized_and_return_evm_state,
        evm::{
            account_for_fees::maybe_account_for_fees,
            eth_tx_info::{
                filter_out_zero_value_eth_tx_infos_from_state,
                filter_submission_material_for_redeem_events_in_state,
                maybe_divert_txs_to_safe_address_if_destination_is_eth_token_address,
                maybe_parse_tx_info_from_canon_block_and_add_to_state,
                maybe_sign_eth_txs_and_add_to_evm_state,
            },
            get_evm_output_json::get_evm_output_json,
        },
    },
    traits::DatabaseInterface,
    types::Result,
};

/// # Submit EVM Block to Core
///
/// The main submission pipeline. Submitting an ETH block to the enclave will - if that block is
/// valid & subsequent to the enclave's current latest block - advanced the piece of the ETH
/// blockchain held by the enclave in it's encrypted database. Should the submitted block
/// contain a redeem event emitted by the smart-contract the enclave is watching, an EOS
/// transaction will be signed & returned to the caller.
pub fn submit_evm_block_to_core<D: DatabaseInterface>(db: D, block_json_string: &str) -> Result<String> {
    info!("✔ Submitting EVM block to core...");
    parse_eth_submission_material_and_put_in_state(block_json_string, EthState::init(db))
        .and_then(check_core_is_initialized_and_return_evm_state)
        .and_then(start_eth_db_transaction_and_return_state)
        .and_then(validate_block_in_state)
        .and_then(get_eth_evm_token_dictionary_from_db_and_add_to_evm_state)
        .and_then(check_for_parent_of_block_in_state)
        .and_then(validate_receipts_in_state)
        .and_then(filter_submission_material_for_redeem_events_in_state)
        .and_then(maybe_add_block_and_receipts_to_db_and_return_state)
        .and_then(maybe_update_latest_block_hash_and_return_state)
        .and_then(maybe_update_eth_canon_block_hash_and_return_state)
        .and_then(maybe_update_eth_tail_block_hash_and_return_state)
        .and_then(maybe_update_eth_linker_hash_and_return_state)
        .and_then(maybe_parse_tx_info_from_canon_block_and_add_to_state)
        .and_then(filter_out_zero_value_eth_tx_infos_from_state)
        .and_then(maybe_account_for_fees)
        .and_then(maybe_divert_txs_to_safe_address_if_destination_is_eth_token_address)
        .and_then(maybe_sign_eth_txs_and_add_to_evm_state)
        .and_then(maybe_increment_eth_account_nonce_and_return_evm_state)
        .and_then(maybe_remove_old_eth_tail_block_and_return_state)
        .and_then(maybe_remove_receipts_from_canon_block_and_return_state)
        .and_then(end_eth_db_transaction_and_return_state)
        .and_then(get_evm_output_json)
}
