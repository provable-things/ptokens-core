use crate::{
    types::Result,
    traits::DatabaseInterface,
    check_enclave_is_initialized::{
        check_enclave_is_initialized_and_return_eth_state,
    },
    eth::{
        eth_state::EthState,
        validate_block::validate_block_in_state,
        get_eth_output_json::get_eth_output_json,
        validate_receipts::validate_receipts_in_state,
        save_btc_utxos_to_db::maybe_save_btc_utxos_to_db,
        increment_btc_nonce::maybe_increment_btc_nonce_in_db,
        filter_receipts::filter_irrelevant_receipts_from_state,
        check_parent_exists::check_for_parent_of_block_in_state,
        update_latest_block_hash::maybe_update_latest_block_hash,
        filter_redeem_params::maybe_filter_redeem_params_in_state,
        remove_old_eth_tail_block::maybe_remove_old_eth_tail_block,
        update_eth_tail_block_hash::maybe_update_eth_tail_block_hash,
        create_btc_transactions::maybe_create_btc_txs_and_add_to_state,
        update_eth_canon_block_hash::maybe_update_eth_canon_block_hash,
        parse_redeem_params::maybe_parse_redeem_params_and_add_to_state,
        update_eth_linker_hash::maybe_update_eth_linker_hash_and_return_state,
        extract_utxos_from_btc_txs::maybe_extract_btc_utxo_from_btc_tx_in_state,
        eth_database_utils::{
            end_eth_db_transaction,
            start_eth_db_transaction,
        },
        parse_eth_block_and_receipts::{
            parse_eth_block_and_receipts_and_put_in_state,
        },
        add_block_and_receipts_to_database::{
            maybe_add_block_and_receipts_to_db_and_return_state,
        },
        remove_receipts_from_canon_block::{
            maybe_remove_receipts_from_canon_block_and_return_state,
        },
    }
};

pub fn submit_eth_block_to_enclave<D>(
    db: D,
    block_json_string: String
) -> Result<String>
    where D: DatabaseInterface
{
    info!("✔ Submitting ETH block to enclave...");
    parse_eth_block_and_receipts_and_put_in_state(
        block_json_string,
        EthState::init(db),
    )
        .and_then(check_enclave_is_initialized_and_return_eth_state)
        .and_then(start_eth_db_transaction)
        .and_then(validate_block_in_state)
        .and_then(check_for_parent_of_block_in_state)
        .and_then(validate_receipts_in_state)
        .and_then(filter_irrelevant_receipts_from_state)
        .and_then(maybe_add_block_and_receipts_to_db_and_return_state)
        .and_then(maybe_update_latest_block_hash)
        .and_then(maybe_update_eth_canon_block_hash)
        .and_then(maybe_update_eth_tail_block_hash)
        .and_then(maybe_update_eth_linker_hash_and_return_state)
        .and_then(maybe_parse_redeem_params_and_add_to_state)
        .and_then(maybe_filter_redeem_params_in_state)
        .and_then(maybe_create_btc_txs_and_add_to_state)
        .and_then(maybe_increment_btc_nonce_in_db)
        .and_then(maybe_extract_btc_utxo_from_btc_tx_in_state)
        .and_then(maybe_save_btc_utxos_to_db)
        .and_then(maybe_remove_old_eth_tail_block)
        .and_then(maybe_remove_receipts_from_canon_block_and_return_state)
        .and_then(end_eth_db_transaction)
        .and_then(get_eth_output_json)
}
