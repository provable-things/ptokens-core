use crate::{
    chains::{
        eth::{
            eth_database_transactions::{
                end_eth_db_transaction_and_return_state,
                start_eth_db_transaction_and_return_state,
            },
            eth_database_utils::{
                get_any_sender_nonce_from_db as get_eth_any_sender_nonce_from_db,
                get_erc20_on_evm_smart_contract_address_from_db,
                get_eth_account_nonce_from_db,
                get_eth_chain_id_from_db,
                get_latest_eth_block_number,
            },
            eth_state::EthState,
            eth_submission_material::parse_eth_submission_material_and_put_in_state,
            increment_evm_account_nonce::maybe_increment_evm_account_nonce_and_return_eth_state,
            validate_block_in_state::validate_block_in_state,
            validate_receipts_in_state::validate_receipts_in_state,
        },
        evm::{
            eth_database_transactions::{
                end_eth_db_transaction_and_return_state as end_evm_db_tx_and_return_state,
                start_eth_db_transaction_and_return_state as start_evm_db_tx_and_return_state,
            },
            eth_database_utils::{
                get_any_sender_nonce_from_db as get_evm_any_sender_nonce_from_db,
                get_eth_account_nonce_from_db as get_evm_account_nonce_from_db,
                get_eth_chain_id_from_db as get_evm_chain_id_from_db,
                get_latest_eth_block_number as get_latest_evm_block_number,
            },
            eth_state::EthState as EvmState,
            eth_submission_material::parse_eth_submission_material_and_put_in_state as parse_evm_submission_material_and_put_in_state,
            increment_eth_account_nonce_and_return_evm_state::maybe_increment_eth_account_nonce_and_return_evm_state,
            validate_block_in_state::validate_block_in_state as validate_evm_block_in_state,
            validate_receipts_in_state::validate_receipts_in_state as validate_evm_receipts_in_state,
        },
    },
    check_debug_mode::check_debug_mode,
    dictionaries::eth_evm::{
        get_eth_evm_token_dictionary_from_db_and_add_to_eth_state,
        get_eth_evm_token_dictionary_from_db_and_add_to_evm_state,
        EthEvmTokenDictionary,
    },
    erc20_on_evm::{
        check_core_is_initialized::{
            check_core_is_initialized_and_return_eth_state,
            check_core_is_initialized_and_return_evm_state,
        },
        eth::{
            account_for_fees::{
                account_for_fees_in_evm_tx_infos_in_state,
                update_accrued_fees_in_dictionary_and_return_state as update_accrued_fees_in_dictionary_and_return_eth_state,
            },
            evm_tx_info::{
                filter_out_zero_value_evm_tx_infos_from_state,
                filter_submission_material_for_peg_in_events_in_state,
                maybe_divert_txs_to_safe_address_if_destination_is_evm_token_address,
                maybe_sign_evm_txs_and_add_to_eth_state,
                EthOnEvmEvmTxInfos,
            },
            get_eth_output_json::{get_evm_signed_tx_info_from_evm_txs, EthOutput},
        },
        evm::{
            account_for_fees::{
                account_for_fees_in_eth_tx_infos_in_state,
                update_accrued_fees_in_dictionary_and_return_state as update_accrued_fees_in_dictionary_and_return_evm_state,
            },
            eth_tx_info::{
                filter_out_zero_value_eth_tx_infos_from_state,
                filter_submission_material_for_redeem_events_in_state,
                maybe_divert_txs_to_safe_address_if_destination_is_eth_token_address,
                maybe_sign_eth_txs_and_add_to_evm_state,
                EthOnEvmEthTxInfos,
            },
            get_evm_output_json::{get_eth_signed_tx_info_from_evm_txs, EvmOutput},
        },
    },
    traits::DatabaseInterface,
    types::Result,
    utils::prepend_debug_output_marker_to_string,
};

fn debug_reprocess_evm_block_maybe_accruing_fees<D: DatabaseInterface>(
    db: D,
    evm_block_json: &str,
    accrue_fees: bool,
) -> Result<String> {
    info!("✔ Debug reprocessing EVM block...");
    check_debug_mode()
        .and_then(|_| parse_evm_submission_material_and_put_in_state(evm_block_json, EvmState::init(db)))
        .and_then(check_core_is_initialized_and_return_evm_state)
        .and_then(start_evm_db_tx_and_return_state)
        .and_then(validate_evm_block_in_state)
        .and_then(validate_evm_receipts_in_state)
        .and_then(get_eth_evm_token_dictionary_from_db_and_add_to_evm_state)
        .and_then(filter_submission_material_for_redeem_events_in_state)
        .and_then(|state| {
            state
                .get_eth_submission_material()
                .and_then(|material| {
                    EthOnEvmEthTxInfos::from_submission_material(
                        material,
                        &EthEvmTokenDictionary::get_from_db(&state.db)?,
                        &get_evm_chain_id_from_db(&state.db)?,
                    )
                })
                .and_then(|params| state.add_erc20_on_evm_eth_tx_infos(params))
        })
        .and_then(filter_out_zero_value_eth_tx_infos_from_state)
        .and_then(account_for_fees_in_eth_tx_infos_in_state)
        .and_then(|state| {
            if accrue_fees {
                update_accrued_fees_in_dictionary_and_return_evm_state(state)
            } else {
                info!("✘ Not accruing fees during EVM block reprocessing...");
                Ok(state)
            }
        })
        .and_then(maybe_divert_txs_to_safe_address_if_destination_is_eth_token_address)
        .and_then(maybe_sign_eth_txs_and_add_to_evm_state)
        .and_then(maybe_increment_eth_account_nonce_and_return_evm_state)
        .and_then(end_evm_db_tx_and_return_state)
        .and_then(|state| {
            info!("✔ Getting EVM output json...");
            let output = serde_json::to_string(&EvmOutput {
                evm_latest_block_number: get_latest_evm_block_number(&state.db)?,
                eth_signed_transactions: if state.erc20_on_evm_eth_signed_txs.is_empty() {
                    vec![]
                } else {
                    let use_any_sender_tx = false;
                    get_eth_signed_tx_info_from_evm_txs(
                        &state.erc20_on_evm_eth_signed_txs,
                        &state.erc20_on_evm_eth_tx_infos,
                        get_eth_account_nonce_from_db(&state.db)?,
                        use_any_sender_tx,
                        get_eth_any_sender_nonce_from_db(&state.db)?,
                        get_latest_eth_block_number(&state.db)?,
                    )?
                },
            })?;
            info!("✔ Reprocess EVM block output: {}", output);
            Ok(output)
        })
        .map(prepend_debug_output_marker_to_string)
}

fn debug_reprocess_eth_block_maybe_accruing_fees<D: DatabaseInterface>(
    db: D,
    eth_block_json: &str,
    accrue_fees: bool,
) -> Result<String> {
    info!("✔ Debug reprocessing ETH block...");
    check_debug_mode()
        .and_then(|_| parse_eth_submission_material_and_put_in_state(eth_block_json, EthState::init(db)))
        .and_then(check_core_is_initialized_and_return_eth_state)
        .and_then(start_eth_db_transaction_and_return_state)
        .and_then(validate_block_in_state)
        .and_then(validate_receipts_in_state)
        .and_then(get_eth_evm_token_dictionary_from_db_and_add_to_eth_state)
        .and_then(filter_submission_material_for_peg_in_events_in_state)
        .and_then(|state| {
            state
                .get_eth_submission_material()
                .and_then(|material| {
                    EthOnEvmEvmTxInfos::from_submission_material(
                        material,
                        &get_erc20_on_evm_smart_contract_address_from_db(&state.db)?,
                        &EthEvmTokenDictionary::get_from_db(&state.db)?,
                        &get_eth_chain_id_from_db(&state.db)?,
                    )
                })
                .and_then(|params| state.add_erc20_on_evm_evm_tx_infos(params))
        })
        .and_then(filter_out_zero_value_evm_tx_infos_from_state)
        .and_then(account_for_fees_in_evm_tx_infos_in_state)
        .and_then(|state| {
            if accrue_fees {
                update_accrued_fees_in_dictionary_and_return_eth_state(state)
            } else {
                info!("✘ Not accruing fees during ETH block reprocessing...");
                Ok(state)
            }
        })
        .and_then(maybe_divert_txs_to_safe_address_if_destination_is_evm_token_address)
        .and_then(maybe_sign_evm_txs_and_add_to_eth_state)
        .and_then(maybe_increment_evm_account_nonce_and_return_eth_state)
        .and_then(end_eth_db_transaction_and_return_state)
        .and_then(|state| {
            info!("✔ Getting ETH output json...");
            let output = serde_json::to_string(&EthOutput {
                eth_latest_block_number: get_latest_eth_block_number(&state.db)?,
                evm_signed_transactions: if state.erc20_on_evm_evm_signed_txs.is_empty() {
                    vec![]
                } else {
                    let use_any_sender_tx = false;
                    get_evm_signed_tx_info_from_evm_txs(
                        &state.erc20_on_evm_evm_signed_txs,
                        &state.erc20_on_evm_evm_tx_infos,
                        get_evm_account_nonce_from_db(&state.db)?,
                        use_any_sender_tx,
                        get_evm_any_sender_nonce_from_db(&state.db)?,
                        get_latest_evm_block_number(&state.db)?,
                        &EthEvmTokenDictionary::get_from_db(&state.db)?,
                    )?
                },
            })?;
            info!("✔ Reprocess ETH block output: {}", output);
            Ok(output)
        })
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Reprocess EVM Block
///
/// This function will take a passed in EVM block submission material and run it through the
/// submission pipeline, signing any signatures for pegouts it may find in the block
///
/// ### NOTES:
///
///  - This function will increment the core's EVM nonce, meaning the outputted reports will have a
/// gap in their report IDs!
///
///  - This version of the EVM block reprocessor __will__ deduct fees from any transaction info(s) it
///  parses from the submitted block, but it will __not__ accrue those fees on to the total in the
///  dictionary. This is to avoid accounting for fees twice.
///
/// ### BEWARE:
/// If you don't broadcast the transaction outputted from this function, ALL future EVM transactions will
/// fail due to the core having an incorret nonce!
pub fn debug_reprocess_evm_block<D: DatabaseInterface>(db: D, evm_block_json: &str) -> Result<String> {
    debug_reprocess_evm_block_maybe_accruing_fees(db, evm_block_json, false)
}

/// # Debug Reprocess EVM Block With Fee Accrual
///
/// This function will take a passed in EVM block submission material and run it through the
/// submission pipeline, signing any signatures for pegouts it may find in the block
///
/// ### NOTES:
///
///  - This function will increment the core's EVM nonce, meaning the outputted reports will have a
/// gap in their report IDs!
///
///  - This version of the EVM block reprocessor __will__ deduct fees from any transaction info(s) it
///  parses from the submitted block, and __will__ accrue those fees on to the total in the
///  dictionary. Only use this is you know what you're doing and why, and make sure you're avoiding
///  accruing the fees twice if the block has already been processed through the non-debug EVM
///  block submission pipeline.
///
/// ### BEWARE:
/// If you don't broadcast the transaction outputted from this function, ALL future EVM transactions will
/// fail due to the core having an incorret nonce!
pub fn debug_reprocess_evm_block_with_fee_accrual<D: DatabaseInterface>(db: D, evm_block_json: &str) -> Result<String> {
    debug_reprocess_evm_block_maybe_accruing_fees(db, evm_block_json, true)
}

/// # Debug Reprocess ETH Block
///
/// This function will take a passed in ETH block submission material and run it through the
/// submission pipeline, signing any signatures for pegouts it may find in the block
///
/// ### NOTES:
///  - This function will increment the core's ETH nonce, meaning the outputted reports will have a
/// gap in their report IDs!
///
///  - This version of the ETH block reprocessor __will__ deduct fees from any transaction info(s) it
///  parses from the submitted block, but it will __not__ accrue those fees on to the total in the
///  dictionary. This is to avoid accounting for fees twice.
///
/// ### BEWARE:
/// If you don't broadcast the transaction outputted from this function, ALL future ETH transactions will
/// fail due to the core having an incorret nonce!
pub fn debug_reprocess_eth_block<D: DatabaseInterface>(db: D, eth_block_json: &str) -> Result<String> {
    debug_reprocess_eth_block_maybe_accruing_fees(db, eth_block_json, false)
}

/// # Debug Reprocess ETH Block With Fee Accrual
///
/// This function will take a passed in ETH block submission material and run it through the
/// submission pipeline, signing any signatures for pegouts it may find in the block
///
/// ### NOTES:
///
///  - This function will increment the core's ETH nonce, meaning the outputted reports will have a
/// gap in their report IDs!
///
///  - This version of the ETH block reprocessor __will__ deduct fees from any transaction info(s) it
///  parses from the submitted block, and __will__ accrue those fees on to the total in the
///  dictionary. Only use this is you know what you're doing and why, and make sure you're avoiding
///  accruing the fees twice if the block has already been processed through the non-debug ETH
///  block submission pipeline.
///
/// ### BEWARE:
/// If you don't broadcast the transaction outputted from this function, ALL future ETH transactions will
/// fail due to the core having an incorret nonce!
pub fn debug_reprocess_eth_block_with_fee_accrual<D: DatabaseInterface>(db: D, evm_block_json: &str) -> Result<String> {
    debug_reprocess_eth_block_maybe_accruing_fees(db, evm_block_json, true)
}
