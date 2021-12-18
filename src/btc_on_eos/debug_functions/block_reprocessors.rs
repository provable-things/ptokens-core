pub use serde_json::json;

use crate::{
    btc_on_eos::{
        btc::{
            account_for_fees::maybe_account_for_fees as maybe_account_for_peg_in_fees,
            get_btc_output_json::{get_btc_output_as_string, get_eos_signed_tx_info_from_eth_txs, BtcOutput},
            minting_params::parse_minting_params_from_p2sh_deposits_and_add_to_state,
            sign_transactions::get_signed_eos_ptoken_issue_txs,
        },
        check_core_is_initialized::{
            check_core_is_initialized_and_return_btc_state,
            check_core_is_initialized_and_return_eos_state,
        },
        eos::{
            account_for_fees::maybe_account_for_fees as maybe_account_for_peg_out_fees,
            extract_utxos_from_btc_txs::maybe_extract_btc_utxo_from_btc_tx_in_state,
            get_eos_output::get_eos_output,
            redeem_info::{
                maybe_filter_value_too_low_redeem_infos_in_state,
                maybe_parse_redeem_infos_and_put_in_state,
            },
            save_btc_utxos_to_db::maybe_save_btc_utxos_to_db,
            sign_transactions::maybe_sign_txs_and_add_to_state,
        },
    },
    chains::{
        btc::{
            btc_database_utils::{get_btc_latest_block_from_db, start_btc_db_transaction},
            btc_state::BtcState,
            btc_submission_material::parse_submission_material_and_put_in_state,
            filter_p2sh_deposit_txs::filter_p2sh_deposit_txs_and_add_to_state,
            get_btc_block_in_db_format::create_btc_block_in_db_format_and_put_in_state,
            get_deposit_info_hash_map::get_deposit_info_hash_map_and_put_in_state,
            increment_btc_account_nonce::maybe_increment_btc_signature_nonce_and_return_eos_state,
            validate_btc_block_header::validate_btc_block_header_in_state,
            validate_btc_difficulty::validate_difficulty_of_btc_block_in_state,
            validate_btc_merkle_root::validate_btc_merkle_root,
            validate_btc_proof_of_work::validate_proof_of_work_of_btc_block_in_state,
        },
        eos::{
            eos_constants::REDEEM_ACTION_NAME,
            eos_crypto::eos_private_key::EosPrivateKey,
            eos_database_transactions::{
                end_eos_db_transaction_and_return_state,
                start_eos_db_transaction_and_return_state,
            },
            eos_database_utils::{
                get_eos_account_name_string_from_db,
                get_eos_account_nonce_from_db,
                get_eos_chain_id_from_db,
            },
            eos_global_sequences::{
                get_processed_global_sequences_and_add_to_state,
                maybe_add_global_sequences_to_processed_list_and_return_state,
            },
            eos_state::EosState,
            eos_submission_material::parse_submission_material_and_add_to_state,
            filter_action_proofs::{
                maybe_filter_duplicate_proofs_from_state,
                maybe_filter_out_action_proof_receipt_mismatches_and_return_state,
                maybe_filter_out_invalid_action_receipt_digests,
                maybe_filter_out_proofs_for_wrong_eos_account_name,
                maybe_filter_out_proofs_with_invalid_merkle_proofs,
                maybe_filter_out_proofs_with_wrong_action_mroot,
                maybe_filter_proofs_for_action_name,
            },
            get_enabled_protocol_features::get_enabled_protocol_features_and_add_to_state,
        },
    },
    check_debug_mode::check_debug_mode,
    fees::fee_database_utils::FeeDatabaseUtils,
    traits::DatabaseInterface,
    types::Result,
    utils::prepend_debug_output_marker_to_string,
};

fn debug_reprocess_eos_block_maybe_accruing_fees<D: DatabaseInterface>(
    db: D,
    block_json: &str,
    accrue_fees: bool,
) -> Result<String> {
    info!(
        "✔ Debug reprocessing EOS block {} fees accruing!",
        if accrue_fees { "WITH" } else { "WITHOUT" }
    );
    check_debug_mode()
        .and_then(|_| parse_submission_material_and_add_to_state(block_json, EosState::init(db)))
        .and_then(check_core_is_initialized_and_return_eos_state)
        .and_then(get_enabled_protocol_features_and_add_to_state)
        .and_then(get_processed_global_sequences_and_add_to_state)
        .and_then(start_eos_db_transaction_and_return_state)
        .and_then(maybe_filter_duplicate_proofs_from_state)
        .and_then(maybe_filter_out_proofs_for_wrong_eos_account_name)
        .and_then(maybe_filter_out_action_proof_receipt_mismatches_and_return_state)
        .and_then(maybe_filter_out_invalid_action_receipt_digests)
        .and_then(maybe_filter_out_proofs_with_invalid_merkle_proofs)
        .and_then(maybe_filter_out_proofs_with_wrong_action_mroot)
        .and_then(|state| maybe_filter_proofs_for_action_name(state, REDEEM_ACTION_NAME))
        .and_then(maybe_parse_redeem_infos_and_put_in_state)
        .and_then(maybe_filter_value_too_low_redeem_infos_in_state)
        .and_then(maybe_add_global_sequences_to_processed_list_and_return_state)
        .and_then(|state| {
            if accrue_fees {
                maybe_account_for_peg_out_fees(state)
            } else {
                info!("✔ Accounting for fees in signing params but NOT accruing them!");
                let basis_points =
                    FeeDatabaseUtils::new_for_btc_on_eos().get_peg_out_basis_points_from_db(&state.db)?;
                let updated_redeem_infos = state.btc_on_eos_redeem_infos.subtract_fees(basis_points)?;
                state.replace_btc_on_eos_redeem_infos(updated_redeem_infos)
            }
        })
        .and_then(maybe_sign_txs_and_add_to_state)
        .and_then(maybe_increment_btc_signature_nonce_and_return_eos_state)
        .and_then(maybe_extract_btc_utxo_from_btc_tx_in_state)
        .and_then(maybe_save_btc_utxos_to_db)
        .and_then(end_eos_db_transaction_and_return_state)
        .and_then(get_eos_output)
        .map(prepend_debug_output_marker_to_string)
}

fn debug_reprocess_btc_block_for_stale_eos_tx_maybe_accruing_fees<D: DatabaseInterface>(
    db: D,
    block_json_string: &str,
    accrue_fees: bool,
) -> Result<String> {
    info!(
        "✔ Reprocessing BTC block to core {} fees accruing",
        if accrue_fees { "WITH" } else { "WITHOUT" }
    );
    check_debug_mode()
        .and_then(|_| parse_submission_material_and_put_in_state(block_json_string, BtcState::init(db)))
        .and_then(check_core_is_initialized_and_return_btc_state)
        .and_then(start_btc_db_transaction)
        .and_then(validate_btc_block_header_in_state)
        .and_then(validate_difficulty_of_btc_block_in_state)
        .and_then(validate_proof_of_work_of_btc_block_in_state)
        .and_then(validate_btc_merkle_root)
        .and_then(get_deposit_info_hash_map_and_put_in_state)
        .and_then(filter_p2sh_deposit_txs_and_add_to_state)
        .and_then(parse_minting_params_from_p2sh_deposits_and_add_to_state)
        .and_then(create_btc_block_in_db_format_and_put_in_state)
        .and_then(|state| {
            if accrue_fees {
                maybe_account_for_peg_in_fees(state)
            } else {
                info!("✔ Accounting for fees in signing params but NOT accruing them!");
                let basis_points = FeeDatabaseUtils::new_for_btc_on_eos().get_peg_in_basis_points_from_db(&state.db)?;
                let updated_minting_params = state.btc_on_eos_minting_params.subtract_fees(basis_points)?;
                state.replace_btc_on_eos_minting_params(updated_minting_params)
            }
        })
        .and_then(|state| {
            info!("✔ Maybe signing reprocessed minting txs...");
            get_signed_eos_ptoken_issue_txs(
                state.get_eos_ref_block_num()?,
                state.get_eos_ref_block_prefix()?,
                &get_eos_chain_id_from_db(&state.db)?,
                &EosPrivateKey::get_from_db(&state.db)?,
                &get_eos_account_name_string_from_db(&state.db)?,
                &state.btc_on_eos_minting_params,
            )
            .and_then(|signed_txs| {
                info!("✔ EOS Signed Txs: {:?}", signed_txs);
                state.add_signed_txs(signed_txs)
            })
        })
        .and_then(|state| {
            info!("✔ Getting BTC output json and putting in state...");
            Ok(serde_json::to_string(&BtcOutput {
                btc_latest_block_number: get_btc_latest_block_from_db(&state.db)?.height,
                eos_signed_transactions: match &state.signed_txs.len() {
                    0 => vec![],
                    _ => get_eos_signed_tx_info_from_eth_txs(
                        &state.signed_txs,
                        &state.btc_on_eos_minting_params,
                        get_eos_account_nonce_from_db(&state.db)?,
                    )?,
                },
            })?)
            .and_then(|output| state.add_output_json_string(output))
        })
        .and_then(get_btc_output_as_string)
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Reprocess EOS Block For Stale Transaction
///
/// This function will take a passed in EOS block submission material and run it through the
/// submission pipeline, signing any signatures for pegouts it may find in the block
///
/// ### NOTE:
///
/// This version of the function _will_ account for fees so the outputted transaction's value is
/// correct, but it will __NOT__ accrue those fees onto the balance stored in the encrypted database.
/// This is to not double-count the fee if this block had already had a failed processing via an
/// organic block submission.
///
/// ### BEWARE:
/// If you don't broadcast the transaction outputted from this function, ALL future BTC transactions will
/// fail due to the core having an incorret set of UTXOs!
pub fn debug_reprocess_eos_block<D: DatabaseInterface>(db: D, block_json: &str) -> Result<String> {
    debug_reprocess_eos_block_maybe_accruing_fees(db, block_json, false)
}

/// # Debug Reprocess BTC Block For Stale Transaction
///
/// This function takes BTC block submission material and runs it thorugh the BTC submission
/// pipeline signing any transactions along the way. The `stale_transaction` part alludes to the
/// fact that EOS transactions have an intrinsic time limit, meaning a failure of upstream parts of
/// the bridge (ie tx broadcasting) could lead to expired transactions that can't ever be mined.
///
/// ### NOTE:
///
/// This version of the function _will_ account for fees so the outputted transaction's value is
/// correct, but it will __NOT__ accrue those fees onto the balance stored in the encrypted database.
/// This is to not double-count the fee if this block had already had a failed processing via an
/// organic block submission.
///
/// ### BEWARE:
/// This function does NOT increment the EOS  nonce (since it is not critical for correct
/// transaction creation) and so outputted reports will NOT contain correct nonces. This is to ensure
/// future transactions written by the proper submit-ETH-block pipeline will remain contiguous. The
/// user of this function should understand why this is the case, and thus should be able to modify
/// the outputted reports to slot into the external database correctly.
pub fn debug_reprocess_btc_block_for_stale_eos_tx<D: DatabaseInterface>(
    db: D,
    block_json_string: &str,
) -> Result<String> {
    debug_reprocess_btc_block_for_stale_eos_tx_maybe_accruing_fees(db, block_json_string, false)
}

/// # Debug Reprocess BTC Block For Stale Transaction
///
/// This function takes BTC block submission material and runs it thorugh the BTC submission
/// pipeline signing any transactions along the way. The `stale_transaction` part alludes to the
/// fact that EOS transactions have an intrinsic time limit, meaning a failure of upstream parts of
/// the bridge (ie tx broadcasting) could lead to expired transactions that can't ever be mined.
///
/// ### NOTE:
///
/// This version of the function _will_ account for fees so the outputted transaction's value is
/// correct, and will also add those fees to the `accrued_fees` value stored in the encrypted
/// database. Only use this function if you're sure those fees have not already been accrued from
/// the blocks organic submission to the core.
///
/// ### BEWARE:
/// This function does NOT increment the EOS  nonce (since it is not critical for correct
/// transaction creation) and so outputted reports will NOT contain correct nonces. This is to ensure
/// future transactions written by the proper submit-ETH-block pipeline will remain contiguous. The
/// user of this function should understand why this is the case, and thus should be able to modify
/// the outputted reports to slot into the external database correctly.
pub fn debug_reprocess_btc_block_for_stale_eos_tx_with_fee_accrual<D: DatabaseInterface>(
    db: D,
    block_json_string: &str,
) -> Result<String> {
    debug_reprocess_btc_block_for_stale_eos_tx_maybe_accruing_fees(db, block_json_string, true)
}

/// # Debug Reprocess EOS Block For Stale Transaction
///
/// This function will take a passed in EOS block submission material and run it through the
/// submission pipeline, signing any signatures for pegouts it may find in the block
///
/// ### NOTE:
///
/// This version of the function _will_ account for fees so the outputted transaction's value is
/// correct, and will also add those fees to the `accrued_fees` value stored in the encrypted
/// database. Only use this function if you're sure those fees have not already been accrued from
/// the blocks organic submission to the core.
///
/// ### BEWARE:
/// If you don't broadcast the transaction outputted from this function, ALL future BTC transactions will
/// fail due to the core having an incorret set of UTXOs!
pub fn debug_reprocess_eos_block_with_fee_accrual<D: DatabaseInterface>(db: D, block_json: &str) -> Result<String> {
    debug_reprocess_eos_block_maybe_accruing_fees(db, block_json, true)
}
