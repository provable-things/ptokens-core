pub use serde_json::json;

use crate::{
    btc_on_eos::{
        btc::{
            get_btc_output_json::{get_btc_output_as_string, get_eos_signed_tx_info_from_eth_txs, BtcOutput},
            minting_params::parse_minting_params_from_p2sh_deposits_and_add_to_state,
            sign_transactions::get_signed_eos_ptoken_issue_txs,
        },
        check_core_is_initialized::{
            check_core_is_initialized,
            check_core_is_initialized_and_return_btc_state,
            check_core_is_initialized_and_return_eos_state,
        },
        eos::{
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
            btc_constants::{get_btc_constants_db_keys, BTC_PRIVATE_KEY_DB_KEY as BTC_KEY},
            btc_database_utils::{get_btc_latest_block_from_db, start_btc_db_transaction},
            btc_state::BtcState,
            btc_submission_material::parse_submission_material_and_put_in_state,
            filter_p2sh_deposit_txs::filter_p2sh_deposit_txs_and_add_to_state,
            get_btc_block_in_db_format::create_btc_block_in_db_format_and_put_in_state,
            get_deposit_info_hash_map::get_deposit_info_hash_map_and_put_in_state,
            increment_btc_account_nonce::maybe_increment_btc_signature_nonce_and_return_eos_state,
            utxo_manager::{
                debug_utxo_utils::{
                    add_multiple_utxos,
                    clear_all_utxos,
                    consolidate_utxos,
                    get_child_pays_for_parent_btc_tx,
                    remove_utxo,
                },
                utxo_constants::get_utxo_constants_db_keys,
                utxo_utils::get_all_utxos_as_json_string,
            },
            validate_btc_block_header::validate_btc_block_header_in_state,
            validate_btc_difficulty::validate_difficulty_of_btc_block_in_state,
            validate_btc_merkle_root::validate_btc_merkle_root,
            validate_btc_proof_of_work::validate_proof_of_work_of_btc_block_in_state,
        },
        eos::{
            core_initialization::eos_init_utils::EosInitJson,
            eos_constants::{get_eos_constants_db_keys, EOS_PRIVATE_KEY_DB_KEY as EOS_KEY, REDEEM_ACTION_NAME},
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
            eos_debug_functions::{add_new_eos_schedule, get_processed_actions_list, update_incremerkle},
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
    constants::{DB_KEY_PREFIX, PRIVATE_KEY_DATA_SENSITIVITY_LEVEL},
    debug_database_utils::{get_key_from_db, set_key_in_db_to_value},
    traits::DatabaseInterface,
    types::Result,
    utils::prepend_debug_output_marker_to_string,
};

/// # Debug Get All Db Keys
///
/// This function will return a JSON formatted list of all the database keys used in the encrypted database.
pub fn debug_get_all_db_keys() -> Result<String> {
    check_debug_mode().map(|_| {
        json!({
            "btc": get_btc_constants_db_keys(),
            "eos": get_eos_constants_db_keys(),
            "db-key-prefix": DB_KEY_PREFIX.to_string(),
            "utxo-manager": get_utxo_constants_db_keys(),
        })
        .to_string()
    })
}

/// # Debug Reprocess EOS Block For Stale Transaction
///
/// This function will take a passed in EOS block submission material and run it through the
/// submission pipeline, signing any signatures for pegouts it may find in the block
///
/// ### BEWARE:
/// If you don't broadcast the transaction outputted from this function, ALL future BTC transactions will
/// fail due to the core having an incorret set of UTXOs!
pub fn debug_reprocess_eos_block<D>(db: D, block_json: &str) -> Result<String>
where
    D: DatabaseInterface,
{
    info!("✔ Debug reprocessing EOS block...");
    parse_submission_material_and_add_to_state(block_json, EosState::init(db))
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
        .and_then(maybe_sign_txs_and_add_to_state)
        .and_then(maybe_increment_btc_signature_nonce_and_return_eos_state)
        .and_then(maybe_extract_btc_utxo_from_btc_tx_in_state)
        .and_then(maybe_save_btc_utxos_to_db)
        .and_then(end_eos_db_transaction_and_return_state)
        .and_then(get_eos_output)
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Reprocess BTC Block For Stale Transaction
///
/// This function takes BTC block submission material and runs it thorugh the BTC submission
/// pipeline signing any transactions along the way. The `stale_transaction` part alludes to the
/// fact that EOS transactions have an intrinsic time limit, meaning a failure of upstream parts of
/// the bridge (ie tx broadcasting) could lead to expired transactions that can't ever be mined.
///
/// ### NOTE:
/// This function will increment the core's EOS nonce, meaning the outputted reports will have a
/// gap in their report IDs!
pub fn debug_reprocess_btc_block_for_stale_eos_tx<D>(db: D, block_json_string: &str) -> Result<String>
where
    D: DatabaseInterface,
{
    info!("✔ Reprocessing BTC block to core...");
    parse_submission_material_and_put_in_state(block_json_string, BtcState::init(db))
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

/// # Debug Update Incremerkle
///
/// This function will take an EOS initialization JSON as its input and use it to create an
/// incremerkle valid for the block number in the JSON. It will then REPLACE the incremerkle in the
/// encrypted database with this one.
///
/// ### BEWARE:
/// Changing the incremerkle changes the last block the enclave has seen and so can easily lead to
/// transaction replays. Use with extreme caution and only if you know exactly what you are doing
/// and why.
pub fn debug_update_incremerkle<D: DatabaseInterface>(db: &D, eos_init_json: &str) -> Result<String> {
    check_core_is_initialized(db).and_then(|_| update_incremerkle(db, &EosInitJson::from_json_string(&eos_init_json)?))
}

/// # Debug Clear All UTXOS
///
/// This function will remove ALL UTXOS from the core's encrypted database
///
/// ### BEWARE:
/// Use with extreme caution, and only if you know exactly what you are doing and why.
pub fn debug_clear_all_utxos<D: DatabaseInterface>(db: &D) -> Result<String> {
    info!("✔ Debug clearing all UTXOs...");
    check_debug_mode()
        .and_then(|_| clear_all_utxos(db))
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Add New Eos Schedule
///
/// Adds a new EOS schedule to the core's encrypted database.
pub fn debug_add_new_eos_schedule<D: DatabaseInterface>(db: D, schedule_json: &str) -> Result<String> {
    check_core_is_initialized(&db).and_then(|_| add_new_eos_schedule(&db, schedule_json))
}

/// # Debug Set Key in DB to Value
///
/// This function set to the given value a given key in the encryped database.
///
/// ### BEWARE:
/// Only use this if you know exactly what you are doing and why.
pub fn debug_set_key_in_db_to_value<D: DatabaseInterface>(db: D, key: &str, value: &str) -> Result<String> {
    let key_bytes = hex::decode(&key)?;
    let sensitivity = match key_bytes == EOS_KEY.to_vec() || key_bytes == BTC_KEY.to_vec() {
        true => PRIVATE_KEY_DATA_SENSITIVITY_LEVEL,
        false => None,
    };
    set_key_in_db_to_value(db, key, value, sensitivity).map(prepend_debug_output_marker_to_string)
}

/// # Debug Get Key From Db
///
/// This function will return the value stored under a given key in the encrypted database.
pub fn debug_get_key_from_db<D: DatabaseInterface>(db: D, key: &str) -> Result<String> {
    let key_bytes = hex::decode(&key)?;
    let sensitivity = match key_bytes == EOS_KEY.to_vec() || key_bytes == BTC_KEY.to_vec() {
        true => PRIVATE_KEY_DATA_SENSITIVITY_LEVEL,
        false => None,
    };
    get_key_from_db(db, key, sensitivity).map(prepend_debug_output_marker_to_string)
}

/// # Debug Get All UTXOs
///
/// This function will return a JSON containing all the UTXOs the encrypted database currently has.
pub fn debug_get_all_utxos<D: DatabaseInterface>(db: D) -> Result<String> {
    check_debug_mode()
        .and_then(|_| check_core_is_initialized(&db))
        .and_then(|_| get_all_utxos_as_json_string(&db))
}

/// # Debug Get Child-Pays-For-Parent BTC Transaction
///
/// This function attempts to find the UTXO via the passed in transaction hash and vOut values, and
/// upon success creates a transaction spending that UTXO, sending it entirely to itself minus the
/// passed in fee.
///
/// ### BEWARE:
/// This function spends UTXOs and outputs the signed transactions. If the outputted transaction is NOT
/// broadcast, the change output saved in the DB will NOT be spendable, leaving the enclave
/// bricked. Use ONLY if you know exactly what you're doing and why!
pub fn debug_get_child_pays_for_parent_btc_tx<D: DatabaseInterface>(
    db: D,
    fee: u64,
    tx_id: &str,
    v_out: u32,
) -> Result<String> {
    check_debug_mode()
        .and_then(|_| check_core_is_initialized(&db))
        .and_then(|_| get_child_pays_for_parent_btc_tx(db, fee, tx_id, v_out))
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Consolidate Utxos
///
/// This function removes X number of UTXOs from the database then crafts them into a single
/// transcation to itself before returning the serialized output ready for broadcasting, thus
/// consolidating those X UTXOs into a single one.
///
/// ### BEWARE:
/// This function spends UTXOs and outputs a signed transaction. If the outputted transaction is NOT
/// broadcast, the consolidated  output saved in the DB will NOT be spendable, leaving the enclave
/// bricked. Use ONLY if you know exactly what you're doing and why!
pub fn debug_consolidate_utxos<D: DatabaseInterface>(db: D, fee: u64, num_utxos: usize) -> Result<String> {
    check_debug_mode()
        .and_then(|_| check_core_is_initialized(&db))
        .and_then(|_| consolidate_utxos(db, fee, num_utxos))
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Remove UTXO
///
/// Pluck a UTXO from the UTXO set and discard it, locating it via its transaction ID and v-out values.
///
/// ### BEWARE:
/// Use ONLY if you know exactly what you're doing and why!
pub fn debug_remove_utxo<D: DatabaseInterface>(db: D, tx_id: &str, v_out: u32) -> Result<String> {
    check_debug_mode()
        .and_then(|_| check_core_is_initialized(&db))
        .and_then(|_| remove_utxo(db, tx_id, v_out))
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Add Multiple Utxos
///
/// Add multiple UTXOs to the databsae. This function first checks if that UTXO already exists in
/// the encrypted database, skipping it if so.
///
/// ### NOTE:
///
/// This function takes as it's argument and valid JSON string in the format that the
/// `debug_get_all_utxos` returns. In this way, it's useful for migrating a UTXO set from one core
/// to another.
///
/// ### BEWARE:
/// Use ONLY if you know exactly what you're doing and why!
pub fn debug_add_multiple_utxos<D: DatabaseInterface>(db: D, json_str: &str) -> Result<String> {
    check_debug_mode().and_then(|_| add_multiple_utxos(&db, json_str).map(prepend_debug_output_marker_to_string))
}

/// # Debug Get Processed Actions List
///
/// This function returns the list of already-processed action global sequences in JSON format.
pub fn debug_get_processed_actions_list<D: DatabaseInterface>(db: &D) -> Result<String> {
    check_core_is_initialized(db).and_then(|_| get_processed_actions_list(db))
}
