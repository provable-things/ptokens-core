pub use serde_json::json;
use crate::{
    types::Result,
    traits::DatabaseInterface,
    check_debug_mode::check_debug_mode,
    utils::prepend_debug_output_marker_to_string,
    constants::{
        DB_KEY_PREFIX,
        PRIVATE_KEY_DATA_SENSITIVITY_LEVEL,
    },
    debug_database_utils::{
        get_key_from_db,
        set_key_in_db_to_value,
    },
    chains::{
        eos::{
            eos_state::EosState,
            eos_crypto::eos_private_key::EosPrivateKey,
            get_processed_tx_ids::get_processed_tx_ids_and_add_to_state,
            parse_eos_schedule::parse_v2_schedule_string_to_v2_schedule,
            parse_submission_material::parse_submission_material_and_add_to_state,
            get_enabled_protocol_features::get_enabled_protocol_features_and_add_to_state,
            add_global_sequences_to_processed_list::maybe_add_global_sequences_to_processed_list_and_return_state,
            eos_database_utils::{
                put_eos_schedule_in_db,
                get_eos_chain_id_from_db,
                get_eos_account_nonce_from_db,
                get_eos_account_name_string_from_db,
            },
            eos_constants::{
                get_eos_constants_db_keys,
                EOS_PRIVATE_KEY_DB_KEY as EOS_KEY,
            },
            eos_database_transactions::{
                end_eos_db_transaction_and_return_state,
                start_eos_db_transaction_and_return_state,
            },
            filter_action_proofs::{
                maybe_filter_duplicate_proofs_from_state,
                maybe_filter_out_invalid_action_receipt_digests,
                maybe_filter_out_proofs_with_wrong_action_mroot,
                maybe_filter_out_proofs_with_invalid_merkle_proofs,
                maybe_filter_out_proofs_for_non_btc_on_eos_accounts,
                maybe_filter_out_action_proof_receipt_mismatches_and_return_state,
            },
            core_initialization::eos_init_utils::{
                EosInitJson,
                put_eos_latest_block_info_in_db,
                generate_and_put_incremerkle_in_db,
            },
        },
        btc::{
            increment_btc_account_nonce::maybe_increment_btc_signature_nonce_and_return_eos_state,
            btc_constants::{
                get_btc_constants_db_keys,
                BTC_PRIVATE_KEY_DB_KEY as BTC_KEY,
            },
            utxo_manager::{
                debug_utxo_utils::clear_all_utxos,
                utxo_utils::get_all_utxos_as_json_string,
                utxo_constants::get_utxo_constants_db_keys,
            },
        },
    },
    btc_on_eos::{
        check_core_is_initialized::{
            check_core_is_initialized,
            check_core_is_initialized_and_return_btc_state,
            check_core_is_initialized_and_return_eos_state,
        },
        btc::{
            btc_state::BtcState,
            sign_transactions::get_signed_txs,
            btc_database_utils::start_btc_db_transaction,
            get_btc_output_json::get_btc_output_as_string,
            btc_database_utils::get_btc_latest_block_from_db,
            validate_btc_merkle_root::validate_btc_merkle_root,
            filter_minting_params::maybe_filter_minting_params_in_state,
            validate_btc_block_header::validate_btc_block_header_in_state,
            filter_p2sh_deposit_txs::filter_p2sh_deposit_txs_and_add_to_state,
            validate_btc_difficulty::validate_difficulty_of_btc_block_in_state,
            filter_too_short_names::maybe_filter_name_too_short_params_in_state,
            get_deposit_info_hash_map::get_deposit_info_hash_map_and_put_in_state,
            parse_submission_material::parse_submission_material_and_put_in_state,
            validate_btc_proof_of_work::validate_proof_of_work_of_btc_block_in_state,
            get_btc_block_in_db_format::create_btc_block_in_db_format_and_put_in_state,
            parse_minting_params_from_p2sh_deposits::parse_minting_params_from_p2sh_deposits_and_add_to_state,
            get_btc_output_json::{
                    BtcOutput,
                    get_eos_signed_tx_info_from_eth_txs,
            },
	},
        eos::{
            get_eos_output::get_eos_output,
            save_btc_utxos_to_db::maybe_save_btc_utxos_to_db,
            sign_transactions::maybe_sign_txs_and_add_to_state,
            extract_utxos_from_btc_txs::maybe_extract_btc_utxo_from_btc_tx_in_state,
            redeem_info::{
                maybe_parse_redeem_infos_and_put_in_state,
                maybe_filter_value_too_low_redeem_infos_in_state,
                maybe_filter_out_already_processed_tx_ids_from_state,
            },
        },
    },
};

/// # Debug Get All Db Keys
///
/// This function will return a JSON formatted list of all the database keys used in the encrypted database.
pub fn debug_get_all_db_keys() -> Result<String> {
    check_debug_mode()
        .map(|_|
            json!({
                "btc": get_btc_constants_db_keys(),
                "eos": get_eos_constants_db_keys(),
                "db-key-prefix": DB_KEY_PREFIX.to_string(),
                "utxo-manager": get_utxo_constants_db_keys(),
            }).to_string()
    )
}

/// # Debug Reprocess EOS Block For Stale Transaction
///
/// This function will take a passed in EOS block submission material and run it through the
/// submission pipeline, signing any signatures for pegouts it may find in the block
///
/// ### BEWARE:
/// If you don't broadcast the transaction outputted from this function, ALL future BTC transactions will
/// fail due to the core having an incorret set of UTXOs!
pub fn debug_reprocess_eos_block<D>(db: D, block_json: &str) -> Result<String> where D: DatabaseInterface {
    info!("✔ Debug reprocessing EOS block...");
    parse_submission_material_and_add_to_state(block_json, EosState::init(db))
        .and_then(check_core_is_initialized_and_return_eos_state)
        .and_then(get_enabled_protocol_features_and_add_to_state)
        .and_then(start_eos_db_transaction_and_return_state)
        .and_then(get_processed_tx_ids_and_add_to_state)
        .and_then(maybe_filter_duplicate_proofs_from_state)
        .and_then(maybe_filter_out_proofs_for_non_btc_on_eos_accounts)
        .and_then(maybe_filter_out_action_proof_receipt_mismatches_and_return_state)
        .and_then(maybe_filter_out_invalid_action_receipt_digests)
        .and_then(maybe_filter_out_proofs_with_invalid_merkle_proofs)
        .and_then(maybe_filter_out_proofs_with_wrong_action_mroot)
        .and_then(maybe_parse_redeem_infos_and_put_in_state)
        .and_then(maybe_filter_value_too_low_redeem_infos_in_state)
        .and_then(maybe_filter_out_already_processed_tx_ids_from_state)
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
pub fn debug_reprocess_btc_block_for_stale_eos_tx<D>(
    db: D,
    block_json_string: &str
) -> Result<String>
    where D: DatabaseInterface
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
        .and_then(maybe_filter_minting_params_in_state)
        .and_then(maybe_filter_name_too_short_params_in_state)
        .and_then(create_btc_block_in_db_format_and_put_in_state)
        .and_then(|state| {
	    info!("✔ Maybe signing reprocessed minting txs...");
	    get_signed_txs(
		state.ref_block_num,
		state.ref_block_prefix,
		&get_eos_chain_id_from_db(&state.db)?,
		&EosPrivateKey::get_from_db(&state.db)?,
		&get_eos_account_name_string_from_db(&state.db)?,
		&state.minting_params,
	    )
		.and_then(|signed_txs| {
			info!("✔ EOS Signed Txs: {:?}", signed_txs);
			state.add_signed_txs(signed_txs)
		})
	})
        .and_then(|state| {
	    info!("✔ Getting BTC output json and putting in state...");
	    Ok(serde_json::to_string(
		&BtcOutput {
		    btc_latest_block_number: get_btc_latest_block_from_db(
                         &state.db
                     )?.height,
		    eos_signed_transactions: match &state.signed_txs.len() {
			0 => vec![],
			_ =>
			    get_eos_signed_tx_info_from_eth_txs(
				&state.signed_txs,
				&state.minting_params,
				get_eos_account_nonce_from_db(&state.db)?,
			    )?,
		    }
		}
	    )?)
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
    info!("✔ Debug updating blockroot merkle...");
    let init_json = EosInitJson::from_json_string(&eos_init_json)?;
    check_debug_mode()
        .and_then(|_| check_core_is_initialized(db))
        .and_then(|_| put_eos_latest_block_info_in_db(db, &init_json.block))
        .and_then(|_| db.start_transaction())
        .and_then(|_| generate_and_put_incremerkle_in_db(db, &init_json.blockroot_merkle))
        .and_then(|_| db.end_transaction())
        .map(|_| "{debug_update_blockroot_merkle_success:true}".to_string())
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Clear All UTXOS
///
/// This function will remove ALL UTXOS from the core's encrypted database
///
/// ### BEWARE:
/// Use with extreme caution, and only if you know exactly what you are doing and why.
pub fn debug_clear_all_utxos<D: DatabaseInterface>(db: &D) -> Result<String> {
    info!("✔ Debug clearing all UTXOs...");
    clear_all_utxos(db).map(prepend_debug_output_marker_to_string)
}

/// # Debug Add New Eos Schedule
///
/// Does exactly what it says on the tin. It's currently required due to an open ticket on the
/// validation of EOS blocks containing new schedules. Once that ticket is cleared, new schedules
/// can be brought in "organically" by syncing to the core up to the block containing said new
/// schedule. Meanwhile, this function must suffice.
pub fn debug_add_new_eos_schedule<D: DatabaseInterface>(db: D, schedule_json: &str) -> Result<String> {
    info!("✔ Debug adding new EOS schedule...");
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| parse_v2_schedule_string_to_v2_schedule(&schedule_json))
        .and_then(|schedule| put_eos_schedule_in_db(&db, &schedule))
        .and_then(|_| db.end_transaction())
        .map(|_| "{debug_adding_eos_schedule_succeeded:true}".to_string())
        .map(prepend_debug_output_marker_to_string)
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
        .and_then(|_| get_all_utxos_as_json_string(db))
}
