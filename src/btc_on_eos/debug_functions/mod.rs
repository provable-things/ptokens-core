pub use serde_json::json;

pub(crate) mod block_reprocessors;

use crate::{
    btc_on_eos::check_core_is_initialized::{
        check_core_is_initialized,
        check_core_is_initialized_and_return_btc_state,
    },
    chains::{
        btc::{
            btc_constants::{get_btc_constants_db_keys, BTC_PRIVATE_KEY_DB_KEY as BTC_KEY},
            btc_database_utils::{end_btc_db_transaction, get_btc_address_from_db, start_btc_db_transaction},
            btc_debug_functions::debug_put_btc_fee_in_db,
            btc_state::BtcState,
            btc_submission_material::parse_submission_material_and_put_in_state,
            btc_utils::{get_hex_tx_from_signed_btc_tx, get_pay_to_pub_key_hash_script},
            extract_utxos_from_p2pkh_txs::{
                extract_utxos_from_txs,
                maybe_extract_utxos_from_p2pkh_txs_and_put_in_state,
            },
            extract_utxos_from_p2sh_txs::maybe_extract_utxos_from_p2sh_txs_and_put_in_state,
            filter_p2pkh_deposit_txs::filter_for_p2pkh_deposit_txs_including_change_outputs_and_add_to_state,
            filter_p2sh_deposit_txs::filter_p2sh_deposit_txs_and_add_to_state,
            filter_utxos::filter_out_utxos_extant_in_db_from_state,
            get_deposit_info_hash_map::get_deposit_info_hash_map_and_put_in_state,
            save_utxos_to_db::maybe_save_utxos_to_db,
            utxo_manager::{
                debug_utxo_utils::{
                    add_multiple_utxos,
                    clear_all_utxos,
                    consolidate_utxos,
                    get_child_pays_for_parent_btc_tx,
                    remove_utxo,
                },
                utxo_constants::get_utxo_constants_db_keys,
                utxo_database_utils::save_utxos_to_db,
                utxo_utils::get_all_utxos_as_json_string,
            },
            validate_btc_block_header::validate_btc_block_header_in_state,
            validate_btc_difficulty::validate_difficulty_of_btc_block_in_state,
            validate_btc_merkle_root::validate_btc_merkle_root,
            validate_btc_proof_of_work::validate_proof_of_work_of_btc_block_in_state,
        },
        eos::{
            core_initialization::eos_init_utils::EosInitJson,
            eos_constants::{get_eos_constants_db_keys, EOS_PRIVATE_KEY_DB_KEY as EOS_KEY},
            eos_debug_functions::{add_new_eos_schedule, get_processed_actions_list, update_incremerkle},
        },
    },
    check_debug_mode::check_debug_mode,
    constants::{DB_KEY_PREFIX, PRIVATE_KEY_DATA_SENSITIVITY_LEVEL, SUCCESS_JSON},
    debug_database_utils::{get_key_from_db, set_key_in_db_to_value},
    fees::{
        fee_database_utils::FeeDatabaseUtils,
        fee_utils::sanity_check_basis_points_value,
        fee_withdrawals::get_btc_on_eos_fee_withdrawal_tx,
    },
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
    check_core_is_initialized(db).and_then(|_| update_incremerkle(db, &EosInitJson::from_json_string(eos_init_json)?))
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
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| add_multiple_utxos(&db, json_str))
        .and_then(|output| {
            db.end_transaction()?;
            Ok(prepend_debug_output_marker_to_string(output))
        })
}

/// # Debug Get Processed Actions List
///
/// This function returns the list of already-processed action global sequences in JSON format.
pub fn debug_get_processed_actions_list<D: DatabaseInterface>(db: &D) -> Result<String> {
    check_core_is_initialized(db).and_then(|_| get_processed_actions_list(db))
}

/// # Debug Maybe Add UTXO To DB
///
/// This function accepts as its param BTC submission material, in which it inspects all the
/// transactions looking for any pertaining to the core's own public key, or deposit addresses
/// derived from it. Any it finds it will extract the UTXO from and add it to the encrypted
/// database. Note that this fxn WILL extract the enclave's own change UTXOs from blocks!
///
/// ### NOTE:
/// The core won't accept UTXOs it already has in its encrypted database.
pub fn debug_maybe_add_utxo_to_db<D: DatabaseInterface>(db: D, btc_submission_material_json: &str) -> Result<String> {
    check_debug_mode()
        .and_then(|_| parse_submission_material_and_put_in_state(btc_submission_material_json, BtcState::init(db)))
        .and_then(check_core_is_initialized_and_return_btc_state)
        .and_then(validate_btc_block_header_in_state)
        .and_then(validate_difficulty_of_btc_block_in_state)
        .and_then(validate_proof_of_work_of_btc_block_in_state)
        .and_then(validate_btc_merkle_root)
        .and_then(get_deposit_info_hash_map_and_put_in_state)
        .and_then(filter_p2sh_deposit_txs_and_add_to_state)
        .and_then(filter_for_p2pkh_deposit_txs_including_change_outputs_and_add_to_state)
        .and_then(maybe_extract_utxos_from_p2pkh_txs_and_put_in_state)
        .and_then(maybe_extract_utxos_from_p2sh_txs_and_put_in_state)
        .and_then(start_btc_db_transaction)
        .and_then(filter_out_utxos_extant_in_db_from_state)
        .and_then(maybe_save_utxos_to_db)
        .and_then(end_btc_db_transaction)
        .map(|_| SUCCESS_JSON.to_string())
        .map(prepend_debug_output_marker_to_string)
}

/// Debug Set BTC fee
///
/// This function sets the BTC fee to the given value. The unit is satoshis per byte.
pub fn debug_set_btc_fee<D: DatabaseInterface>(db: D, fee: u64) -> Result<String> {
    debug_put_btc_fee_in_db(&db, fee)
}

fn debug_put_btc_on_eos_basis_points_in_db<D: DatabaseInterface>(
    db: &D,
    basis_points: u64,
    peg_in: bool,
) -> Result<String> {
    let suffix = if peg_in { "in" } else { "out" };
    info!(
        "✔ Debug setting `BtcOnEos` peg-{} basis-points to {}",
        suffix, basis_points
    );
    check_debug_mode()
        .and_then(|_| sanity_check_basis_points_value(basis_points))
        .and_then(|_| db.start_transaction())
        .and_then(|_| {
            if peg_in {
                FeeDatabaseUtils::new_for_btc_on_eos().put_peg_in_basis_points_in_db(db, basis_points)
            } else {
                FeeDatabaseUtils::new_for_btc_on_eos().put_peg_out_basis_points_in_db(db, basis_points)
            }
        })
        .and_then(|_| db.end_transaction())
        .and(Ok(
            json!({format!("set_btc_on_eos_peg_{}_basis_points", suffix):true}).to_string()
        ))
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Put BTC-on-EOS Peg-In Basis-Points In DB
///
/// This function sets to the given value the `BTC-on-EOS` peg-in basis-points in the encrypted
/// database.
pub fn debug_put_btc_on_eos_peg_in_basis_points_in_db<D: DatabaseInterface>(
    db: &D,
    basis_points: u64,
) -> Result<String> {
    info!("✔ Debug setting `BtcOnEos` peg-in basis-points to {}", basis_points);
    debug_put_btc_on_eos_basis_points_in_db(db, basis_points, true)
}

/// # Debug Put BTC-on-EOS Peg-Out Basis-Points In DB
///
/// This function sets to the given value the `BTC-on-EOS` peg-out basis-points in the encrypted
/// database.
pub fn debug_put_btc_on_eos_peg_out_basis_points_in_db<D: DatabaseInterface>(
    db: &D,
    basis_points: u64,
) -> Result<String> {
    info!("✔ Debug setting `BtcOnEos` peg-out basis-points to {}", basis_points);
    debug_put_btc_on_eos_basis_points_in_db(db, basis_points, false)
}

/// # Debug Get Fee Withdrawal Tx
///
/// This function crates a BTC transaction to the passed in address for the amount of accrued fees
/// accounted for in the encrypted database. The function then reset this value back to zero. The
/// signed transaction is returned to the caller.
pub fn debug_get_fee_withdrawal_tx<D: DatabaseInterface>(db: D, btc_address: &str) -> Result<String> {
    info!("✔ Debug getting `BtcOnEos` withdrawal tx...");
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| get_btc_on_eos_fee_withdrawal_tx(&db, btc_address))
        .and_then(|btc_tx| {
            let change_utxos = get_pay_to_pub_key_hash_script(&get_btc_address_from_db(&db)?)
                .map(|target_script| extract_utxos_from_txs(&target_script, &[btc_tx.clone()]))?;
            save_utxos_to_db(&db, &change_utxos)?;
            db.end_transaction()?;
            Ok(json!({ "signed_btc_tx": get_hex_tx_from_signed_btc_tx(&btc_tx) }).to_string())
        })
        .map(prepend_debug_output_marker_to_string)
}
