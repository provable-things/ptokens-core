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
    erc20_on_eos::{
        eos::{
            get_eos_output::get_eos_output,
            redeem_info::maybe_parse_redeem_infos_and_put_in_state,
            sign_normal_eth_txs::maybe_sign_normal_eth_txs_and_add_to_state,
            increment_eth_nonce::maybe_increment_eth_nonce_in_db_and_return_state,
        },
        check_core_is_initialized::{
            check_core_is_initialized,
            check_core_is_initialized_and_return_eth_state,
            check_core_is_initialized_and_return_eos_state,
        },
        eth::{
            get_output_json::get_output_json,
            peg_in_info::maybe_filter_peg_in_info_in_state,
        },
    },
    chains::{
        eos::{
            eos_database_utils::put_eos_schedule_in_db,
            parse_eos_schedule::parse_v2_schedule_string_to_v2_schedule,
            sign_eos_transactions::maybe_sign_eos_txs_and_add_to_eth_state,
            eos_erc20_dictionary::{
                EosErc20Dictionary,
                EosErc20DictionaryEntry,
                get_erc20_dictionary_from_db_and_add_to_eth_state,
            },
            eos_constants::{
                EOS_PRIVATE_KEY_DB_KEY,
                get_eos_constants_db_keys,
            },
            core_initialization::eos_init_utils::{
                EosInitJson,
                put_eos_latest_block_info_in_db,
                generate_and_put_incremerkle_in_db,
            },
            eos_state::EosState,
            add_schedule::maybe_add_new_eos_schedule_to_db_and_return_state,
            get_active_schedule::get_active_schedule_from_db_and_add_to_state,
            parse_submission_material::parse_submission_material_and_add_to_state,
            eos_erc20_dictionary::get_erc20_dictionary_from_db_and_add_to_eos_state,
            get_enabled_protocol_features::get_enabled_protocol_features_and_add_to_state,
            eos_database_transactions::{
                end_eos_db_transaction_and_return_state,
                start_eos_db_transaction_and_return_state,
            },
            filter_action_proofs::{
                maybe_filter_duplicate_proofs_from_state,
                maybe_filter_out_proofs_for_non_erc20_accounts,
                maybe_filter_out_invalid_action_receipt_digests,
                maybe_filter_out_proofs_with_wrong_action_mroot,
                maybe_filter_out_proofs_with_invalid_merkle_proofs,
                maybe_filter_out_action_proof_receipt_mismatches_and_return_state,
            },
        },
        eth::{
            eth_state::EthState,
            eth_utils::get_eth_address_from_str,
            eth_crypto::eth_transaction::EthTransaction,
            validate_block_in_state::validate_block_in_state,
            validate_receipts_in_state::validate_receipts_in_state,
            eth_submission_material::parse_eth_submission_material_and_put_in_state,
            filter_receipts_in_state::filter_receipts_for_erc20_on_eos_peg_in_events_in_state,
            eth_contracts::perc20::{
                PERC20_MIGRATE_GAS_LIMIT,
                encode_perc20_migrate_fxn_data,
                PERC20_CHANGE_SUPPORTED_TOKEN_GAS_LIMIT,
                encode_perc20_add_supported_token_fx_data,
                encode_perc20_remove_supported_token_fx_data,
            },
            eth_database_utils::{
                get_eth_chain_id_from_db,
                get_eth_gas_price_from_db,
                get_eth_private_key_from_db,
                get_eth_account_nonce_from_db,
                increment_eth_account_nonce_in_db,
                get_erc20_on_eos_smart_contract_address_from_db,
                put_erc20_on_eos_smart_contract_address_in_db,
            },
            eth_constants::{
                ETH_PRIVATE_KEY_DB_KEY,
                get_eth_constants_db_keys,
            },
        },
    },
};

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
        .and(Ok("{debug_update_blockroot_merkle_success:true}".to_string()))
        .map(prepend_debug_output_marker_to_string)
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
        .and(Ok("{debug_adding_eos_schedule_succeeded:true}".to_string()))
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
    let is_private_key = {
        key_bytes == EOS_PRIVATE_KEY_DB_KEY.to_vec() || key_bytes == ETH_PRIVATE_KEY_DB_KEY.to_vec()
    };
    let sensitivity = match is_private_key {
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
    let is_private_key = {
        key_bytes == EOS_PRIVATE_KEY_DB_KEY.to_vec() || key_bytes == ETH_PRIVATE_KEY_DB_KEY.to_vec()
    };
    let sensitivity = match is_private_key {
        true => PRIVATE_KEY_DATA_SENSITIVITY_LEVEL,
        false => None,
    };
    get_key_from_db(db, key, sensitivity).map(prepend_debug_output_marker_to_string)
}

/// # Debug Get All Db Keys
///
/// This function will return a JSON formatted list of all the database keys used in the encrypted database.
pub fn debug_get_all_db_keys() -> Result<String> {
    check_debug_mode()
        .and(Ok(json!({
            "eth": get_eth_constants_db_keys(),
            "eos": get_eos_constants_db_keys(),
            "db-key-prefix": DB_KEY_PREFIX.to_string(),
        }).to_string())
    )
}

/// # Debug Add ERC20 Dictionary Entry
///
/// This function will add an entry to the `EosErc20Dictionary` held in the encrypted database. The
/// dictionary defines the relationship between ERC20 etheruem addresses and their pToken EOS
/// address counterparts.
///
/// The required format of an entry is:
/// {
///     "eos_symbol": <symbol>,
///     "eth_symbol": <symbol>,
///     "eos_address": <address>,
///     "eth_address": <address>,
///     "eth_token_decimals": <num-decimals>,
///     "eos_token_decimals": <num-decimals>,
/// }
pub fn debug_add_erc20_dictionary_entry<D>(
    db: D,
    dictionary_entry_json_string: &str,
) -> Result<String>
    where D: DatabaseInterface
{
    info!("✔ Debug adding entry to `EosErc20Dictionary`...");
    let dictionary = EosErc20Dictionary::get_from_db(&db)?;
    check_debug_mode()
        .and_then(|_| check_core_is_initialized(&db))
        .and_then(|_| db.start_transaction())
        .and_then(|_| EosErc20DictionaryEntry::from_str(dictionary_entry_json_string))
        .and_then(|entry| dictionary.add_and_update_in_db(entry, &db))
        .and_then(|_| db.end_transaction())
        .and(Ok(json!({"adding_dictionary_entry_sucess":true}).to_string()))
}

/// # Debug Remove ERC20 Dictionary Entry
///
/// This function will remove an entry pertaining to the passed in ETH address from the
/// `EosErc20Dictionary` held in the encrypted database, should that entry exist. If it is
/// not extant, nothing is changed.
pub fn debug_remove_erc20_dictionary_entry<D>(
    db: D,
    eth_address_str: &str,
) -> Result<String>
    where D: DatabaseInterface
{
    info!("✔ Debug removing entry from `EosErc20Dictionary`...");
    let dictionary = EosErc20Dictionary::get_from_db(&db)?;
    check_debug_mode()
        .and_then(|_| check_core_is_initialized(&db))
        .and_then(|_| db.start_transaction())
        .and_then(|_| get_eth_address_from_str(eth_address_str))
        .and_then(|eth_address| dictionary.remove_entry_via_eth_address_and_update_in_db(&eth_address, &db))
        .and_then(|_| db.end_transaction())
        .and(Ok(json!({"removing_dictionary_entry_sucess":true}).to_string()))
}
/// # Debug Get PERC20 Migration Transaction
///
/// This function will create and sign a transaction that calls the `migrate` function on the
/// current `pERC20-on-EOS` smart-contract, migrationg it to the ETH address provided as an
/// argument. It then updates the smart-contract address stored in the encrypted database to that
/// new address.
///
/// ### NOTE:
/// This function will increment the core's ETH nonce, meaning the outputted reports will have a
/// gap in their report IDs!
///
/// ### BEWARE:
/// This function outputs a signed transaction which if NOT broadcast will result in the enclave no
/// longer working.  Use with extreme caution and only if you know exactly what you are doing!
pub fn debug_get_perc20_migration_tx<D>(
    db: D,
    new_eos_erc20_smart_contract_address_string: &str,
) -> Result<String>
    where D: DatabaseInterface
{
    db.start_transaction()?;
    info!("✔ Debug getting migration transaction...");
    let current_eth_account_nonce = get_eth_account_nonce_from_db(&db)?;
    let current_eos_erc20_smart_contract_address = get_erc20_on_eos_smart_contract_address_from_db(&db)?;
    let new_eos_erc20_smart_contract_address = get_eth_address_from_str(new_eos_erc20_smart_contract_address_string)?;
    check_debug_mode()
        .and_then(|_| check_core_is_initialized(&db))
        .and_then(|_| increment_eth_account_nonce_in_db(&db, 1))
        .and_then(|_| put_erc20_on_eos_smart_contract_address_in_db(&db, &new_eos_erc20_smart_contract_address))
        .and_then(|_| encode_perc20_migrate_fxn_data(new_eos_erc20_smart_contract_address))
        .and_then(|tx_data| Ok(EthTransaction::new_unsigned(
            tx_data,
            current_eth_account_nonce,
            0,
            current_eos_erc20_smart_contract_address,
            get_eth_chain_id_from_db(&db)?,
            PERC20_MIGRATE_GAS_LIMIT,
            get_eth_gas_price_from_db(&db)?,
        )))
        .and_then(|unsigned_tx| unsigned_tx.sign(get_eth_private_key_from_db(&db)?))
        .map(|signed_tx| signed_tx.serialize_hex())
        .and_then(|hex_tx| {
            db.end_transaction()?;
            Ok(json!({
                "success": true,
                "eth_signed_tx": hex_tx,
                "migrated_to_address:": new_eos_erc20_smart_contract_address.to_string(),
            }).to_string())
        })
}

/// # Debug Get Add Supported Token Transaction
///
/// This function will sign a transaction to add the given address as a supported token to
/// the `perc20-on-eos` smart-contract.
///
/// ### NOTE:
/// This function will increment the core's ETH nonce, meaning the outputted reports will have a
/// gap in their report IDs!
///
/// ### BEWARE:
/// This function will increment the core's ETH nonce, and so if the transaction is not broadcast
/// successfully, the core's ETH side will no longer function correctly. Use with extreme caution
/// and only if you know exactly what you are doing and why!
pub fn debug_get_add_supported_token_tx<D>(
    db: D,
    eth_address_str: &str,
) -> Result<String>
    where D: DatabaseInterface
{
    info!("✔ Debug getting `addSupportedToken` contract tx...");
    db.start_transaction()?;
    let current_eth_account_nonce = get_eth_account_nonce_from_db(&db)?;
    let eth_address = get_eth_address_from_str(eth_address_str)?;
    check_debug_mode()
        .and_then(|_| check_core_is_initialized(&db))
        .and_then(|_| increment_eth_account_nonce_in_db(&db, 1))
        .and_then(|_| encode_perc20_add_supported_token_fx_data(eth_address))
        .and_then(|tx_data| Ok(EthTransaction::new_unsigned(
            tx_data,
            current_eth_account_nonce,
            0,
            get_erc20_on_eos_smart_contract_address_from_db(&db)?,
            get_eth_chain_id_from_db(&db)?,
            PERC20_CHANGE_SUPPORTED_TOKEN_GAS_LIMIT,
            get_eth_gas_price_from_db(&db)?,
        )))
        .and_then(|unsigned_tx| unsigned_tx.sign(get_eth_private_key_from_db(&db)?))
        .map(|signed_tx| signed_tx.serialize_hex())
        .and_then(|hex_tx| {
            db.end_transaction()?;
            Ok(json!({ "success": true, "eth_signed_tx": hex_tx }).to_string())
        })
}

/// # Debug Get Remove Supported Token Transaction
///
/// This function will sign a transaction to remove the given address as a supported token to
/// the `perc20-on-eos` smart-contract.
///
/// ### NOTE:
/// This function will increment the core's ETH nonce, meaning the outputted reports will have a
/// gap in their report IDs!
///
/// ### BEWARE:
/// This function will increment the core's ETH nonce, and so if the transaction is not broadcast
/// successfully, the core's ETH side will no longer function correctly. Use with extreme caution
/// and only if you know exactly what you are doing and why!
pub fn debug_get_remove_supported_token_tx<D>(
    db: D,
    eth_address_str: &str,
) -> Result<String>
    where D: DatabaseInterface
{
    info!("✔ Debug getting `removeSupportedToken` contract tx...");
    db.start_transaction()?;
    let current_eth_account_nonce = get_eth_account_nonce_from_db(&db)?;
    let eth_address = get_eth_address_from_str(eth_address_str)?;
    check_debug_mode()
        .and_then(|_| check_core_is_initialized(&db))
        .and_then(|_| increment_eth_account_nonce_in_db(&db, 1))
        .and_then(|_| encode_perc20_remove_supported_token_fx_data(eth_address))
        .and_then(|tx_data| Ok(EthTransaction::new_unsigned(
            tx_data,
            current_eth_account_nonce,
            0,
            get_erc20_on_eos_smart_contract_address_from_db(&db)?,
            get_eth_chain_id_from_db(&db)?,
            PERC20_CHANGE_SUPPORTED_TOKEN_GAS_LIMIT,
            get_eth_gas_price_from_db(&db)?,
        )))
        .and_then(|unsigned_tx| unsigned_tx.sign(get_eth_private_key_from_db(&db)?))
        .map(|signed_tx| signed_tx.serialize_hex())
        .and_then(|hex_tx| {
            db.end_transaction()?;
            Ok(json!({ "success": true, "eth_signed_tx": hex_tx }).to_string())
        })
}

/// # Debug Reprocess ETH Block For Stale EOS Transaction
///
/// This function will take a passed in ETH block submission material and run it through the
/// simplified submission pipeline, signing any EOS signatures for peg-ins it may find in the block
///
/// ### NOTE:
/// This function has no database transactional capabilities and thus cannot modifiy the state of
/// the encrypted database in any way.
///
/// ### BEWARE:
/// Per above, this function does NOT increment the EOS  nonce (since it is not critical for correct
/// transaction creation) and so outputted reports will NOT contain correct nonces. This is to ensure
/// future transactions written by the proper submit-ETH-block pipeline will remain contiguous. The
/// user of this function should understand why this is the case, and thus should be able to modify
/// the outputted reports to slot into the external database correctly.
pub fn debug_reprocess_eth_block<D: DatabaseInterface>(db: D, block_json_string: &str) -> Result<String> {
    info!("✔ Debug reprocessing ETH block...");
    parse_eth_submission_material_and_put_in_state(block_json_string, EthState::init(db))
        .and_then(check_core_is_initialized_and_return_eth_state)
        .and_then(validate_block_in_state)
        .and_then(get_erc20_dictionary_from_db_and_add_to_eth_state)
        .and_then(validate_receipts_in_state)
        .and_then(filter_receipts_for_erc20_on_eos_peg_in_events_in_state)
        .and_then(|state| {
            let submission_material = state.get_eth_submission_material()?.clone();
            match submission_material.receipts.is_empty() {
                true => {
                    info!("✔ No receipts in block ∴ no info to parse!");
                    Ok(state)
                }
                false => {
                    info!("✔ {} receipts in block ∴ parsing info...", submission_material.get_block_number()?);
                    EosErc20Dictionary::get_from_db(&state.db)
                        .and_then(|accounts| submission_material.get_erc20_on_eos_peg_in_infos(&accounts))
                        .and_then(|peg_in_infos| state.add_erc20_on_eos_peg_in_infos(peg_in_infos))
                }
            }
        })
        .and_then(maybe_filter_peg_in_info_in_state)
        .and_then(maybe_sign_eos_txs_and_add_to_eth_state)
        .and_then(get_output_json)
}

/// # Debug Reprocess EOS Block
///
/// This function will take passed in EOS submission material and run it through the simplified
/// submission pipeline, signing and ETH transactions based on valid proofs therein.
///
/// ### NOTE:
/// This function does NOT validate the block to which the proofs (may) pertain.
///
/// ### BEWARE:
/// This function will incrememnt the ETH nonce in the encrypted database, and so not broadcasting
/// any outputted transactions will result in all future transactions failing. Use only with
/// extreme caution and when you know exactly what you are doing and why.
pub fn debug_reprocess_eos_block<D>(db: D, block_json: &str) -> Result<String> where D: DatabaseInterface {
    info!("✔ Debug reprocessing EOS block...");
    parse_submission_material_and_add_to_state(block_json, EosState::init(db))
        .and_then(check_core_is_initialized_and_return_eos_state)
        .and_then(get_enabled_protocol_features_and_add_to_state)
        .and_then(get_active_schedule_from_db_and_add_to_state)
        .and_then(start_eos_db_transaction_and_return_state)
        .and_then(get_erc20_dictionary_from_db_and_add_to_eos_state)
        .and_then(maybe_add_new_eos_schedule_to_db_and_return_state)
        .and_then(maybe_filter_duplicate_proofs_from_state)
        .and_then(maybe_filter_out_proofs_for_non_erc20_accounts)
        .and_then(maybe_filter_out_action_proof_receipt_mismatches_and_return_state)
        .and_then(maybe_filter_out_invalid_action_receipt_digests)
        .and_then(maybe_filter_out_proofs_with_invalid_merkle_proofs)
        .and_then(maybe_filter_out_proofs_with_wrong_action_mroot)
        .and_then(maybe_parse_redeem_infos_and_put_in_state)
        .and_then(maybe_sign_normal_eth_txs_and_add_to_state)
        .and_then(maybe_increment_eth_nonce_in_db_and_return_state)
        .and_then(end_eos_db_transaction_and_return_state)
        .and_then(get_eos_output)
        .map(prepend_debug_output_marker_to_string)
}
