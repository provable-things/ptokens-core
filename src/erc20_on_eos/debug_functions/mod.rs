pub use serde_json::json;

use crate::{
    chains::{
        eos::{
            add_schedule::maybe_add_new_eos_schedule_to_db_and_return_state,
            core_initialization::eos_init_utils::EosInitJson,
            eos_constants::{get_eos_constants_db_keys, EOS_PRIVATE_KEY_DB_KEY, REDEEM_ACTION_NAME},
            eos_database_transactions::{
                end_eos_db_transaction_and_return_state,
                start_eos_db_transaction_and_return_state,
            },
            eos_debug_functions::{
                add_eos_eth_token_dictionary_entry,
                add_new_eos_schedule,
                get_processed_actions_list,
                remove_eos_eth_token_dictionary_entry,
                update_incremerkle,
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
                maybe_filter_out_proofs_for_accounts_not_in_token_dictionary,
                maybe_filter_out_proofs_with_invalid_merkle_proofs,
                maybe_filter_out_proofs_with_wrong_action_mroot,
                maybe_filter_proofs_for_action_name,
            },
            get_enabled_protocol_features::get_enabled_protocol_features_and_add_to_state,
        },
        eth::{
            eth_constants::{get_eth_constants_db_keys, ETH_PRIVATE_KEY_DB_KEY},
            eth_contracts::erc20_vault::{
                encode_erc20_vault_add_supported_token_fx_data,
                encode_erc20_vault_migrate_fxn_data,
                encode_erc20_vault_remove_supported_token_fx_data,
                ERC20_VAULT_CHANGE_SUPPORTED_TOKEN_GAS_LIMIT,
                ERC20_VAULT_MIGRATE_GAS_LIMIT,
            },
            eth_crypto::eth_transaction::EthTransaction,
            eth_database_utils::{
                get_erc20_on_eos_smart_contract_address_from_db,
                get_eth_account_nonce_from_db,
                get_eth_chain_id_from_db,
                get_eth_gas_price_from_db,
                get_eth_private_key_from_db,
                increment_eth_account_nonce_in_db,
                put_erc20_on_eos_smart_contract_address_in_db,
            },
            eth_debug_functions::debug_set_eth_gas_price_in_db,
            eth_state::EthState,
            eth_submission_material::parse_eth_submission_material_and_put_in_state,
            eth_utils::get_eth_address_from_str,
            validate_block_in_state::validate_block_in_state,
            validate_receipts_in_state::validate_receipts_in_state,
        },
    },
    check_debug_mode::check_debug_mode,
    constants::{DB_KEY_PREFIX, PRIVATE_KEY_DATA_SENSITIVITY_LEVEL},
    debug_database_utils::{get_key_from_db, set_key_in_db_to_value},
    dictionaries::{
        dictionary_constants::EOS_ETH_DICTIONARY_KEY,
        eos_eth::{
            get_eos_eth_token_dictionary_from_db_and_add_to_eos_state,
            get_eos_eth_token_dictionary_from_db_and_add_to_eth_state,
            EosEthTokenDictionary,
        },
    },
    erc20_on_eos::{
        check_core_is_initialized::{
            check_core_is_initialized,
            check_core_is_initialized_and_return_eos_state,
            check_core_is_initialized_and_return_eth_state,
        },
        eos::{
            get_eos_output::get_eos_output,
            increment_eth_nonce::maybe_increment_eth_nonce_in_db_and_return_eos_state,
            redeem_info::maybe_parse_redeem_infos_and_put_in_state,
            sign_normal_eth_txs::maybe_sign_normal_eth_txs_and_add_to_state,
        },
        eth::{
            get_output_json::get_output_json,
            peg_in_info::{
                filter_out_zero_value_peg_ins_from_state,
                filter_submission_material_for_peg_in_events_in_state,
                maybe_sign_eos_txs_and_add_to_eth_state,
                Erc20OnEosPegInInfos,
            },
        },
    },
    traits::DatabaseInterface,
    types::Result,
    utils::prepend_debug_output_marker_to_string,
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
    check_core_is_initialized(db)
        .and_then(|_| update_incremerkle(db, &EosInitJson::from_json_string(eos_init_json)?))
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
    let is_private_key =
        { key_bytes == EOS_PRIVATE_KEY_DB_KEY.to_vec() || key_bytes == ETH_PRIVATE_KEY_DB_KEY.to_vec() };
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
    let is_private_key =
        { key_bytes == EOS_PRIVATE_KEY_DB_KEY.to_vec() || key_bytes == ETH_PRIVATE_KEY_DB_KEY.to_vec() };
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
    check_debug_mode().and(Ok(json!({
        "eth": get_eth_constants_db_keys(),
        "eos": get_eos_constants_db_keys(),
        "db-key-prefix": DB_KEY_PREFIX.to_string(),
        "dictionary": hex::encode(EOS_ETH_DICTIONARY_KEY.to_vec()),
    })
    .to_string()))
}

/// # Debug Add ERC20 Dictionary Entry
///
/// This function will add an entry to the `EosEthTokenDictionary` held in the encrypted database. The
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
pub fn debug_add_eos_eth_token_dictionary_entry<D: DatabaseInterface>(
    db: D,
    dictionary_entry_json_string: &str,
) -> Result<String> {
    check_core_is_initialized(&db).and_then(|_| add_eos_eth_token_dictionary_entry(&db, dictionary_entry_json_string))
}

/// # Debug Remove ERC20 Dictionary Entry
///
/// This function will remove an entry pertaining to the passed in ETH address from the
/// `EosEthTokenDictionary` held in the encrypted database, should that entry exist. If it is
/// not extant, nothing is changed.
pub fn debug_remove_eos_eth_token_dictionary_entry<D: DatabaseInterface>(
    db: D,
    eth_address_str: &str,
) -> Result<String> {
    check_core_is_initialized(&db).and_then(|_| remove_eos_eth_token_dictionary_entry(&db, eth_address_str))
}

/// # Debug Get ERC20_VAULT Migration Transaction
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
pub fn debug_get_erc20_vault_migration_tx<D>(db: D, new_eos_erc20_smart_contract_address_string: &str) -> Result<String>
where
    D: DatabaseInterface,
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
        .and_then(|_| encode_erc20_vault_migrate_fxn_data(new_eos_erc20_smart_contract_address))
        .and_then(|tx_data| {
            Ok(EthTransaction::new_unsigned(
                tx_data,
                current_eth_account_nonce,
                0,
                current_eos_erc20_smart_contract_address,
                &get_eth_chain_id_from_db(&db)?,
                ERC20_VAULT_MIGRATE_GAS_LIMIT,
                get_eth_gas_price_from_db(&db)?,
            ))
        })
        .and_then(|unsigned_tx| unsigned_tx.sign(&get_eth_private_key_from_db(&db)?))
        .map(|signed_tx| signed_tx.serialize_hex())
        .and_then(|hex_tx| {
            db.end_transaction()?;
            Ok(json!({
                "success": true,
                "eth_signed_tx": hex_tx,
                "migrated_to_address:": new_eos_erc20_smart_contract_address.to_string(),
            })
            .to_string())
        })
}

/// # Debug Get Add Supported Token Transaction
///
/// This function will sign a transaction to add the given address as a supported token to
/// the `erc20-vault-on-eos` smart-contract.
///
/// ### NOTE:
/// This function will increment the core's ETH nonce, meaning the outputted reports will have a
/// gap in their report IDs!
///
/// ### BEWARE:
/// This function will increment the core's ETH nonce, and so if the transaction is not broadcast
/// successfully, the core's ETH side will no longer function correctly. Use with extreme caution
/// and only if you know exactly what you are doing and why!
pub fn debug_get_add_supported_token_tx<D>(db: D, eth_address_str: &str) -> Result<String>
where
    D: DatabaseInterface,
{
    info!("✔ Debug getting `addSupportedToken` contract tx...");
    db.start_transaction()?;
    let current_eth_account_nonce = get_eth_account_nonce_from_db(&db)?;
    let eth_address = get_eth_address_from_str(eth_address_str)?;
    check_debug_mode()
        .and_then(|_| check_core_is_initialized(&db))
        .and_then(|_| increment_eth_account_nonce_in_db(&db, 1))
        .and_then(|_| encode_erc20_vault_add_supported_token_fx_data(eth_address))
        .and_then(|tx_data| {
            Ok(EthTransaction::new_unsigned(
                tx_data,
                current_eth_account_nonce,
                0,
                get_erc20_on_eos_smart_contract_address_from_db(&db)?,
                &get_eth_chain_id_from_db(&db)?,
                ERC20_VAULT_CHANGE_SUPPORTED_TOKEN_GAS_LIMIT,
                get_eth_gas_price_from_db(&db)?,
            ))
        })
        .and_then(|unsigned_tx| unsigned_tx.sign(&get_eth_private_key_from_db(&db)?))
        .map(|signed_tx| signed_tx.serialize_hex())
        .and_then(|hex_tx| {
            db.end_transaction()?;
            Ok(json!({ "success": true, "eth_signed_tx": hex_tx }).to_string())
        })
}

/// # Debug Get Remove Supported Token Transaction
///
/// This function will sign a transaction to remove the given address as a supported token to
/// the `erc20-vault-on-eos` smart-contract.
///
/// ### NOTE:
/// This function will increment the core's ETH nonce, meaning the outputted reports will have a
/// gap in their report IDs!
///
/// ### BEWARE:
/// This function will increment the core's ETH nonce, and so if the transaction is not broadcast
/// successfully, the core's ETH side will no longer function correctly. Use with extreme caution
/// and only if you know exactly what you are doing and why!
pub fn debug_get_remove_supported_token_tx<D>(db: D, eth_address_str: &str) -> Result<String>
where
    D: DatabaseInterface,
{
    info!("✔ Debug getting `removeSupportedToken` contract tx...");
    db.start_transaction()?;
    let current_eth_account_nonce = get_eth_account_nonce_from_db(&db)?;
    let eth_address = get_eth_address_from_str(eth_address_str)?;
    check_debug_mode()
        .and_then(|_| check_core_is_initialized(&db))
        .and_then(|_| increment_eth_account_nonce_in_db(&db, 1))
        .and_then(|_| encode_erc20_vault_remove_supported_token_fx_data(eth_address))
        .and_then(|tx_data| {
            Ok(EthTransaction::new_unsigned(
                tx_data,
                current_eth_account_nonce,
                0,
                get_erc20_on_eos_smart_contract_address_from_db(&db)?,
                &get_eth_chain_id_from_db(&db)?,
                ERC20_VAULT_CHANGE_SUPPORTED_TOKEN_GAS_LIMIT,
                get_eth_gas_price_from_db(&db)?,
            ))
        })
        .and_then(|unsigned_tx| unsigned_tx.sign(&get_eth_private_key_from_db(&db)?))
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
        .and_then(get_eos_eth_token_dictionary_from_db_and_add_to_eth_state)
        .and_then(validate_receipts_in_state)
        .and_then(filter_submission_material_for_peg_in_events_in_state)
        .and_then(|state| {
            let submission_material = state.get_eth_submission_material()?.clone();
            match submission_material.receipts.is_empty() {
                true => {
                    info!("✔ No receipts in block ∴ no info to parse!");
                    Ok(state)
                },
                false => {
                    info!(
                        "✔ {} receipts in block ∴ parsing info...",
                        submission_material.get_block_number()?
                    );
                    EosEthTokenDictionary::get_from_db(&state.db)
                        .and_then(|token_dictionary| {
                            Erc20OnEosPegInInfos::from_submission_material(
                                &submission_material,
                                &token_dictionary,
                                &get_eth_chain_id_from_db(&state.db)?,
                            )
                        })
                        .and_then(|peg_in_infos| state.add_erc20_on_eos_peg_in_infos(peg_in_infos))
                },
            }
        })
        .and_then(filter_out_zero_value_peg_ins_from_state)
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
pub fn debug_reprocess_eos_block<D>(db: D, block_json: &str) -> Result<String>
where
    D: DatabaseInterface,
{
    info!("✔ Debug reprocessing EOS block...");
    parse_submission_material_and_add_to_state(block_json, EosState::init(db))
        .and_then(check_core_is_initialized_and_return_eos_state)
        .and_then(get_enabled_protocol_features_and_add_to_state)
        .and_then(start_eos_db_transaction_and_return_state)
        .and_then(get_processed_global_sequences_and_add_to_state)
        .and_then(get_eos_eth_token_dictionary_from_db_and_add_to_eos_state)
        .and_then(maybe_add_new_eos_schedule_to_db_and_return_state)
        .and_then(maybe_filter_duplicate_proofs_from_state)
        .and_then(maybe_filter_out_proofs_for_accounts_not_in_token_dictionary)
        .and_then(maybe_filter_out_action_proof_receipt_mismatches_and_return_state)
        .and_then(maybe_filter_out_invalid_action_receipt_digests)
        .and_then(maybe_filter_out_proofs_with_invalid_merkle_proofs)
        .and_then(maybe_filter_out_proofs_with_wrong_action_mroot)
        .and_then(|state| maybe_filter_proofs_for_action_name(state, REDEEM_ACTION_NAME))
        .and_then(maybe_parse_redeem_infos_and_put_in_state)
        .and_then(maybe_sign_normal_eth_txs_and_add_to_state)
        .and_then(maybe_add_global_sequences_to_processed_list_and_return_state)
        .and_then(maybe_increment_eth_nonce_in_db_and_return_eos_state)
        .and_then(end_eos_db_transaction_and_return_state)
        .and_then(get_eos_output)
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Get Processed Actions List
///
/// This function returns the list of already-processed action global sequences in JSON format.
pub fn debug_get_processed_actions_list<D: DatabaseInterface>(db: &D) -> Result<String> {
    check_core_is_initialized(db).and_then(|_| get_processed_actions_list(db))
}

/// Debug Set ETH Gas Price
///
/// This function sets the ETH gas price to use when making ETH transactions. It's unit is `Wei`.
pub fn debug_set_eth_gas_price<D: DatabaseInterface>(db: D, gas_price: u64) -> Result<String> {
    debug_set_eth_gas_price_in_db(&db, gas_price)
}
