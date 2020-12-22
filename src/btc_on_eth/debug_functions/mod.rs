use crate::{
    btc_on_eth::{
        btc::{
            filter_op_return_deposit_txs::filter_op_return_deposit_txs_and_add_to_state,
            get_btc_output_json::get_eth_signed_tx_info_from_eth_txs,
            minting_params::{
                parse_minting_params_from_op_return_deposits_and_add_to_state,
                parse_minting_params_from_p2sh_deposits_and_add_to_state,
            },
            sign_normal_eth_transactions::get_eth_signed_txs,
        },
        check_core_is_initialized::{
            check_core_is_initialized,
            check_core_is_initialized_and_return_btc_state,
            check_core_is_initialized_and_return_eth_state,
        },
        eth::{
            create_btc_transactions::maybe_create_btc_txs_and_add_to_state,
            extract_utxos_from_btc_txs::maybe_extract_btc_utxo_from_btc_tx_in_state,
            get_eth_output_json::{get_btc_signed_tx_info_from_btc_txs, EthOutput},
            increment_btc_nonce::maybe_increment_btc_nonce_in_db_and_return_state,
            save_btc_utxos_to_db::maybe_save_btc_utxos_to_db_and_return_state,
        },
    },
    chains::{
        btc::{
            btc_block::parse_btc_block_and_id_and_put_in_state,
            btc_constants::{get_btc_constants_db_keys, BTC_PRIVATE_KEY_DB_KEY as BTC_KEY},
            btc_database_utils::{end_btc_db_transaction, get_btc_account_nonce_from_db, start_btc_db_transaction},
            btc_state::BtcState,
            btc_submission_material::parse_btc_submission_json_and_put_in_state,
            extract_utxos_from_op_return_txs::maybe_extract_utxos_from_op_return_txs_and_put_in_state,
            extract_utxos_from_p2sh_txs::maybe_extract_utxos_from_p2sh_txs_and_put_in_state,
            filter_minting_params::maybe_filter_out_value_too_low_btc_on_eth_minting_params_in_state,
            filter_p2sh_deposit_txs::filter_p2sh_deposit_txs_and_add_to_state,
            filter_utxos::{filter_out_utxos_extant_in_db_from_state, filter_out_value_too_low_utxos_from_state},
            get_deposit_info_hash_map::get_deposit_info_hash_map_and_put_in_state,
            increment_eth_nonce::maybe_increment_eth_nonce_in_db,
            save_utxos_to_db::maybe_save_utxos_to_db,
            set_flags::set_any_sender_flag_in_state,
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
            validate_btc_merkle_root::validate_btc_merkle_root,
            validate_btc_proof_of_work::validate_proof_of_work_of_btc_block_in_state,
        },
        eth::{
            eth_constants::{get_eth_constants_db_keys, ETH_PRIVATE_KEY_DB_KEY as ETH_KEY},
            eth_contracts::{
                erc777::get_signed_erc777_change_pnetwork_tx,
                erc777_proxy::{
                    get_signed_erc777_proxy_change_pnetwork_by_proxy_tx,
                    get_signed_erc777_proxy_change_pnetwork_tx,
                },
            },
            eth_crypto::eth_transaction::get_signed_minting_tx,
            eth_database_transactions::{
                end_eth_db_transaction_and_return_state,
                start_eth_db_transaction_and_return_state,
            },
            eth_database_utils::{
                get_any_sender_nonce_from_db,
                get_erc777_contract_address_from_db,
                get_erc777_proxy_contract_address_from_db,
                get_eth_account_nonce_from_db,
                get_eth_private_key_from_db,
                get_latest_eth_block_number,
                get_signing_params_from_db,
            },
            eth_network::EthNetwork,
            eth_state::EthState,
            eth_submission_material::parse_eth_submission_material_and_put_in_state,
            filter_receipts_in_state::filter_receipts_for_btc_on_eth_redeem_events_in_state,
            validate_block_in_state::validate_block_in_state,
        },
    },
    check_debug_mode::check_debug_mode,
    constants::{DB_KEY_PREFIX, PRIVATE_KEY_DATA_SENSITIVITY_LEVEL, SUCCESS_JSON},
    debug_database_utils::{get_key_from_db, set_key_in_db_to_value},
    traits::DatabaseInterface,
    types::Result,
    utils::{decode_hex_with_err_msg, prepend_debug_output_marker_to_string, strip_hex_prefix},
};
use ethereum_types::Address as EthAddress;
use serde_json::json;

/// # Debug Get All Db Keys
///
/// This function will return a JSON formatted list of all the database keys used in the encrypted database.
pub fn debug_get_all_db_keys() -> Result<String> {
    check_debug_mode().map(|_| {
        json!({
            "btc": get_btc_constants_db_keys(),
            "eth": get_eth_constants_db_keys(),
            "db-key-prefix": DB_KEY_PREFIX.to_string(),
            "utxo-manager": get_utxo_constants_db_keys(),
        })
        .to_string()
    })
}

/// # Debug Clear All UTXOS
///
/// This function will remove ALL UTXOS from the core's encrypted database
///
/// ### BEWARE:
/// Use with extreme caution, and only if you know exactly what you are doing and why.
pub fn debug_clear_all_utxos<D: DatabaseInterface>(db: &D) -> Result<String> {
    info!("✔ Debug clearing all UTXOs...");
    check_core_is_initialized(db)
        .and_then(|_| check_debug_mode())
        .and_then(|_| db.start_transaction())
        .and_then(|_| clear_all_utxos(db))
        .and_then(|_| db.end_transaction())
        .map(|_| SUCCESS_JSON.to_string())
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Reprocess BTC Block
///
/// This function will take a passed in ETH block submission material and run it through the
/// submission pipeline, signing any signatures for pegins it may find in the block
///
/// ### NOTE:
/// This does not yet work with AnySender type transactions.
///
/// ### BEWARE:
/// If you don't broadcast the transaction outputted from this function, future ETH transactions will
/// fail due to the nonce being too high!
// TODO/FIXME: This doesn't work with AnySender yet!
pub fn debug_reprocess_btc_block<D: DatabaseInterface>(db: D, btc_submission_material_json: &str) -> Result<String> {
    check_debug_mode()
        .and_then(|_| parse_btc_submission_json_and_put_in_state(btc_submission_material_json, BtcState::init(db)))
        .and_then(set_any_sender_flag_in_state)
        .and_then(parse_btc_block_and_id_and_put_in_state)
        .and_then(check_core_is_initialized_and_return_btc_state)
        .and_then(start_btc_db_transaction)
        .and_then(validate_btc_block_header_in_state)
        .and_then(validate_proof_of_work_of_btc_block_in_state)
        .and_then(validate_btc_merkle_root)
        .and_then(get_deposit_info_hash_map_and_put_in_state)
        .and_then(filter_op_return_deposit_txs_and_add_to_state)
        .and_then(filter_p2sh_deposit_txs_and_add_to_state)
        .and_then(parse_minting_params_from_op_return_deposits_and_add_to_state)
        .and_then(parse_minting_params_from_p2sh_deposits_and_add_to_state)
        .and_then(maybe_extract_utxos_from_op_return_txs_and_put_in_state)
        .and_then(maybe_extract_utxos_from_p2sh_txs_and_put_in_state)
        .and_then(filter_out_value_too_low_utxos_from_state)
        .and_then(maybe_save_utxos_to_db)
        .and_then(maybe_filter_out_value_too_low_btc_on_eth_minting_params_in_state)
        .and_then(|state| {
            get_eth_signed_txs(
                &get_signing_params_from_db(&state.db)?,
                &state.btc_on_eth_minting_params,
            )
            .and_then(|signed_txs| state.add_eth_signed_txs(signed_txs))
        })
        .and_then(maybe_increment_eth_nonce_in_db)
        .and_then(|state| {
            let signatures = serde_json::to_string(&match &state.eth_signed_txs {
                None => Ok(vec![]),
                Some(txs) => get_eth_signed_tx_info_from_eth_txs(
                    txs,
                    &state.btc_on_eth_minting_params,
                    get_eth_account_nonce_from_db(&state.db)?,
                    state.use_any_sender_tx_type(),
                    get_any_sender_nonce_from_db(&state.db)?,
                ),
            }?)?;
            info!("✔ BTC signatures: {}", signatures);
            state.add_output_json_string(signatures)
        })
        .and_then(end_btc_db_transaction)
        .map(|state| match state.output_json_string {
            None => "✘ No signatures signed ∴ no output!".to_string(),
            Some(output) => output,
        })
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Reprocess ETH Block
///
/// This function will take a passed in ETH block submission material and run it through the
/// submission pipeline, signing any signatures for pegouts it may find in the block
///
/// ### NOTE:
/// This function will increment the core's ETH nonce, meaning the outputted reports will have a
/// gap in their report IDs!
///
/// ### BEWARE:
/// If you don't broadcast the transaction outputted from this function, ALL future BTC transactions will
/// fail due to the core having an incorret set of UTXOs!
pub fn debug_reprocess_eth_block<D: DatabaseInterface>(db: D, eth_block_json: &str) -> Result<String> {
    check_debug_mode()
        .and_then(|_| parse_eth_submission_material_and_put_in_state(eth_block_json, EthState::init(db)))
        .and_then(check_core_is_initialized_and_return_eth_state)
        .and_then(start_eth_db_transaction_and_return_state)
        .and_then(validate_block_in_state)
        .and_then(filter_receipts_for_btc_on_eth_redeem_events_in_state)
        .and_then(|state| {
            state
                .get_eth_submission_material()
                .and_then(|block| block.get_btc_on_eth_redeem_infos())
                .and_then(|params| state.add_btc_on_eth_redeem_infos(params))
        })
        .and_then(maybe_create_btc_txs_and_add_to_state)
        .and_then(maybe_increment_btc_nonce_in_db_and_return_state)
        .and_then(maybe_extract_btc_utxo_from_btc_tx_in_state)
        .and_then(maybe_save_btc_utxos_to_db_and_return_state)
        .and_then(end_eth_db_transaction_and_return_state)
        .and_then(|state| {
            info!("✔ Getting ETH output json...");
            let output = serde_json::to_string(&EthOutput {
                eth_latest_block_number: get_latest_eth_block_number(&state.db)?,
                btc_signed_transactions: match state.btc_transactions {
                    Some(txs) => get_btc_signed_tx_info_from_btc_txs(
                        get_btc_account_nonce_from_db(&state.db)?,
                        txs,
                        &state.btc_on_eth_redeem_infos,
                    )?,
                    None => vec![],
                },
            })?;
            info!("✔ ETH Output: {}", output);
            Ok(output)
        })
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Set Key in DB to Value
///
/// This function set to the given value a given key in the encryped database.
///
/// ### BEWARE:
/// Only use this if you know exactly what you are doing and why.
pub fn debug_set_key_in_db_to_value<D: DatabaseInterface>(db: D, key: &str, value: &str) -> Result<String> {
    check_debug_mode()
        .and_then(|_| {
            let key_bytes = hex::decode(&key)?;
            let sensitivity = match key_bytes == ETH_KEY.to_vec() || key_bytes == BTC_KEY.to_vec() {
                true => PRIVATE_KEY_DATA_SENSITIVITY_LEVEL,
                false => None,
            };
            set_key_in_db_to_value(db, key, value, sensitivity)
        })
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Get Key From Db
///
/// This function will return the value stored under a given key in the encrypted database.
pub fn debug_get_key_from_db<D: DatabaseInterface>(db: D, key: &str) -> Result<String> {
    check_debug_mode()
        .and_then(|_| {
            let key_bytes = hex::decode(&key)?;
            let sensitivity = match key_bytes == ETH_KEY.to_vec() || key_bytes == BTC_KEY.to_vec() {
                true => PRIVATE_KEY_DATA_SENSITIVITY_LEVEL,
                false => None,
            };
            get_key_from_db(db, key, sensitivity)
        })
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Get All UTXOs
///
/// This function will return a JSON containing all the UTXOs the encrypted database currently has.
pub fn debug_get_all_utxos<D: DatabaseInterface>(db: D) -> Result<String> {
    check_debug_mode()
        .and_then(|_| check_core_is_initialized(&db))
        .and_then(|_| get_all_utxos_as_json_string(&db))
}

/// # Debug Get Signed ERC777 change pNetwork Tx
///
/// This function will create a signed ETH transaction that will change the pNetwork address in
/// the pToken ERC777 contract to the passed in address.
///
/// ### NOTE:
/// This function will increment the core's ETH nonce, meaning the outputted reports will have a
/// gap in their report IDs!
///
/// ### BEWARE:
/// If you don't broadcast the transaction outputted from this function, future ETH transactions will
/// fail due to the nonce being too high!
pub fn debug_get_signed_erc777_change_pnetwork_tx<D>(db: D, new_address: &str) -> Result<String>
where
    D: DatabaseInterface,
{
    check_core_is_initialized(&db)
        .and_then(|_| check_debug_mode())
        .and_then(|_| db.start_transaction())
        .and_then(|_| get_signed_erc777_change_pnetwork_tx(&db, EthAddress::from_slice(&hex::decode(new_address)?)))
        .and_then(|signed_tx_hex| {
            db.end_transaction()?;
            Ok(format!("{{signed_tx:{}}}", signed_tx_hex))
        })
        .map(prepend_debug_output_marker_to_string)
}

fn check_erc777_proxy_address_is_set<D: DatabaseInterface>(db: &D) -> Result<()> {
    info!("✔ Checking if the ERC777 proxy address is set...");
    check_debug_mode()
        .and_then(|_| get_erc777_proxy_contract_address_from_db(db))
        .and_then(|address| match address.is_zero() {
            true => Err("✘ No ERC777 proxy address set in db - not signing tx!".into()),
            false => Ok(()),
        })
}

/// # Debug Get Signed ERC777 change pNetwork Tx
///
/// This function will create a signed ETH transaction that will change the pNetwork address in
/// the pToken ERC777 proxy contract to the passed in address.
///
/// ### NOTE:
/// This function will increment the core's ETH nonce, meaning the outputted reports will have a
/// gap in their report IDs!
///
/// ### BEWARE:
/// If you don't broadcast the transaction outputted from this function, future ETH transactions will
/// fail due to the nonce being too high!
pub fn debug_get_signed_erc777_proxy_change_pnetwork_tx<D>(db: D, new_address: &str) -> Result<String>
where
    D: DatabaseInterface,
{
    check_core_is_initialized(&db)
        .and_then(|_| check_debug_mode())
        .and_then(|_| check_erc777_proxy_address_is_set(&db))
        .and_then(|_| db.start_transaction())
        .and_then(|_| {
            get_signed_erc777_proxy_change_pnetwork_tx(&db, EthAddress::from_slice(&hex::decode(new_address)?))
        })
        .and_then(|signed_tx_hex| {
            db.end_transaction()?;
            Ok(format!("{{signed_tx:{}}}", signed_tx_hex))
        })
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Get Signed ERC777 change pNetwork By Proxy Tx
///
/// This function will create a signed ETH transaction that will change the pNetwork address in
/// the pToken ERC777 contract via the ERC777 proxy contract, to the passed in address.
///
/// ### NOTE:
/// This function will increment the core's ETH nonce, meaning the outputted reports will have a
/// gap in their report IDs!
///
/// ### BEWARE:
/// If you don't broadcast the transaction outputted from this function, future ETH transactions will
/// fail due to the nonce being too high!
pub fn debug_get_signed_erc777_proxy_change_pnetwork_by_proxy_tx<D>(db: D, new_address: &str) -> Result<String>
where
    D: DatabaseInterface,
{
    check_core_is_initialized(&db)
        .and_then(|_| check_debug_mode())
        .and_then(|_| check_erc777_proxy_address_is_set(&db))
        .and_then(|_| db.start_transaction())
        .and_then(|_| {
            get_signed_erc777_proxy_change_pnetwork_by_proxy_tx(&db, EthAddress::from_slice(&hex::decode(new_address)?))
        })
        .and_then(|signed_tx_hex| {
            db.end_transaction()?;
            Ok(format!("{{signed_tx:{}}}", signed_tx_hex))
        })
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Maybe Add UTXO To DB
///
/// This function accepts as its param BTC submission material, in which it inspects all the
/// transactions looking for any pertaining to the core's own public key, or deposit addresses
/// derived from it. Any it finds it will extract the UTXO from and add it to the encrypted
/// database.
///
/// ### NOTE:
/// The core won't accept UTXOs it already has in its encrypted database.
pub fn debug_maybe_add_utxo_to_db<D>(db: D, btc_submission_material_json: &str) -> Result<String>
where
    D: DatabaseInterface,
{
    check_debug_mode()
        .and_then(|_| parse_btc_submission_json_and_put_in_state(btc_submission_material_json, BtcState::init(db)))
        .and_then(set_any_sender_flag_in_state)
        .and_then(parse_btc_block_and_id_and_put_in_state)
        .and_then(check_core_is_initialized_and_return_btc_state)
        .and_then(start_btc_db_transaction)
        .and_then(validate_btc_block_header_in_state)
        .and_then(validate_proof_of_work_of_btc_block_in_state)
        .and_then(validate_btc_merkle_root)
        .and_then(get_deposit_info_hash_map_and_put_in_state)
        .and_then(filter_op_return_deposit_txs_and_add_to_state)
        .and_then(filter_p2sh_deposit_txs_and_add_to_state)
        .and_then(maybe_extract_utxos_from_op_return_txs_and_put_in_state)
        .and_then(maybe_extract_utxos_from_p2sh_txs_and_put_in_state)
        .and_then(filter_out_value_too_low_utxos_from_state)
        .and_then(filter_out_utxos_extant_in_db_from_state)
        .and_then(maybe_save_utxos_to_db)
        .and_then(end_btc_db_transaction)
        .map(|_| SUCCESS_JSON.to_string())
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Mint pBTC
///
/// This fxn simply creates & signs a pBTC minting transaction using the private key from the
/// database. It does __not__ change the database in __any way__, including incrementing the nonce
/// etc.
///
/// ### NOTE:
/// This function will increment the core's ETH nonce, meaning the outputted reports will have a
/// gap in their report IDs!
///
/// ### BEWARE:
/// There is great potential for bricking a running instance when using this, so only use it
/// if you know exactly what you're doing and why!
pub fn debug_mint_pbtc<D: DatabaseInterface>(
    db: D,
    amount: u128,
    nonce: u64,
    eth_network: &str,
    gas_price: u64,
    recipient: &str,
) -> Result<String> {
    check_core_is_initialized(&db)
        .and_then(|_| check_debug_mode())
        .and_then(|_| strip_hex_prefix(&recipient))
        .and_then(|hex_no_prefix| {
            decode_hex_with_err_msg(
                &hex_no_prefix,
                "Could not decode hex for recipient in `debug_mint_pbtc` fxn!",
            )
        })
        .map(|recipient_bytes| EthAddress::from_slice(&recipient_bytes))
        .and_then(|recipient_eth_address| {
            get_signed_minting_tx(
                &amount.into(),
                nonce,
                EthNetwork::from_str(&eth_network)?.to_byte(),
                get_erc777_contract_address_from_db(&db)?,
                gas_price,
                &recipient_eth_address,
                get_eth_private_key_from_db(&db)?,
                None,
                None,
            )
        })
        .map(|signed_tx| {
            json!({
                "nonce": nonce,
                "amount": amount,
                "gas_price": gas_price,
                "recipient": recipient,
                "eth_network": eth_network,
                "signed_tx": signed_tx.serialize_hex(),
            })
            .to_string()
        })
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Get Child-Pays-For-Parent BTC Transaction
///
/// This function attempts to find the UTXO via the passed in transaction hash and vOut values, and
/// upon success creates a transaction spending that UTXO, sending it entirely to itself minus the
/// passed in fee.
///
/// ### BEWARE:
/// This function spends UTXOs and outputs the signed transactions. If the output trnsaction is NOT
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
