use crate::{
    types::Result,
    traits::DatabaseInterface,
    constants::{
        DEBUG_MODE,
        DB_KEY_PREFIX,
        CORE_IS_VALIDATING,
    },
    chains::btc::{
        btc_constants::BTC_TAIL_LENGTH,
        utxo_manager::utxo_database_utils::{
            get_utxo_nonce_from_db,
            get_total_utxo_balance_from_db,
            get_total_number_of_utxos_from_db,
        },
    },
    btc_on_eos::{
        check_core_is_initialized::check_core_is_initialized,
        constants::{
            SAFE_EOS_ADDRESS,
            SAFE_BTC_ADDRESS,
        },
        eos::{
            eos_types::EosKnownSchedulesJsons,
            protocol_features::EnabledFeatures,
            eos_crypto::eos_private_key::EosPrivateKey,
            eos_database_utils::{
                get_eos_chain_id_from_db,
                get_eos_token_symbol_from_db,
                get_eos_account_nonce_from_db,
                get_eos_known_schedules_from_db,
                get_eos_last_seen_block_id_from_db,
                get_eos_last_seen_block_num_from_db,
                get_eos_account_name_string_from_db,
                get_eos_enabled_protocol_features_from_db,
            },
        },
        btc::{
            update_btc_linker_hash::{
                get_linker_hash_or_genesis_hash as get_btc_linker_hash,
            },
            btc_database_utils::{
                get_btc_fee_from_db,
                get_btc_network_from_db,
                get_btc_address_from_db,
                get_btc_tail_block_from_db,
                get_btc_difficulty_from_db,
                get_btc_private_key_from_db,
                get_btc_canon_block_from_db,
                get_btc_latest_block_from_db,
                get_btc_anchor_block_from_db,
                get_btc_account_nonce_from_db,
                get_btc_canon_to_tip_length_from_db,
            },
        },
    },
};

#[derive(Serialize, Deserialize)]
struct EnclaveState {
    debug_mode: bool,
    btc_difficulty: u64,
    btc_network: String,
    btc_address: String,
    eos_symbol: String,
    btc_utxo_nonce: u64,
    btc_tail_length: u64,
    db_key_prefix: String,
    eos_chain_id: String,
    btc_sats_per_byte: u64,
    eos_public_key: String,
    btc_public_key: String,
    btc_linker_hash: String,
    btc_signature_nonce: u64,
    eos_signature_nonce: u64,
    core_is_validating: bool,
    eos_account_name: String,
    btc_number_of_utxos: u64,
    btc_utxo_total_value: u64,
    btc_tail_block_number: u64,
    btc_canon_block_number: u64,
    btc_tail_block_hash: String,
    btc_canon_block_hash: String,
    btc_latest_block_number: u64,
    btc_anchor_block_number: u64,
    btc_canon_to_tip_length: u64,
    eos_last_seen_block_num: u64,
    btc_latest_block_hash: String,
    btc_anchor_block_hash: String,
    eos_last_seen_block_id: String,
    eos_known_schedules: EosKnownSchedulesJsons,
    eos_enabled_protocol_features: EnabledFeatures,
    safe_eos_address: String,
    safe_btc_address: String,
}

pub fn get_enclave_state<D>(
    db: D
) -> Result<String>
    where D: DatabaseInterface
{
    info!("✔ Getting core state...");
    check_core_is_initialized(&db)
        .and_then(|_| {
            let btc_tail_block = get_btc_tail_block_from_db(&db)?;
            let btc_canon_block = get_btc_canon_block_from_db(&db)?;
            let btc_anchor_block = get_btc_anchor_block_from_db(&db)?;
            let btc_latest_block = get_btc_latest_block_from_db(&db)?;
            let btc_private_key = get_btc_private_key_from_db(&db)?;
            let eos_public_key = EosPrivateKey::get_from_db(&db)?.to_public_key().to_string();
            let btc_public_key_hex = hex::encode(&btc_private_key.to_public_key_slice().to_vec());
            Ok(serde_json::to_string(
                &EnclaveState {
                    eos_public_key,
                    debug_mode: DEBUG_MODE,
                    btc_tail_length: BTC_TAIL_LENGTH,
                    btc_public_key: btc_public_key_hex,
                    core_is_validating: CORE_IS_VALIDATING,
                    db_key_prefix: DB_KEY_PREFIX.to_string(),
                    btc_address: get_btc_address_from_db(&db)?,
                    eos_chain_id: get_eos_chain_id_from_db(&db)?,
                    btc_tail_block_number: btc_tail_block.height,
                    btc_sats_per_byte: get_btc_fee_from_db(&db)?,
                    btc_utxo_nonce: get_utxo_nonce_from_db(&db)?,
                    eos_symbol: get_eos_token_symbol_from_db(&db)?,
                    safe_btc_address: SAFE_BTC_ADDRESS.to_string(),
                    safe_eos_address: SAFE_EOS_ADDRESS.to_string(),
                    btc_canon_block_number: btc_canon_block.height,
                    btc_latest_block_number: btc_latest_block.height,
                    btc_anchor_block_number: btc_anchor_block.height,
                    btc_difficulty: get_btc_difficulty_from_db(&db)?,
                    btc_tail_block_hash: btc_tail_block.id.to_string(),
                    btc_canon_block_hash: btc_canon_block.id.to_string(),
                    btc_latest_block_hash: btc_latest_block.id.to_string(),
                    btc_anchor_block_hash: btc_anchor_block.id.to_string(),
                    btc_linker_hash: get_btc_linker_hash(&db)?.to_string(),
                    btc_network: get_btc_network_from_db(&db)?.to_string(),
                    eos_signature_nonce: get_eos_account_nonce_from_db(&db)?,
                    btc_signature_nonce: get_btc_account_nonce_from_db(&db)?,
                    btc_utxo_total_value: get_total_utxo_balance_from_db(&db)?,
                    eos_account_name: get_eos_account_name_string_from_db(&db)?,
                    btc_number_of_utxos: get_total_number_of_utxos_from_db(&db)?,
                    btc_canon_to_tip_length: get_btc_canon_to_tip_length_from_db(&db)?,
                    eos_last_seen_block_num: get_eos_last_seen_block_num_from_db(&db)?,
                    eos_last_seen_block_id: get_eos_last_seen_block_id_from_db(&db)?.to_string(),
                    eos_enabled_protocol_features: get_eos_enabled_protocol_features_from_db(&db)?,
                    eos_known_schedules: EosKnownSchedulesJsons::from_schedules(get_eos_known_schedules_from_db(&db)?),
                }
            )?)
        })
}
