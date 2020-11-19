use crate::{
    types::Result,
    traits::DatabaseInterface,
    constants::{
        DEBUG_MODE,
        DB_KEY_PREFIX,
        SAFE_ETH_ADDRESS,
        SAFE_EOS_ADDRESS,
        CORE_IS_VALIDATING,
    },
    erc20_on_eos::check_core_is_initialized::check_core_is_initialized,
    chains::{
        eos::{
            eos_types::EosKnownSchedulesJsons,
            protocol_features::EnabledFeatures,
            eos_crypto::eos_private_key::EosPrivateKey,
            eos_erc20_dictionary::{
                EosErc20Dictionary,
                EosErc20DictionaryJson,
            },
            eos_database_utils::{
                get_eos_chain_id_from_db,
                get_eos_account_nonce_from_db,
                get_eos_known_schedules_from_db,
                get_eos_last_seen_block_id_from_db,
                get_latest_eos_block_number,
                get_eos_enabled_protocol_features_from_db,
            },
        },
        eth::{
            eth_constants::ETH_TAIL_LENGTH,
            get_linker_hash::get_linker_hash_or_genesis_hash as get_eth_linker_hash,
            eth_database_utils::{
                get_eth_gas_price_from_db,
                get_eth_tail_block_from_db,
                get_eth_canon_block_from_db,
                get_eth_latest_block_from_db,
                get_any_sender_nonce_from_db,
                get_eth_anchor_block_from_db,
                get_eth_account_nonce_from_db,
                get_public_eth_address_from_db,
                get_eth_canon_to_tip_length_from_db,
                get_erc20_on_eos_smart_contract_address_from_db,
            },
        },
    },
};


#[derive(Serialize, Deserialize)]
struct EnclaveState {
    debug_mode: bool,
    eth_gas_price: u64,
    eth_address: String,
    eth_tail_length: u64,
    any_sender_nonce: u64,
    db_key_prefix: String,
    eth_account_nonce: u64,
    eth_linker_hash: String,
    core_is_validating: bool,
    eth_safe_address: String,
    eth_tail_block_hash: String,
    eth_tail_block_number: usize,
    eth_canon_block_hash: String,
    eth_anchor_block_hash: String,
    eth_latest_block_hash: String,
    eth_canon_block_number: usize,
    eth_anchor_block_number: usize,
    eth_canon_to_tip_length: u64,
    eth_latest_block_number: usize,
    eth_perc20_on_eos_smart_contract_address: String,
    eos_chain_id: String,
    eos_public_key: String,
    eos_signature_nonce: u64,
    eos_last_seen_block_num: u64,
    eos_last_seen_block_id: String,
    eos_known_schedules: EosKnownSchedulesJsons,
    eos_enabled_protocol_features: EnabledFeatures,
    eos_safe_address: String,
    eos_erc20_dictionary: EosErc20DictionaryJson,
}

pub fn get_enclave_state<D>(
    db: D
) -> Result<String>
    where D: DatabaseInterface
{
    info!("✔ Getting enclave state...");
    check_core_is_initialized(&db)
        .and_then(|_| {
            let eth_tail_block = get_eth_tail_block_from_db(&db)?;
            let eth_canon_block = get_eth_canon_block_from_db(&db)?;
            let eth_anchor_block = get_eth_anchor_block_from_db(&db)?;
            let eth_latest_block = get_eth_latest_block_from_db(&db)?;
            let eos_public_key = EosPrivateKey::get_from_db(&db)?.to_public_key().to_string();
            Ok(serde_json::to_string(
                &EnclaveState {
                    debug_mode: DEBUG_MODE,
                    eth_tail_length: ETH_TAIL_LENGTH,
                    core_is_validating: CORE_IS_VALIDATING,
                    db_key_prefix: DB_KEY_PREFIX.to_string(),
                    eth_gas_price: get_eth_gas_price_from_db(&db)?,
                    any_sender_nonce: get_any_sender_nonce_from_db(&db)?,
                    eth_account_nonce: get_eth_account_nonce_from_db(&db)?,
                    eth_safe_address: hex::encode(SAFE_ETH_ADDRESS.as_bytes()),
                    eth_linker_hash: hex::encode(get_eth_linker_hash(&db)?.as_bytes()),
                    eth_canon_to_tip_length: get_eth_canon_to_tip_length_from_db(&db)?,
                    eth_tail_block_number: eth_tail_block.get_block_number()?.as_usize(),
                    eth_canon_block_number: eth_canon_block.get_block_number()?.as_usize(),
                    eth_anchor_block_number: eth_anchor_block.get_block_number()?.as_usize(),
                    eth_latest_block_number: eth_latest_block.get_block_number()?.as_usize(),
                    eth_address: hex::encode(get_public_eth_address_from_db(&db)?.as_bytes()),
                    eth_tail_block_hash: hex::encode(eth_tail_block.get_block_hash()?.as_bytes()),
                    eth_canon_block_hash: hex::encode(eth_canon_block.get_block_hash()?.as_bytes()),
                    eth_anchor_block_hash: hex::encode(eth_anchor_block.get_block_hash()?.as_bytes()),
                    eth_latest_block_hash: hex::encode(eth_latest_block.get_block_hash()?.as_bytes()),
                    eth_perc20_on_eos_smart_contract_address: hex::encode(
                        get_erc20_on_eos_smart_contract_address_from_db(&db)?
                    ),
                    eos_public_key,
                    eos_chain_id: get_eos_chain_id_from_db(&db)?,
                    eos_safe_address: SAFE_EOS_ADDRESS.to_string(),
                    eos_signature_nonce: get_eos_account_nonce_from_db(&db)?,
                    eos_last_seen_block_num: get_latest_eos_block_number(&db)?,
                    eos_last_seen_block_id: get_eos_last_seen_block_id_from_db(&db)?.to_string(),
                    eos_enabled_protocol_features: get_eos_enabled_protocol_features_from_db(&db)?,
                    eos_known_schedules: EosKnownSchedulesJsons::from_schedules(get_eos_known_schedules_from_db(&db)?),
                    eos_erc20_dictionary: EosErc20Dictionary::get_from_db(&db)?.to_json()?,
                }
            )?)
        })
}
