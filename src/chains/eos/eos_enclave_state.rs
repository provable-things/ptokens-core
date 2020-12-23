use crate::{
    chains::eos::{
        eos_database_utils::{
            get_eos_account_nonce_from_db,
            get_eos_chain_id_from_db,
            get_eos_enabled_protocol_features_from_db,
            get_eos_known_schedules_from_db,
            get_eos_last_seen_block_id_from_db,
            get_eos_public_key_from_db,
            get_latest_eos_block_number,
        },
        eos_erc20_dictionary::{EosErc20Dictionary, EosErc20DictionaryJson},
        eos_types::EosKnownSchedulesJsons,
        protocol_features::EnabledFeatures,
    },
    constants::SAFE_EOS_ADDRESS,
    traits::DatabaseInterface,
    types::Result,
};

#[derive(Serialize, Deserialize)]
pub struct EosEnclaveState {
    eos_chain_id: String,
    eos_public_key: String,
    eos_safe_address: String,
    eos_signature_nonce: u64,
    eos_last_seen_block_num: u64,
    eos_last_seen_block_id: String,
    eos_known_schedules: EosKnownSchedulesJsons,
    eos_erc20_dictionary: EosErc20DictionaryJson,
    eos_enabled_protocol_features: EnabledFeatures,
}

impl EosEnclaveState {
    pub fn new<D: DatabaseInterface>(db: &D) -> Result<Self> {
        info!("✔ Getting EOS enclave state...");
        Ok(EosEnclaveState {
            eos_chain_id: get_eos_chain_id_from_db(db)?,
            eos_safe_address: SAFE_EOS_ADDRESS.to_string(),
            eos_signature_nonce: get_eos_account_nonce_from_db(db)?,
            eos_last_seen_block_num: get_latest_eos_block_number(db)?,
            eos_public_key: get_eos_public_key_from_db(db)?.to_string(),
            eos_erc20_dictionary: EosErc20Dictionary::get_from_db(db)?.to_json()?,
            eos_last_seen_block_id: get_eos_last_seen_block_id_from_db(db)?.to_string(),
            eos_enabled_protocol_features: get_eos_enabled_protocol_features_from_db(db)?,
            eos_known_schedules: EosKnownSchedulesJsons::from_schedules(get_eos_known_schedules_from_db(db)?),
        })
    }
}
