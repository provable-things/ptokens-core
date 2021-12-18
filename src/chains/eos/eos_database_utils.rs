use std::str::FromStr;

use eos_chain::{AccountName as EosAccountName, Checksum256};

use crate::{
    chains::eos::{
        eos_chain_id::EosChainId,
        eos_constants::{
            EOS_ACCOUNT_NAME_KEY,
            EOS_ACCOUNT_NONCE_KEY,
            EOS_CHAIN_ID_DB_KEY,
            EOS_INCREMERKLE_KEY,
            EOS_LAST_SEEN_BLOCK_ID_KEY,
            EOS_LAST_SEEN_BLOCK_NUM_KEY,
            EOS_PROTOCOL_FEATURES_KEY,
            EOS_PUBLIC_KEY_DB_KEY,
            EOS_SCHEDULE_LIST_KEY,
            EOS_TOKEN_SYMBOL_KEY,
        },
        eos_crypto::eos_public_key::EosPublicKey,
        eos_merkle_utils::{Incremerkle, IncremerkleJson},
        eos_producer_schedule::EosProducerScheduleV2,
        eos_types::EosKnownSchedules,
        eos_utils::{convert_hex_to_checksum256, get_eos_schedule_db_key},
        protocol_features::EnabledFeatures,
    },
    constants::MIN_DATA_SENSITIVITY_LEVEL,
    database_utils::{get_string_from_db, get_u64_from_db, put_string_in_db, put_u64_in_db},
    traits::DatabaseInterface,
    types::Result,
};

pub fn put_eos_public_key_in_db<D: DatabaseInterface>(db: &D, public_key: &EosPublicKey) -> Result<()> {
    debug!("✔ Putting EOS public key in db...");
    db.put(
        EOS_PUBLIC_KEY_DB_KEY.to_vec(),
        public_key.to_bytes(),
        MIN_DATA_SENSITIVITY_LEVEL,
    )
}

pub fn get_eos_public_key_from_db<D: DatabaseInterface>(db: &D) -> Result<EosPublicKey> {
    debug!("✔ Getting EOS public key from db...");
    db.get(EOS_PUBLIC_KEY_DB_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
        .and_then(|bytes| EosPublicKey::from_bytes(&bytes))
}

pub fn put_eos_enabled_protocol_features_in_db<D: DatabaseInterface>(
    db: &D,
    protocol_features: &EnabledFeatures,
) -> Result<()> {
    debug!("✔ Putting EOS enabled protocol features in db...");
    db.put(
        EOS_PROTOCOL_FEATURES_KEY.to_vec(),
        serde_json::to_vec(&protocol_features)?,
        MIN_DATA_SENSITIVITY_LEVEL,
    )
}

pub fn get_eos_enabled_protocol_features_from_db<D: DatabaseInterface>(db: &D) -> Result<EnabledFeatures> {
    debug!("✔ Getting EOS enabled protocol features from db...");
    match db.get(EOS_PROTOCOL_FEATURES_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL) {
        Ok(bytes) => Ok(serde_json::from_slice(&bytes)?),
        Err(_) => {
            info!("✔ No features found in db! Initting empty features...");
            Ok(EnabledFeatures::init())
        },
    }
}

pub fn put_eos_last_seen_block_num_in_db<D: DatabaseInterface>(db: &D, num: u64) -> Result<()> {
    debug!("✔ Putting EOS last seen block num in db...");
    put_u64_in_db(db, &EOS_LAST_SEEN_BLOCK_NUM_KEY.to_vec(), num)
}

pub fn get_latest_eos_block_number<D: DatabaseInterface>(db: &D) -> Result<u64> {
    debug!("✔ Getting EOS latest block number from db...");
    get_u64_from_db(db, &EOS_LAST_SEEN_BLOCK_NUM_KEY.to_vec())
}

pub fn put_eos_last_seen_block_id_in_db<D: DatabaseInterface>(db: &D, latest_block_id: &Checksum256) -> Result<()> {
    let block_id_string = latest_block_id.to_string();
    debug!("✔ Putting EOS latest block ID {} in db...", block_id_string);
    put_string_in_db(db, &EOS_LAST_SEEN_BLOCK_ID_KEY.to_vec(), &block_id_string)
}

pub fn get_eos_last_seen_block_id_from_db<D: DatabaseInterface>(db: &D) -> Result<Checksum256> {
    debug!("✔ Getting EOS last seen block ID from db...");
    get_string_from_db(db, &EOS_LAST_SEEN_BLOCK_ID_KEY.to_vec()).and_then(convert_hex_to_checksum256)
}

pub fn put_incremerkle_in_db<D: DatabaseInterface>(db: &D, incremerkle: &Incremerkle) -> Result<()> {
    debug!("✔ Putting EOS incremerkle in db...");
    db.put(
        EOS_INCREMERKLE_KEY.to_vec(),
        serde_json::to_vec(&incremerkle.to_json())?,
        MIN_DATA_SENSITIVITY_LEVEL,
    )
}

pub fn get_incremerkle_from_db<D: DatabaseInterface>(db: &D) -> Result<Incremerkle> {
    debug!("✔ Getting EOS incremerkle from db...");
    db.get(EOS_INCREMERKLE_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
        .and_then(|bytes| Ok(serde_json::from_slice(&bytes)?))
        .and_then(|json: IncremerkleJson| json.to_incremerkle())
}

pub fn get_eos_known_schedules_from_db<D: DatabaseInterface>(db: &D) -> Result<EosKnownSchedules> {
    debug!("✔ Getting EOS known schedules from db...");
    db.get(EOS_SCHEDULE_LIST_KEY.to_vec(), MIN_DATA_SENSITIVITY_LEVEL)
        .and_then(|bytes| Ok(serde_json::from_slice(&bytes)?))
}

pub fn put_eos_known_schedules_in_db<D: DatabaseInterface>(
    db: &D,
    eos_known_schedules: &EosKnownSchedules,
) -> Result<()> {
    debug!("✔ Putting EOS known schedules in db: {}", &eos_known_schedules);
    db.put(
        EOS_SCHEDULE_LIST_KEY.to_vec(),
        serde_json::to_vec(eos_known_schedules)?,
        MIN_DATA_SENSITIVITY_LEVEL,
    )
}

pub fn put_eos_schedule_in_db<D: DatabaseInterface>(db: &D, schedule: &EosProducerScheduleV2) -> Result<()> {
    let db_key = get_eos_schedule_db_key(schedule.version);
    match db.get(db_key.clone(), MIN_DATA_SENSITIVITY_LEVEL) {
        Ok(_) => {
            trace!("✘ EOS schedule {} already in db!", &schedule.version);
            Ok(())
        },
        Err(_) => {
            trace!("✔ Putting EOS schedule in db: {:?}", schedule);
            put_string_in_db(db, &db_key, &serde_json::to_string(schedule)?)
                .and_then(|_| get_eos_known_schedules_from_db(db))
                .map(|scheds| scheds.add(schedule.version))
                .and_then(|scheds| put_eos_known_schedules_in_db(db, &scheds))
        },
    }
}

pub fn get_eos_schedule_from_db<D: DatabaseInterface>(db: &D, version: u32) -> Result<EosProducerScheduleV2> {
    debug!("✔ Getting EOS schedule from db...");
    match get_string_from_db(db, &get_eos_schedule_db_key(version)) {
        Ok(json) => EosProducerScheduleV2::from_json(&json),
        Err(_) => Err(format!("✘ Core does not have EOS schedule version: {}", version).into()),
    }
}

pub fn get_eos_account_nonce_from_db<D: DatabaseInterface>(db: &D) -> Result<u64> {
    debug!("✔ Getting EOS account nonce from db...");
    get_u64_from_db(db, &EOS_ACCOUNT_NONCE_KEY.to_vec())
}

pub fn put_eos_account_nonce_in_db<D: DatabaseInterface>(db: &D, new_nonce: u64) -> Result<()> {
    debug!("✔ Putting EOS account nonce in db...");
    put_u64_in_db(db, &EOS_ACCOUNT_NONCE_KEY.to_vec(), new_nonce)
}

pub fn put_eos_token_symbol_in_db<D: DatabaseInterface>(db: &D, name: &str) -> Result<()> {
    debug!("✔ Putting EOS token symbol in db...");
    put_string_in_db(db, &EOS_TOKEN_SYMBOL_KEY.to_vec(), name)
}

pub fn get_eos_token_symbol_from_db<D: DatabaseInterface>(db: &D) -> Result<String> {
    debug!("✔ Getting EOS token symbol from db...");
    get_string_from_db(db, &EOS_TOKEN_SYMBOL_KEY.to_vec())
}

pub fn put_eos_account_name_in_db<D: DatabaseInterface>(db: &D, name: &str) -> Result<()> {
    debug!("✔ Putting EOS account name in db...");
    put_string_in_db(db, &EOS_ACCOUNT_NAME_KEY.to_vec(), name)
}

pub fn get_eos_account_name_string_from_db<D: DatabaseInterface>(db: &D) -> Result<String> {
    debug!("✔ Getting EOS account name string from db...");
    get_string_from_db(db, &EOS_ACCOUNT_NAME_KEY.to_vec())
}

pub fn get_eos_account_name_from_db<D: DatabaseInterface>(db: &D) -> Result<EosAccountName> {
    debug!("✔ Getting EOS account name from db...");
    match get_eos_account_name_string_from_db(db) {
        Err(_) => Err("No EOS account name in DB! Did you forget to set it?".into()),
        Ok(ref s) => Ok(EosAccountName::from_str(s)?),
    }
}

pub fn put_eos_chain_id_in_db<D: DatabaseInterface>(db: &D, chain_id: &EosChainId) -> Result<()> {
    debug!("✔ Putting EOS chain ID in db...");
    put_string_in_db(db, &EOS_CHAIN_ID_DB_KEY.to_vec(), &chain_id.to_hex())
}

pub fn get_eos_chain_id_from_db<D: DatabaseInterface>(db: &D) -> Result<EosChainId> {
    info!("✔ Getting EOS chain ID from db...");
    EosChainId::from_str(&get_string_from_db(db, &EOS_CHAIN_ID_DB_KEY.to_vec())?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{chains::eos::eos_test_utils::get_sample_eos_public_key, test_utils::get_test_database};

    #[test]
    fn should_put_and_get_eos_public_key_in_db_correctly() {
        let db = get_test_database();
        let key = get_sample_eos_public_key();
        put_eos_public_key_in_db(&db, &key).unwrap();
        let result = get_eos_public_key_from_db(&db).unwrap();
        assert_eq!(key, result);
    }
}
