use serde_json::json;

use crate::{
    chains::{
        eos::{
            core_initialization::eos_init_utils::{
                generate_and_put_incremerkle_in_db,
                put_eos_latest_block_info_in_db,
                EosInitJson,
            },
            eos_database_utils::{put_eos_account_nonce_in_db, put_eos_schedule_in_db},
            eos_global_sequences::{GlobalSequences, ProcessedGlobalSequences},
            eos_producer_schedule::EosProducerScheduleV2,
        },
        eth::eth_utils::get_eth_address_from_str,
    },
    check_debug_mode::check_debug_mode,
    dictionaries::eos_eth::{EosEthTokenDictionary, EosEthTokenDictionaryEntry},
    traits::DatabaseInterface,
    types::Result,
    utils::prepend_debug_output_marker_to_string,
};

pub fn update_incremerkle<D: DatabaseInterface>(db: &D, init_json: &EosInitJson) -> Result<String> {
    info!("✔ Debug updating blockroot merkle...");
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| put_eos_latest_block_info_in_db(db, &init_json.block))
        .and_then(|_| generate_and_put_incremerkle_in_db(db, &init_json.blockroot_merkle))
        .and_then(|_| db.end_transaction())
        .and(Ok("{debug_update_blockroot_merkle_success:true}".to_string()))
        .map(prepend_debug_output_marker_to_string)
}

pub fn add_new_eos_schedule<D: DatabaseInterface>(db: &D, schedule_json: &str) -> Result<String> {
    info!("✔ Debug adding new EOS schedule...");
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| EosProducerScheduleV2::from_json(schedule_json))
        .and_then(|schedule| put_eos_schedule_in_db(db, &schedule))
        .and_then(|_| db.end_transaction())
        .and(Ok("{debug_adding_eos_schedule_success:true}".to_string()))
        .map(prepend_debug_output_marker_to_string)
}

pub fn add_eos_eth_token_dictionary_entry<D: DatabaseInterface>(
    db: &D,
    dictionary_entry_json_string: &str,
) -> Result<String> {
    info!("✔ Debug adding entry to `EosEthTokenDictionary`...");
    let dictionary = EosEthTokenDictionary::get_from_db(db)?;
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| EosEthTokenDictionaryEntry::from_str(dictionary_entry_json_string))
        .and_then(|entry| dictionary.add_and_update_in_db(entry, db))
        .and_then(|_| db.end_transaction())
        .and(Ok(json!({"adding_dictionary_entry_sucess":true}).to_string()))
        .map(prepend_debug_output_marker_to_string)
}

pub fn remove_eos_eth_token_dictionary_entry<D: DatabaseInterface>(db: &D, eth_address_str: &str) -> Result<String> {
    info!("✔ Debug removing entry from `EosEthTokenDictionary`...");
    let dictionary = EosEthTokenDictionary::get_from_db(db)?;
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| get_eth_address_from_str(eth_address_str))
        .and_then(|eth_address| dictionary.remove_entry_via_eth_address_and_update_in_db(&eth_address, db))
        .and_then(|_| db.end_transaction())
        .and(Ok(json!({"removing_dictionary_entry_sucess":true}).to_string()))
        .map(prepend_debug_output_marker_to_string)
}

pub fn get_processed_actions_list<D: DatabaseInterface>(db: &D) -> Result<String> {
    info!("✔ Debug getting processed actions list...");
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| ProcessedGlobalSequences::get_from_db(db))
        .and_then(|processed_global_sequences| {
            db.end_transaction()?;
            Ok(processed_global_sequences.to_json().to_string())
        })
        .map(prepend_debug_output_marker_to_string)
}

pub fn debug_add_global_sequences_to_processed_list<D: DatabaseInterface>(
    db: &D,
    global_sequences_json: &str,
) -> Result<String> {
    info!("✔ Debug adding global sequences to processed list...");
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| {
            ProcessedGlobalSequences::add_global_sequences_to_list_in_db(
                db,
                &mut GlobalSequences::from_str(global_sequences_json)?,
            )
        })
        .and_then(|_| db.end_transaction())
        .and(Ok(json!({"added_global_sequences_to_processed_list":true}).to_string()))
        .map(prepend_debug_output_marker_to_string)
}

pub fn debug_remove_global_sequences_from_processed_list<D: DatabaseInterface>(
    db: &D,
    global_sequences_json: &str,
) -> Result<String> {
    info!("✔ Debug adding global sequences to processed list...");
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| {
            ProcessedGlobalSequences::remove_global_sequences_from_list_in_db(
                db,
                &GlobalSequences::from_str(global_sequences_json)?,
            )
        })
        .and_then(|_| db.end_transaction())
        .and(Ok(
            json!({"removed_global_sequences_to_processed_list":true}).to_string()
        ))
        .map(prepend_debug_output_marker_to_string)
}

/// # Debug Set EOS Account Nonce
///
/// This function set to the given value EOS account nonce in the encryped database.
pub fn debug_set_eos_account_nonce<D: DatabaseInterface>(db: &D, new_nonce: u64) -> Result<String> {
    info!("✔ Debug setting EOS account nonce...");
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| put_eos_account_nonce_in_db(db, new_nonce))
        .and_then(|_| db.end_transaction())
        .and(Ok(json!({"set_eos_account_nonce":true}).to_string()))
        .map(prepend_debug_output_marker_to_string)
}

#[cfg(all(test, feature = "debug"))]
mod tests {
    use super::*;
    use crate::{chains::eos::eos_database_utils::get_eos_account_nonce_from_db, test_utils::get_test_database};

    #[test]
    fn should_set_eos_account_nonce() {
        let db = get_test_database();
        let nonce = 6;
        put_eos_account_nonce_in_db(&db, nonce).unwrap();
        assert_eq!(get_eos_account_nonce_from_db(&db).unwrap(), nonce);
        let new_nonce = 4;
        debug_set_eos_account_nonce(&db, new_nonce).unwrap();
        assert_eq!(get_eos_account_nonce_from_db(&db).unwrap(), new_nonce);
    }
}
