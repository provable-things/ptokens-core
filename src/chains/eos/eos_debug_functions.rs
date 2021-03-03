use serde_json::json;

use crate::{
    chains::{
        eos::{
            core_initialization::eos_init_utils::{
                generate_and_put_incremerkle_in_db,
                put_eos_latest_block_info_in_db,
                EosInitJson,
            },
            eos_database_utils::put_eos_schedule_in_db,
            eos_eth_token_dictionary::{EosEthTokenDictionary, EosEthTokenDictionaryEntry},
            eos_global_sequences::{GlobalSequences, ProcessedGlobalSequences},
            parse_eos_schedule::parse_v2_schedule_string_to_v2_schedule,
        },
        eth::eth_utils::get_eth_address_from_str,
    },
    check_debug_mode::check_debug_mode,
    traits::DatabaseInterface,
    types::Result,
    utils::prepend_debug_output_marker_to_string,
};

pub fn update_incremerkle<D: DatabaseInterface>(db: &D, init_json: &EosInitJson) -> Result<String> {
    info!("✔ Debug updating blockroot merkle...");
    check_debug_mode()
        .and_then(|_| put_eos_latest_block_info_in_db(db, &init_json.block))
        .and_then(|_| db.start_transaction())
        .and_then(|_| generate_and_put_incremerkle_in_db(db, &init_json.blockroot_merkle))
        .and_then(|_| db.end_transaction())
        .and(Ok("{debug_update_blockroot_merkle_success:true}".to_string()))
        .map(prepend_debug_output_marker_to_string)
}

pub fn add_new_eos_schedule<D: DatabaseInterface>(db: &D, schedule_json: &str) -> Result<String> {
    info!("✔ Debug adding new EOS schedule...");
    check_debug_mode()
        .and_then(|_| db.start_transaction())
        .and_then(|_| parse_v2_schedule_string_to_v2_schedule(&schedule_json))
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
