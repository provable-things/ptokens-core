use crate::{
    chains::eos::{
        check_eos_core_is_initialized::is_eos_core_initialized,
        core_initialization::eos_init_utils::{
            generate_and_put_incremerkle_in_db_and_return_state,
            generate_and_save_eos_keys_and_return_state,
            get_eos_init_output,
            maybe_enable_protocol_features_and_return_state,
            maybe_put_erc20_dictionary_in_db_and_return_state,
            put_empty_processed_tx_ids_in_db_and_return_state,
            put_eos_account_nonce_in_db_and_return_state,
            put_eos_chain_id_in_db_and_return_state,
            put_eos_known_schedule_in_db_and_return_state,
            put_eos_latest_block_info_in_db_and_return_state,
            put_eos_schedule_in_db_and_return_state,
            test_block_validation_and_return_state,
            EosInitJson,
        },
        eos_database_transactions::{
            end_eos_db_transaction_and_return_state,
            start_eos_db_transaction_and_return_state,
        },
        eos_state::EosState,
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn maybe_initialize_eos_core<D>(db: D, chain_id: &str, eos_init_json: &str) -> Result<String>
where
    D: DatabaseInterface,
{
    info!("✔ Maybe initializing EOS core...");
    let init_json = EosInitJson::from_json_string(&eos_init_json)?;
    match is_eos_core_initialized(&db) {
        true => {
            info!("✔ EOS core already initialized!");
            Ok("{eos_core_initialized:true}".to_string())
        },
        false => {
            info!("✔ Initializing core for EOS...");
            start_eos_db_transaction_and_return_state(EosState::init(db))
                .and_then(put_empty_processed_tx_ids_in_db_and_return_state)
                .and_then(|state| put_eos_chain_id_in_db_and_return_state(chain_id, state))
                .and_then(|state| put_eos_known_schedule_in_db_and_return_state(&init_json.active_schedule, state))
                .and_then(|state| put_eos_schedule_in_db_and_return_state(&init_json.active_schedule, state))
                .and_then(|state| put_eos_latest_block_info_in_db_and_return_state(&init_json.block, state))
                .and_then(|state| {
                    generate_and_put_incremerkle_in_db_and_return_state(&init_json.blockroot_merkle, state)
                })
                .and_then(|state| {
                    maybe_enable_protocol_features_and_return_state(&init_json.maybe_protocol_features_to_enable, state)
                })
                .and_then(|state| maybe_put_erc20_dictionary_in_db_and_return_state(&init_json, state))
                .and_then(|state| test_block_validation_and_return_state(&init_json.block, state))
                .and_then(generate_and_save_eos_keys_and_return_state)
                .and_then(put_eos_account_nonce_in_db_and_return_state)
                .and_then(end_eos_db_transaction_and_return_state)
                .and_then(get_eos_init_output)
        },
    }
}
