use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eth::btc::{
        btc_state::BtcState,
        add_btc_block_to_db::maybe_add_btc_block_to_db,
        validate_btc_merkle_root::validate_btc_merkle_root,
        set_btc_canon_block_hash::maybe_set_btc_canon_block_hash,
        parse_btc_block_and_id::parse_btc_block_and_id_and_put_in_state,
        parse_submission_material_json::parse_btc_submission_json_and_put_in_state,
        set_btc_latest_block_hash::maybe_set_btc_latest_block_hash,
        set_btc_anchor_block_hash::maybe_set_btc_anchor_block_hash,
        validate_btc_block_header::validate_btc_block_header_in_state,
        validate_btc_difficulty::validate_difficulty_of_btc_block_in_state,
        set_flags::set_any_sender_flag_in_state,
        btc_database_utils::{
            end_btc_db_transaction,
            start_btc_db_transaction,
        },
        validate_btc_proof_of_work::{
            validate_proof_of_work_of_btc_block_in_state,
        },
        get_btc_block_in_db_format::{
            create_btc_block_in_db_format_and_put_in_state
        },
        initialize_btc::{
            is_btc_initialized::is_btc_enclave_initialized,
            get_btc_init_output_json::get_btc_init_output_json,
            generate_btc_address::generate_and_store_btc_address,
            generate_btc_private_key::generate_and_store_btc_private_key,
            btc_init_utils::{
                put_difficulty_threshold_in_db,
                put_btc_fee_in_db_and_return_state,
                put_btc_network_in_db_and_return_state,
                put_btc_account_nonce_in_db_and_return_state,
                put_btc_tail_block_hash_in_db_and_return_state,
                put_canon_to_tip_length_in_db_and_return_state,
            },
        }
    },
};

pub fn maybe_initialize_btc_enclave<D>(
    db: D,
    block_json_string: &str,
    fee: u64,
    difficulty: u64,
    network: &str,
    canon_to_tip_length: u64,
) -> Result<String>
    where D: DatabaseInterface
{
    trace!("✔ Maybe initializing BTC enclave...");
    Ok(BtcState::init(db))
        .and_then(|state|
            match is_btc_enclave_initialized(&state.db) {
                true => {
                    info!("✔ BTC enclave already initialized!");
                    Ok("{btc_enclave_initialized:true}".to_string())
                }
                false => {
                    info!("✔ Initializing enclave for BTC...");
                    start_btc_db_transaction(state)
                        .and_then(|state| put_difficulty_threshold_in_db(difficulty, state))
                        .and_then(|state| put_btc_network_in_db_and_return_state(&network, state))
                        .and_then(|state| put_btc_fee_in_db_and_return_state(fee, state))
                        .and_then(|state| parse_btc_submission_json_and_put_in_state(block_json_string, state))
                        .and_then(set_any_sender_flag_in_state)
                        .and_then(parse_btc_block_and_id_and_put_in_state)
                        .and_then(validate_btc_block_header_in_state)
                        .and_then(validate_difficulty_of_btc_block_in_state)
                        .and_then(validate_proof_of_work_of_btc_block_in_state)
                        .and_then(validate_btc_merkle_root)
                        .and_then(|state| put_canon_to_tip_length_in_db_and_return_state(canon_to_tip_length, state))
                        .and_then(maybe_set_btc_anchor_block_hash)
                        .and_then(maybe_set_btc_latest_block_hash)
                        .and_then(maybe_set_btc_canon_block_hash)
                        .and_then(put_btc_tail_block_hash_in_db_and_return_state)
                        .and_then(create_btc_block_in_db_format_and_put_in_state)
                        .and_then(maybe_add_btc_block_to_db)
                        .and_then(put_btc_account_nonce_in_db_and_return_state)
                        .and_then(|state| generate_and_store_btc_private_key(&network, state))
                        .and_then(generate_and_store_btc_address)
                        .and_then(end_btc_db_transaction)
                        .and_then(get_btc_init_output_json)
                }
            }
        )
}
