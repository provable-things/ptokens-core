use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::eth::{
        eth_state::EthState,
        core_initialization::{
            generate_eth_address::generate_and_store_eth_address,
            check_eth_core_is_initialized::is_eth_core_initialized,
            generate_eth_private_key::generate_and_store_eth_private_key,
            get_eth_core_init_output_json::get_eth_core_init_output_json,
            generate_eth_contract_tx::generate_eth_contract_tx_and_put_in_state,
            generate_eth_contract_address::generate_and_store_erc20_on_eos_contract_address,
            eth_core_init_utils::{
                remove_receipts_from_block_in_state,
                add_eth_block_to_db_and_return_state,
                put_eth_chain_id_in_db_and_return_state,
                put_eth_gas_price_in_db_and_return_state,
                set_eth_canon_block_hash_and_return_state,
                set_eth_anchor_block_hash_and_return_state,
                set_eth_latest_block_hash_and_return_state,
                put_any_sender_nonce_in_db_and_return_state,
                put_eth_account_nonce_in_db_and_return_state,
                check_for_existence_of_eth_contract_byte_code,
                put_canon_to_tip_length_in_db_and_return_state,
                put_eth_tail_block_hash_in_db_and_return_state,
            },
        },
        eth_submission_material::parse_eth_submission_material_and_put_in_state,
        validate_block_in_state::validate_block_in_state as validate_eth_block_in_state,
        eth_database_transactions::{
            end_eth_db_transaction_and_return_state,
            start_eth_db_transaction_and_return_state,
        },
    },
};

pub fn maybe_initialize_eth_enclave<D>(
    db: D,
    block_json_string: &str,
    chain_id: u8,
    gas_price: u64,
    canon_to_tip_length: u64,
    bytecode_path: &str,
) -> Result<String>
    where D: DatabaseInterface
{
    check_for_existence_of_eth_contract_byte_code(bytecode_path)
        .map(|_| EthState::init(db))
        .and_then(|state|
            match is_eth_core_initialized(&state.db) {
                true => {
                    info!("✔ ETH Enclave already initialized!");
                    Ok("{eth_enclave_initialized:true}".to_string())
                }
                false => {
                    info!("✔ Initializing enclave for ETH...");
                    parse_eth_submission_material_and_put_in_state(block_json_string, state)
                        .and_then(validate_eth_block_in_state)
                        .and_then(remove_receipts_from_block_in_state)
                        .and_then(start_eth_db_transaction_and_return_state)
                        .and_then(add_eth_block_to_db_and_return_state)
                        .and_then(|state| put_canon_to_tip_length_in_db_and_return_state(canon_to_tip_length, state))
                        .and_then(set_eth_anchor_block_hash_and_return_state)
                        .and_then(set_eth_latest_block_hash_and_return_state)
                        .and_then(set_eth_canon_block_hash_and_return_state)
                        .and_then(generate_and_store_eth_private_key)
                        .and_then(put_eth_tail_block_hash_in_db_and_return_state)
                        .and_then(|state| put_eth_chain_id_in_db_and_return_state(chain_id, state))
                        .and_then(|state| put_eth_gas_price_in_db_and_return_state(gas_price, state))
                        .and_then(put_eth_account_nonce_in_db_and_return_state)
                        .and_then(put_any_sender_nonce_in_db_and_return_state)
                        .and_then(generate_and_store_eth_address)
                        .and_then(generate_and_store_erc20_on_eos_contract_address)
                        .and_then(|state|
                            generate_eth_contract_tx_and_put_in_state(chain_id, gas_price, bytecode_path, state)
                        )
                        .and_then(end_eth_db_transaction_and_return_state)
                        .and_then(get_eth_core_init_output_json)
                }
            }
        )
}
