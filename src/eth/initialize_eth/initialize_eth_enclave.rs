use crate::{
    types::Result,
    traits::DatabaseInterface,
    eth::{
        eth_state::EthState,
        eth_database_utils::{
            end_eth_db_transaction,
            start_eth_db_transaction,
        },
        parse_eth_block_and_receipts::{
            parse_eth_block_and_receipts_and_put_in_state,
        },
        validate_block::{
            validate_block_in_state as validate_eth_block_in_state,
        },
        initialize_eth::{
            is_eth_initialized::is_eth_enclave_initialized,
            get_eth_init_output_json::get_eth_init_output_json,
            generate_eth_address::generate_and_store_eth_address,
            generate_eth_private_key::generate_and_store_eth_private_key,
            generate_eth_contract_tx::generate_eth_contract_tx_and_put_in_state,
            generate_eth_contract_address::{
                generate_and_store_eth_contract_address
            },
            eth_init_utils::{
                remove_receipts_from_block_in_state,
                add_eth_block_to_db_and_return_state,
                put_eth_chain_id_in_db_and_return_state,
                put_eth_gas_price_in_db_and_return_state,
                set_eth_canon_block_hash_and_return_state,
                set_eth_anchor_block_hash_and_return_state,
                set_eth_latest_block_hash_and_return_state,
                put_eth_account_nonce_in_db_and_return_state,
                check_for_existence_of_eth_contract_byte_code,
                put_canon_to_tip_length_in_db_and_return_state,
                put_eth_tail_block_hash_in_db_and_return_state,
            },
        },
    },
};

pub fn maybe_initialize_eth_enclave<D>(
    db: D,
    block_json_string: String,
    chain_id: u8,
    gas_price: u64,
    canon_to_tip_length: u64,
) -> Result<String>
    where D: DatabaseInterface
{
    check_for_existence_of_eth_contract_byte_code()
        .map(|_| EthState::init(db))
        .and_then(|state|
            match is_eth_enclave_initialized(&state.db) {
                true => {
                    info!("✔ ETH Enclave already initialized!");
                    Ok("{eth_enclave_initialized:true}".to_string())
                }
                false => {
                    info!("✔ Initializing enclave for ETH...");
                    parse_eth_block_and_receipts_and_put_in_state(
                        block_json_string,
                        state,
                    )
                        .and_then(validate_eth_block_in_state)
                        .and_then(remove_receipts_from_block_in_state)
                        .and_then(start_eth_db_transaction)
                        .and_then(add_eth_block_to_db_and_return_state)
                        .and_then(|state|
                            put_canon_to_tip_length_in_db_and_return_state(
                                canon_to_tip_length,
                                state,
                            )
                        )
                        .and_then(set_eth_anchor_block_hash_and_return_state)
                        .and_then(set_eth_latest_block_hash_and_return_state)
                        .and_then(set_eth_canon_block_hash_and_return_state)
                        .and_then(generate_and_store_eth_private_key)
                        .and_then(put_eth_tail_block_hash_in_db_and_return_state)
                        .and_then(|state|
                            put_eth_chain_id_in_db_and_return_state(
                                chain_id,
                                state,
                            )
                        )
                        .and_then(|state|
                            put_eth_gas_price_in_db_and_return_state(
                                gas_price,
                                state
                            )
                        )
                        .and_then(put_eth_account_nonce_in_db_and_return_state)
                        .and_then(generate_and_store_eth_address)
                        .and_then(generate_and_store_eth_contract_address)
                        .and_then(|state|
                            generate_eth_contract_tx_and_put_in_state(
                                chain_id,
                                gas_price,
                                state,
                            )
                        )
                        .and_then(end_eth_db_transaction)
                        .and_then(get_eth_init_output_json)
                }
            }
        )
}
