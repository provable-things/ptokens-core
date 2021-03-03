use crate::{
    chains::eth::{
        core_initialization::{
            eth_core_init_utils::{
                add_eth_block_to_db_and_return_state,
                put_any_sender_nonce_in_db_and_return_state,
                put_canon_to_tip_length_in_db_and_return_state,
                put_eth_account_nonce_in_db_and_return_state,
                put_eth_chain_id_in_db_and_return_state,
                put_eth_gas_price_in_db_and_return_state,
                put_eth_tail_block_hash_in_db_and_return_state,
                remove_receipts_from_block_in_state,
                set_eth_anchor_block_hash_and_return_state,
                set_eth_canon_block_hash_and_return_state,
                set_eth_latest_block_hash_and_return_state,
            },
            generate_eth_address::generate_and_store_eth_address,
            generate_eth_contract_tx::generate_eth_contract_tx_and_put_in_state,
            generate_eth_private_key::generate_and_store_eth_private_key,
        },
        eth_state::EthState,
        eth_submission_material::parse_eth_submission_material_and_put_in_state,
        validate_block_in_state::validate_block_in_state as validate_eth_block_in_state,
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn initialize_eth_core_maybe_with_contract_tx<D: DatabaseInterface>(
    block_json: &str,
    chain_id: u8,
    gas_price: u64,
    canon_to_tip_length: u64,
    maybe_bytecode_path: Option<&str>,
    state: EthState<D>,
) -> Result<EthState<D>> {
    parse_eth_submission_material_and_put_in_state(block_json, state)
        .and_then(validate_eth_block_in_state)
        .and_then(remove_receipts_from_block_in_state)
        .and_then(add_eth_block_to_db_and_return_state)
        .and_then(|state| put_canon_to_tip_length_in_db_and_return_state(canon_to_tip_length, state))
        .and_then(set_eth_anchor_block_hash_and_return_state)
        .and_then(set_eth_latest_block_hash_and_return_state)
        .and_then(set_eth_canon_block_hash_and_return_state)
        .and_then(generate_and_store_eth_private_key)
        .and_then(put_eth_tail_block_hash_in_db_and_return_state)
        .and_then(|state| put_eth_chain_id_in_db_and_return_state(chain_id, state))
        .and_then(|state| put_eth_gas_price_in_db_and_return_state(gas_price, state))
        .and_then(|state| match maybe_bytecode_path {
            Some(_) => put_eth_account_nonce_in_db_and_return_state(state, 1),
            None => put_eth_account_nonce_in_db_and_return_state(state, 0),
        })
        .and_then(put_any_sender_nonce_in_db_and_return_state)
        .and_then(generate_and_store_eth_address)
        .and_then(|state| match maybe_bytecode_path {
            Some(ref path) => generate_eth_contract_tx_and_put_in_state(chain_id, gas_price, path, state),
            None => Ok(state),
        })
}

pub fn initialize_eth_core<D: DatabaseInterface>(
    block_json: &str,
    chain_id: u8,
    gas_price: u64,
    canon_to_tip_length: u64,
    bytecode_path: &str,
    state: EthState<D>,
) -> Result<EthState<D>> {
    info!("✔ Initializing ETH core with contract tx...");
    initialize_eth_core_maybe_with_contract_tx(
        block_json,
        chain_id,
        gas_price,
        canon_to_tip_length,
        Some(bytecode_path),
        state,
    )
}

pub fn initialize_eth_core_with_no_contract_tx<D: DatabaseInterface>(
    block_json: &str,
    chain_id: u8,
    gas_price: u64,
    canon_to_tip_length: u64,
    state: EthState<D>,
) -> Result<EthState<D>> {
    info!("✔ Initializing ETH core with NO contract tx...");
    initialize_eth_core_maybe_with_contract_tx(block_json, chain_id, gas_price, canon_to_tip_length, None, state)
}
