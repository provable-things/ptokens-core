use ethereum_types::Address as EthAddress;
use serde::{Deserialize, Serialize};

use crate::{
    chains::evm::{
        eth_constants::ETH_TAIL_LENGTH,
        eth_database_utils::{
            get_any_sender_nonce_from_db,
            get_erc777_proxy_contract_address_from_db,
            get_eth_account_nonce_from_db,
            get_eth_anchor_block_from_db,
            get_eth_canon_block_from_db,
            get_eth_canon_to_tip_length_from_db,
            get_eth_chain_id_from_db,
            get_eth_gas_price_from_db,
            get_eth_latest_block_from_db,
            get_eth_tail_block_from_db,
            get_public_eth_address_from_db,
        },
        get_linker_hash::get_linker_hash_or_genesis_hash as get_eth_linker_hash,
    },
    constants::SAFE_ETH_ADDRESS,
    traits::DatabaseInterface,
    types::Result,
};

#[derive(Serialize, Deserialize)]
pub struct EthEnclaveState {
    evm_gas_price: u64,
    evm_chain_id: u8,
    evm_address: String,
    evm_tail_length: u64,
    any_sender_nonce: u64,
    evm_account_nonce: u64,
    evm_linker_hash: String,
    evm_safe_address: String,
    evm_tail_block_hash: String,
    evm_canon_to_tip_length: u64,
    evm_tail_block_number: usize,
    evm_canon_block_hash: String,
    evm_anchor_block_hash: String,
    evm_latest_block_hash: String,
    evm_canon_block_number: usize,
    evm_anchor_block_number: usize,
    evm_latest_block_number: usize,
    smart_contract_address: String,
    erc777_proxy_contract_address: String,
}

impl EthEnclaveState {
    fn new<D: DatabaseInterface>(db: &D, smart_contract_address: &EthAddress) -> Result<Self> {
        info!("✔ Getting ETH enclave state...");
        let evm_tail_block = get_eth_tail_block_from_db(db)?;
        let evm_canon_block = get_eth_canon_block_from_db(db)?;
        let evm_anchor_block = get_eth_anchor_block_from_db(db)?;
        let evm_latest_block = get_eth_latest_block_from_db(db)?;
        Ok(EthEnclaveState {
            evm_tail_length: ETH_TAIL_LENGTH,
            evm_gas_price: get_eth_gas_price_from_db(db)?,
            evm_chain_id: get_eth_chain_id_from_db(db)?.to_u8(),
            any_sender_nonce: get_any_sender_nonce_from_db(db)?,
            evm_account_nonce: get_eth_account_nonce_from_db(db)?,
            evm_safe_address: hex::encode(SAFE_ETH_ADDRESS.as_bytes()),
            evm_linker_hash: hex::encode(get_eth_linker_hash(db)?.as_bytes()),
            evm_canon_to_tip_length: get_eth_canon_to_tip_length_from_db(db)?,
            evm_tail_block_number: evm_tail_block.get_block_number()?.as_usize(),
            evm_canon_block_number: evm_canon_block.get_block_number()?.as_usize(),
            smart_contract_address: hex::encode(smart_contract_address.as_bytes()),
            evm_anchor_block_number: evm_anchor_block.get_block_number()?.as_usize(),
            evm_latest_block_number: evm_latest_block.get_block_number()?.as_usize(),
            evm_address: hex::encode(get_public_eth_address_from_db(db)?.as_bytes()),
            evm_tail_block_hash: hex::encode(evm_tail_block.get_block_hash()?.as_bytes()),
            evm_canon_block_hash: hex::encode(evm_canon_block.get_block_hash()?.as_bytes()),
            evm_anchor_block_hash: hex::encode(evm_anchor_block.get_block_hash()?.as_bytes()),
            evm_latest_block_hash: hex::encode(evm_latest_block.get_block_hash()?.as_bytes()),
            erc777_proxy_contract_address: hex::encode(get_erc777_proxy_contract_address_from_db(db)?),
        })
    }

    pub fn new_for_erc20_on_evm<D: DatabaseInterface>(db: &D) -> Result<Self> {
        Self::new(db, &EthAddress::zero())
    }
}
