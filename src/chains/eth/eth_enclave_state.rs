use ethereum_types::Address as EthAddress;

use crate::{
    chains::eth::{
        eth_constants::ETH_TAIL_LENGTH,
        eth_database_utils::{
            get_any_sender_nonce_from_db,
            get_eos_on_eth_smart_contract_address_from_db,
            get_erc20_on_eos_smart_contract_address_from_db,
            get_erc777_contract_address_from_db,
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
    eth_gas_price: u64,
    eth_chain_id: u8,
    eth_address: String,
    eth_tail_length: u64,
    any_sender_nonce: u64,
    eth_account_nonce: u64,
    eth_linker_hash: String,
    eth_safe_address: String,
    eth_tail_block_hash: String,
    eth_canon_to_tip_length: u64,
    eth_tail_block_number: usize,
    eth_canon_block_hash: String,
    eth_anchor_block_hash: String,
    eth_latest_block_hash: String,
    eth_canon_block_number: usize,
    eth_anchor_block_number: usize,
    eth_latest_block_number: usize,
    smart_contract_address: String,
    erc777_proxy_contract_address: String,
}

impl EthEnclaveState {
    fn new<D: DatabaseInterface>(db: &D, smart_contract_address: &EthAddress) -> Result<Self> {
        info!("✔ Getting ETH enclave state...");
        let eth_tail_block = get_eth_tail_block_from_db(db)?;
        let eth_canon_block = get_eth_canon_block_from_db(db)?;
        let eth_anchor_block = get_eth_anchor_block_from_db(db)?;
        let eth_latest_block = get_eth_latest_block_from_db(db)?;
        Ok(EthEnclaveState {
            eth_tail_length: ETH_TAIL_LENGTH,
            eth_chain_id: get_eth_chain_id_from_db(db)?,
            eth_gas_price: get_eth_gas_price_from_db(db)?,
            any_sender_nonce: get_any_sender_nonce_from_db(db)?,
            eth_account_nonce: get_eth_account_nonce_from_db(db)?,
            eth_safe_address: hex::encode(SAFE_ETH_ADDRESS.as_bytes()),
            eth_linker_hash: hex::encode(get_eth_linker_hash(db)?.as_bytes()),
            eth_canon_to_tip_length: get_eth_canon_to_tip_length_from_db(db)?,
            eth_tail_block_number: eth_tail_block.get_block_number()?.as_usize(),
            eth_canon_block_number: eth_canon_block.get_block_number()?.as_usize(),
            smart_contract_address: hex::encode(smart_contract_address.as_bytes()),
            eth_anchor_block_number: eth_anchor_block.get_block_number()?.as_usize(),
            eth_latest_block_number: eth_latest_block.get_block_number()?.as_usize(),
            eth_address: hex::encode(get_public_eth_address_from_db(db)?.as_bytes()),
            eth_tail_block_hash: hex::encode(eth_tail_block.get_block_hash()?.as_bytes()),
            eth_canon_block_hash: hex::encode(eth_canon_block.get_block_hash()?.as_bytes()),
            eth_anchor_block_hash: hex::encode(eth_anchor_block.get_block_hash()?.as_bytes()),
            eth_latest_block_hash: hex::encode(eth_latest_block.get_block_hash()?.as_bytes()),
            erc777_proxy_contract_address: hex::encode(get_erc777_proxy_contract_address_from_db(db)?),
        })
    }

    pub fn new_for_btc_on_eth<D: DatabaseInterface>(db: &D) -> Result<Self> {
        Self::new(db, &get_erc777_contract_address_from_db(db)?)
    }

    pub fn new_for_erc20_on_eos<D: DatabaseInterface>(db: &D) -> Result<Self> {
        Self::new(db, &get_erc20_on_eos_smart_contract_address_from_db(db)?)
    }

    pub fn new_for_eos_on_eth<D: DatabaseInterface>(db: &D) -> Result<Self> {
        Self::new(db, &get_eos_on_eth_smart_contract_address_from_db(db)?)
    }
}
