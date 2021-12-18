use ethereum_types::Address as EthAddress;
use serde::{Deserialize, Serialize};
use serde_json::to_string;

use crate::{
    chains::evm::{
        eth_database_utils::{get_latest_eth_block_number, get_public_eth_address_from_db},
        eth_state::EthState,
    },
    traits::DatabaseInterface,
    types::Result,
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EthInitializationOutput {
    pub eth_address: String,
    pub eth_latest_block_num: usize,
    pub eth_ptoken_contract_tx: Option<String>,
    pub smart_contract_address: Option<String>,
}

impl EthInitializationOutput {
    fn init<D: DatabaseInterface>(
        db: &D,
        contract_address: Option<&EthAddress>,
        contract_tx: Option<&str>,
    ) -> Result<Self> {
        Ok(Self {
            eth_address: format!("0x{}", hex::encode(get_public_eth_address_from_db(db)?.as_bytes())),
            eth_latest_block_num: get_latest_eth_block_number(db)?,
            eth_ptoken_contract_tx: contract_tx.map(|tx| tx.to_string()),
            smart_contract_address: contract_address.map(|address| format!("0x{}", hex::encode(address))),
        })
    }

    pub fn new_for_erc20_on_evm<D: DatabaseInterface>(state: EthState<D>) -> Result<String> {
        Ok(to_string(&Self::init(
            &state.db,
            Some(&EthAddress::zero()),
            Some(&state.get_misc_string()?),
        )?)?)
    }
}
