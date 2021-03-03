use ethereum_types::Address as EthAddress;
use serde_json::to_string;

use crate::{
    chains::eth::{
        eth_database_utils::{
            get_erc20_on_eos_smart_contract_address_from_db,
            get_erc777_contract_address_from_db,
            get_latest_eth_block_number,
            get_public_eth_address_from_db,
        },
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

    pub fn new_for_eos_on_eth<D: DatabaseInterface>(state: EthState<D>) -> Result<String> {
        let contract_tx = None;
        let contract_address = None;
        Ok(to_string(&Self::init(&state.db, contract_address, contract_tx)?)?)
    }

    pub fn new_for_btc_on_eth<D: DatabaseInterface>(state: EthState<D>) -> Result<String> {
        Ok(to_string(&Self::init(
            &state.db,
            Some(&get_erc777_contract_address_from_db(&state.db)?),
            Some(&state.get_misc_string()?),
        )?)?)
    }

    pub fn new_for_erc20_on_eth<D: DatabaseInterface>(state: EthState<D>) -> Result<String> {
        Ok(to_string(&Self::init(
            &state.db,
            Some(&get_erc20_on_eos_smart_contract_address_from_db(&state.db)?),
            Some(&state.get_misc_string()?),
        )?)?)
    }
}
