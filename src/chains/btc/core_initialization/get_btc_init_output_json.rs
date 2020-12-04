use crate::{
    chains::btc::{
        btc_database_utils::{get_btc_address_from_db, get_latest_btc_block_number},
        btc_state::BtcState,
    },
    traits::DatabaseInterface,
    types::Result,
};
use derive_more::Constructor;

#[derive(Clone, Debug, Serialize, Deserialize, Constructor)]
pub struct BtcInitializationOutput {
    pub btc_address: String,
    pub btc_latest_block_num: u64,
}

fn json_stringify(output: BtcInitializationOutput) -> Result<String> {
    match serde_json::to_string(&output) {
        Ok(res) => Ok(res),
        Err(err) => Err(err.into()),
    }
}

pub fn get_btc_init_output_json<D: DatabaseInterface>(state: BtcState<D>) -> Result<String> {
    json_stringify(BtcInitializationOutput::new(
        get_btc_address_from_db(&state.db)?,
        get_latest_btc_block_number(&state.db)?,
    ))
}
