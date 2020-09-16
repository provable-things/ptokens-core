use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::btc::{
        btc_state::BtcState,
        btc_database_utils::{
            get_btc_address_from_db,
            get_btc_latest_block_number,
        },
    },
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BtcInitializationOutput {
    pub btc_address: String,
    pub btc_latest_block_num: u64,
}

impl BtcInitializationOutput {
    pub fn new(
        btc_address: String,
        btc_latest_block_num: u64,
    ) -> Result<Self> {
        Ok(
            BtcInitializationOutput {
                btc_address,
                btc_latest_block_num,
            }
        )
    }
}

fn json_stringify(
    output: BtcInitializationOutput
) -> Result<String> {
    match serde_json::to_string(&output) {
        Ok(res) => Ok(res),
        Err(err) => Err(err.into())
    }
}

pub fn get_btc_init_output_json<D>(
    state: BtcState<D>
) -> Result<String>
    where D: DatabaseInterface
{
    BtcInitializationOutput::new(
        get_btc_address_from_db(&state.db)?,
        get_btc_latest_block_number(&state.db)?,
    )
        .and_then(json_stringify)
}
