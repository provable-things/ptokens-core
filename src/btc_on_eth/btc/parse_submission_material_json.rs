use crate::{
    btc_on_eth::btc::{
        btc_state::BtcState,
        parse_btc_block_and_id::BtcBlockJson,
    },
    chains::btc::deposit_address_info::DepositAddressInfoJsonList,
    traits::DatabaseInterface,
    types::Result,
};

#[derive(Clone, PartialEq, Eq, Debug, Deserialize)]
pub struct BtcSubmissionMaterialJson {
    pub block: BtcBlockJson,
    pub transactions: Vec<String>,
    pub deposit_address_list: DepositAddressInfoJsonList,
    pub any_sender: Option<bool>,
}

pub fn parse_btc_block_string_to_json(
    btc_block_json_string: &str
) -> Result<BtcSubmissionMaterialJson> {
    trace!("✔ Parsing JSON string to `BtcSubmissionMaterialJson`...");
    match serde_json::from_str(btc_block_json_string) {
        Ok(json) => Ok(json),
        Err(err) => Err(err.into())
    }
}

pub fn parse_btc_submission_json_and_put_in_state<D>(
    block_json: &str,
    state: BtcState<D>,
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Parsing BTC submission json...");
    parse_btc_block_string_to_json(&block_json)
        .and_then(|result| state.add_btc_submission_json(result))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc_on_eth::btc::btc_test_utils::{
        get_sample_btc_submission_material_json_string,
    };

    #[test]
    fn should_parse_btc_block_json() {
        let string = get_sample_btc_submission_material_json_string();
        if let Err(e) = parse_btc_block_string_to_json(&string) {
            panic!("Error getting json from btc block and txs sample: {}", e);
        }
    }
}
