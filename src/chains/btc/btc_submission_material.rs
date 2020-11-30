pub use bitcoin::{
    hashes::sha256d,
    util::address::Address as BtcAddress,
    consensus::encode::deserialize as btc_deserialize,
    blockdata::{
        block::Block as BtcBlock,
        block::BlockHeader as BtcBlockHeader,
        transaction::Transaction as BtcTransaction,
    },
};
use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::btc::{
        btc_state::BtcState,
        deposit_address_info::DepositAddressInfoJsonList,
        btc_block::{
            BtcBlockJson,
            BtcBlockAndId,
        },
    },
};

pub fn parse_btc_submission_json_and_put_in_state<D>(
    json_str: &str,
    state: BtcState<D>,
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Parsing BTC submission json and adding to state...");
    BtcSubmissionMaterialJson::from_str(&json_str).and_then(|result| state.add_btc_submission_json(result))
}

pub fn parse_submission_material_and_put_in_state<D: DatabaseInterface>(
    json_str: &str,
    state: BtcState<D>,
) -> Result<BtcState<D>> {
    info!("✔ Parsing BTC submisson material and adding to state...");
    BtcSubmissionMaterial::from_str(&json_str).and_then(|result| state.add_btc_submission_material(result))
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct BtcSubmissionMaterialJson {
    pub block: BtcBlockJson,
    pub any_sender: Option<bool>,
    pub transactions: Vec<String>,
    pub ref_block_num: Option<u16>,
    pub ref_block_prefix: Option<u32>,
    pub deposit_address_list: DepositAddressInfoJsonList,
}

impl BtcSubmissionMaterialJson {
    fn convert_hex_txs_to_btc_transactions(hex_txs: Vec<String>) -> Result<Vec<BtcTransaction>> {
        hex_txs.into_iter().map(Self::convert_hex_tx_to_btc_transaction).collect::<Result<Vec<BtcTransaction>>>()
    }

    fn convert_hex_tx_to_btc_transaction(hex: String) -> Result<BtcTransaction> {
        Ok(btc_deserialize::<BtcTransaction>(&hex::decode(hex)?)?)
    }

    pub fn to_btc_block(&self) -> Result<BtcBlock> {
        info!("✔ Parsing `BtcSubmissionMaterialJson` to `BtcBlock`...");
        Ok(BtcBlock::new(
            self.block.to_block_header()?,
            Self::convert_hex_txs_to_btc_transactions(self.transactions.clone())?,
        ))
    }

    pub fn from_str(string: &str) -> Result<Self> {
        info!("✔ Parsing `BtcSubmissionMaterialJson` from string...");
        match serde_json::from_str(string) {
            Ok(json) => Ok(json),
            Err(err) => Err(err.into())
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BtcSubmissionMaterial {
    pub ref_block_num: Option<u16>,
    pub block_and_id: BtcBlockAndId,
    pub ref_block_prefix: Option<u32>,
}

impl BtcSubmissionMaterial {
    pub fn from_json(json: &BtcSubmissionMaterialJson) -> Result<Self> {
        Ok(Self {
            ref_block_num: json.ref_block_num,
            ref_block_prefix: json.ref_block_prefix,
            block_and_id: BtcBlockAndId::from_json(json)?,
        })
    }

    pub fn from_str(string: &str) -> Result<Self> {
        BtcSubmissionMaterialJson::from_str(string).and_then(|json| Self::from_json(&json))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::btc::btc_test_utils::get_sample_btc_submission_material_json_string;

    #[test]
    fn should_get_submission_material_json_from_str() {
        let string = get_sample_btc_submission_material_json_string();
        let result = BtcSubmissionMaterialJson::from_str(&string);
        assert!(result.is_ok());
    }

    #[test]
    fn should_get_submission_material_from_str() {
        let string = get_sample_btc_submission_material_json_string();
        let result = BtcSubmissionMaterial::from_str(&string);
        assert!(result.is_ok());
    }
}
