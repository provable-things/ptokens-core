use std::str::FromStr;
use bitcoin_hashes::sha256d;
use bitcoin::{
    blockdata::{
        block::Block as BtcBlock,
        block::BlockHeader as BtcBlockHeader,
        transaction::Transaction as BtcTransaction,
    },
    consensus::encode::deserialize,
};
use crate::{
    btc_on_eth::btc::{
        btc_state::BtcState,
        btc_types::BtcBlockAndId,
        parse_submission_material_json::BtcSubmissionMaterialJson,
    },
    chains::btc::deposit_address_info::{
        DepositAddressInfo,
        DepositAddressInfoJson,
        DepositInfoList,
    },
    traits::DatabaseInterface,
    types::Result,
};

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct BtcBlockJson {
    pub bits: u32,
    pub id: String,
    pub nonce: u32,
    pub version: u32,
    pub height: u64,
    pub timestamp: u32,
    pub merkle_root: String,
    pub previousblockhash: String,
}

fn parse_btc_block_json_to_block_header(
    btc_submission_material_json: BtcBlockJson
) -> Result<BtcBlockHeader> {
    trace!("✔ Parsing `BtcBlockJson` to `BtcBlockHeader`...");
    Ok(
        BtcBlockHeader::new(
            btc_submission_material_json.timestamp,
            btc_submission_material_json.bits,
            btc_submission_material_json.nonce,
            btc_submission_material_json.version,
            sha256d::Hash::from_str(&btc_submission_material_json.merkle_root)?,
            sha256d::Hash::from_str(&btc_submission_material_json.previousblockhash)?,
        )
    )
}

pub fn parse_btc_block_and_tx_json_to_struct(
    btc_submission_material_json: &BtcSubmissionMaterialJson
) -> Result<BtcBlockAndId> {
    trace!("✔ Parsing `BtcBlockSAndtxsJson` to `BtcBlockAndId`...");
    Ok(
        BtcBlockAndId {
            height: btc_submission_material_json.block.height,
            id: sha256d::Hash::from_str(&btc_submission_material_json.block.id)?,
            deposit_address_list: parse_deposit_info_jsons_to_deposit_info_list(
                &btc_submission_material_json.deposit_address_list,
            )?,
            block: parse_btc_block_json_to_btc_block(
                btc_submission_material_json
            )?,
        }
    )
}

pub fn parse_btc_block_and_id_and_put_in_state<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface,
{
    parse_btc_block_and_tx_json_to_struct(state.get_btc_submission_json()?)
        .and_then(|result| state.add_btc_block_and_id(result))
}

fn parse_btc_block_json_to_btc_block(
    btc_submission_material_json: &BtcSubmissionMaterialJson
) -> Result<BtcBlock> {
    trace!("✔ Parsing `BtcSubmissionMaterialJson` to `BtcBlock`...");
    Ok(
        BtcBlock::new(
            parse_btc_block_json_to_block_header(
                btc_submission_material_json.block.clone()
            )?,
            convert_hex_txs_to_btc_transactions(
                btc_submission_material_json.transactions.clone()
            )?
        )
    )
}

fn parse_deposit_info_jsons_to_deposit_info_list(
    deposit_address_json_list: &[DepositAddressInfoJson]
) -> Result<DepositInfoList> {
    deposit_address_json_list
        .iter()
        .map(DepositAddressInfo::from_json)
        .collect::<Result<DepositInfoList>>()
}

fn convert_hex_txs_to_btc_transactions(
    hex_txs: Vec<String>
) -> Result<Vec<BtcTransaction>> {
    hex_txs
        .into_iter()
        .map(convert_hex_tx_to_btc_transaction)
        .collect::<Result<Vec<BtcTransaction>>>()
}

fn convert_hex_tx_to_btc_transaction(hex: String) -> Result<BtcTransaction> {
    Ok(deserialize::<BtcTransaction>(&hex::decode(hex)?)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc_on_eth::btc::btc_test_utils::{
        get_sample_btc_submission_material_json,
    };

    #[test]
    fn should_parse_block_and_tx_json_to_struct() {
        let json = get_sample_btc_submission_material_json()
            .unwrap();
        if let Err(e) = parse_btc_block_and_tx_json_to_struct(&json) {
            panic!("Error getting json from btc block and txs sample: {}", e);
        }
    }

    #[test]
    fn should_not_panic_deserializing_tx() {
        let tx_bytes = hex::decode("0200000000010117c33a062c8d0c2ce104c9988599f6ba382ff9f786ad48519425e39af23da9880000000000feffffff022c920b00000000001976a914be8a09363cd4719b1c05b2703797ca890b718b5088acf980d30d000000001600147448bbdfe47ec14f27c68393e766567ac7c9c77102473044022073fc2b43d5c5f56d7bc92b47a28db989e04988411721db96fb0eea6689fb83ab022034b7ce2729e867962891fec894210d0faf538b971d3ae9059ebb34358209ec9e012102a51b8eb0eb8ef6b2a421fb1aae3d7308e6cdae165b90f78074c2493af98e3612c43b0900")
            .unwrap();
        if let Err(e) = deserialize::<BtcTransaction>(&tx_bytes) {
            panic!("Error deserializing tx: {}", e);
        }
    }
}
