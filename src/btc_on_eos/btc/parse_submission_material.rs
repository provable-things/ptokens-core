use std::str::FromStr;
use bitcoin_hashes::sha256d;
use bitcoin::{
    consensus::encode::deserialize,
    blockdata::{
        block::Block as BtcBlock,
        block::BlockHeader as BtcBlockHeader,
        transaction::Transaction as BtcTransaction,
    },
};
use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::btc::deposit_address_info::{
        DepositInfoList,
        DepositAddressInfo,
        DepositAddressInfoJson,
    },
    btc_on_eos::btc::{
        btc_state::BtcState,
        btc_types::{
            BtcBlockJson,
            BtcBlockAndId,
            SubmissionMaterial,
            SubmissionMaterialJson,
        },
    },
};

fn parse_btc_block_json_to_block_header(
    btc_block_json: BtcBlockJson
) -> Result<BtcBlockHeader> {
    trace!("✔ Parsing `BtcBlockJson` to `BtcBlockHeader`...");
    Ok(
        BtcBlockHeader::new(
            btc_block_json.timestamp,
            btc_block_json.bits,
            btc_block_json.nonce,
            btc_block_json.version,
            sha256d::Hash::from_str(&btc_block_json.merkle_root)?,
            sha256d::Hash::from_str(&btc_block_json.previousblockhash)?,
        )
    )
}

pub fn parse_btc_block_json_to_btc_block(
    json: &SubmissionMaterialJson
) -> Result<BtcBlock> {
    trace!("✔ Parsing `SubmissionMaterialJson` to `BtcBlock`...");
    Ok(
        BtcBlock::new(
            parse_btc_block_json_to_block_header(
                json.block.clone()
            )?,
            convert_hex_txs_to_btc_transactions(
                &json.transactions
            )?
        )
    )
}

pub fn parse_submission_material_to_json(
    submission_material: &str
) -> Result<SubmissionMaterialJson> {
    trace!("✔ Parsing JSON string to `SubmissionMaterialJson`...");
    match serde_json::from_str(submission_material) {
        Ok(json) => Ok(json),
        Err(err) => Err(err.into())
    }
}

fn convert_hex_tx_to_btc_transaction<T: AsRef<[u8]>>(hex: T) -> Result<BtcTransaction> {
    Ok(deserialize::<BtcTransaction>(&hex::decode(hex)?)?)
}

fn convert_hex_txs_to_btc_transactions(
    hex_txs: &[String]
) -> Result<Vec<BtcTransaction>> {
    hex_txs
        .iter()
        .map(convert_hex_tx_to_btc_transaction)
        .collect::<Result<Vec<BtcTransaction>>>()
}

fn parse_deposit_info_jsons_to_deposit_info_list(
    deposit_address_json_list: &[DepositAddressInfoJson]
) -> Result<DepositInfoList> {
    deposit_address_json_list
        .iter()
        .map(DepositAddressInfo::from_json)
        .collect::<Result<DepositInfoList>>()
}

pub fn parse_btc_block_from_submission_material(
    submision_material_json: &SubmissionMaterialJson,
) -> Result<BtcBlockAndId> {
    trace!("✔ Parsing `BtcBlockSAndtxsJson` to `BtcBlockAndId`...");
    Ok(
        BtcBlockAndId {
            height: submision_material_json.block.height,
            id: sha256d::Hash::from_str(&submision_material_json.block.id)?,
            deposit_address_list: parse_deposit_info_jsons_to_deposit_info_list(
                &submision_material_json.deposit_address_list,
            )?,
            block: parse_btc_block_json_to_btc_block(
                submision_material_json
            )?,
        }
    )
}

fn parse_submission_json(
    submission_json: &SubmissionMaterialJson,
) -> Result<SubmissionMaterial> {
    Ok(
        SubmissionMaterial {
            ref_block_num:
                submission_json.ref_block_num,
            ref_block_prefix:
                submission_json.ref_block_prefix,
            block_and_id:
                parse_btc_block_from_submission_material(submission_json)?,
        }
    )
}

pub fn parse_submission_material_and_put_in_state<D>(
    submission_json: &str,
    state: BtcState<D>,
) -> Result<BtcState<D>>
   where D: DatabaseInterface
{
    info!("✔ Parsing BTC submisson material...");
    parse_submission_material_to_json(&submission_json)
        .and_then(|json| parse_submission_json(&json))
        .and_then(|result| state.add_btc_submission_material(result))
}
