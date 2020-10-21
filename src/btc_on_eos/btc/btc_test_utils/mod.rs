#![cfg(test)]
use std::fs::read_to_string;
use bitcoin::{
    blockdata::transaction::Transaction as BtcTransaction,
    hashes::{
        Hash,
        sha256d,
    },
};
use crate::{
    errors::AppError,
    types::{
        Bytes,
        Result,
    },
    chains::btc::{
        btc_constants::MINIMUM_REQUIRED_SATOSHIS,
        utxo_manager::utxo_types::BtcUtxoAndValue,
        deposit_address_info::DepositAddressInfoJson,
    },
    btc_on_eos::{
        utils::convert_u64_to_8_decimal_eos_asset,
        btc::{
            btc_utils::create_unsigned_utxo_from_tx,
            btc_crypto::btc_private_key::BtcPrivateKey,
            btc_types::{
                MintingParams,
                BtcBlockAndId,
                MintingParamStruct,
                BtcBlockInDbFormat,
                SubmissionMaterialJson,
            },
            parse_submission_material::{
                parse_submission_material_to_json,
                parse_btc_block_from_submission_material,
            },
        },
    },
};

pub const SAMPLE_TRANSACTION_INDEX: usize = 1;
pub const SAMPLE_OUTPUT_INDEX_OF_UTXO: u32 = 0;

pub const SAMPLE_TARGET_BTC_ADDRESS: &str =
    "moBSQbHn7N9BC9pdtAMnA7GBiALzNMQJyE";

pub const SAMPLE_BTC_BLOCK_JSON_PATH: &str =
    "src/btc_on_eos/btc/btc_test_utils/604700-btc-block-and-txs.json";

pub const SAMPLE_BTC_PRIVATE_KEY_WIF: &str =
    "cP2Dv4mx1DwJzN8iF6CCyPZmuS27bT9MV4Qmgb9h6cNQNq2Jgpmy";

pub const SAMPLE_BTC_PUBLIC_KEY: &str =
    "03d2a5e3b162eb580fe2ce023cd5e0dddbb6286923acde77e3e5468314dc9373f7";

pub const SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH: &str =
    "src/btc_on_eos/btc/btc_test_utils/1610046-testnet-block-with-tx-to-test-address.json";

pub const SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_2: &str =
    "src/btc_on_eos/btc/btc_test_utils/1610166-testnet-block-with-tx-to-test-address.json";

pub const SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_3: &str =
    "src/btc_on_eos/btc/btc_test_utils/1610161-testnet-block-with-tx-to-test-address.json";

pub const SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_5: &str =
    "src/btc_on_eos/btc/btc_test_utils/1637173-testnet-block-and-txs-with-p2sh-deposit.json";

pub const SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_6: &str =
    "src/btc_on_eos/btc/btc_test_utils/1660807-testnet-block-and-txs-with-2-p2sh-deposits.json";

pub const SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_7: &str =
    "src/btc_on_eos/btc/btc_test_utils/btc-1661479-btc-block-and-txs-with-deposit-originating-from-enclave-key.json";

pub const SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_8: &str =
    "src/btc_on_eos/btc/btc_test_utils/1661611-block-and-txs-with-no-op-return.json";

pub const SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_9: &str =
    "src/btc_on_eos/btc/btc_test_utils/1666951-block-and-txs-p2sh-and-op-return-below-threshold.json";

pub const SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_10: &str =
    "src/btc_on_eos/btc/btc_test_utils/btc-1670411-block-and-txs.json";

pub const SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_11: &str =
    "src/btc_on_eos/btc/btc_test_utils/btc-1670534-block-and-txs.json";

pub const SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_12: &str =
    "src/btc_on_eos/btc/btc_test_utils/btc-1670541-block-and-txs.json";

fn get_btc_block_in_db_format(
    btc_block_and_id: BtcBlockAndId,
    minting_params: MintingParams,
    extra_data: Bytes,
) -> Result<BtcBlockInDbFormat> {
    BtcBlockInDbFormat::new(
        btc_block_and_id.height,
        btc_block_and_id.id,
        minting_params,
        btc_block_and_id.block,
        extra_data,
    )
}

pub fn get_sample_btc_pub_key_bytes() -> Bytes {
    hex::decode(SAMPLE_BTC_PUBLIC_KEY).unwrap()
}

pub fn get_sample_minting_params() -> MintingParams {
    let symbol = "PBTC".to_string();
    let originating_tx_address_1 = "eosaccount1x".to_string();
    let originating_tx_address_2 = "eosaccount2x".to_string();
    let originating_tx_address_3 = "eosaccount3x".to_string();
    let eos_address_1 = originating_tx_address_1.clone();
    let eos_address_2 = originating_tx_address_2.clone();
    let eos_address_3 = originating_tx_address_3.clone();
    let amount_1 = convert_u64_to_8_decimal_eos_asset(
        MINIMUM_REQUIRED_SATOSHIS,
        &symbol
    );
    let amount_2 = convert_u64_to_8_decimal_eos_asset(
        MINIMUM_REQUIRED_SATOSHIS + 1,
        &symbol
    );
    let amount_3 = convert_u64_to_8_decimal_eos_asset(
        MINIMUM_REQUIRED_SATOSHIS - 1,
        &symbol
    );
    let originating_tx_hash_1 = sha256d::Hash::hash(b"something_1").to_string();
    let originating_tx_hash_2 = sha256d::Hash::hash(b"something_2").to_string();
    let originating_tx_hash_3 = sha256d::Hash::hash(b"something_3").to_string();
    let minting_params_1 = MintingParamStruct {
        amount: amount_1,
        to: eos_address_1,
        originating_tx_hash: originating_tx_hash_1,
        originating_tx_address: originating_tx_address_1,
    };
    let minting_params_2 = MintingParamStruct {
        amount: amount_2,
        to: eos_address_2,
        originating_tx_hash: originating_tx_hash_2,
        originating_tx_address: originating_tx_address_2,
    };
    let minting_params_3 = MintingParamStruct {
        amount: amount_3,
        to: eos_address_3,
        originating_tx_hash: originating_tx_hash_3,
        originating_tx_address: originating_tx_address_3,
    };
    vec![minting_params_1, minting_params_2, minting_params_3]
}

pub fn get_sample_sequential_btc_blocks_in_db_format(
) -> Vec<BtcBlockInDbFormat> {
    let start_num = 1_611_090;
    let path_prefix = "src/btc_on_eos/btc/btc_test_utils/sequential_block_and_ids/";
    let path_suffix = "-btc-block-and-txs.json";
    let mut paths = Vec::new();
    for i in 0..11 {
        paths.push(
            format!("{}{}{}", path_prefix, start_num + i, path_suffix)
        )
    };
    paths
        .iter()
        .map(|path|
             read_to_string(path).unwrap()
        )
        .map(|json_string|
            parse_submission_material_to_json(&json_string)
                .and_then(|json|
                    parse_btc_block_from_submission_material(&json)
                )
                .and_then(convert_sample_block_to_db_format)
        )
        .collect::<Result<Vec<BtcBlockInDbFormat>>>()
        .unwrap()
}

pub fn convert_sample_block_to_db_format(
    btc_block_and_id: BtcBlockAndId,
) -> Result<BtcBlockInDbFormat> {
    get_btc_block_in_db_format(
        btc_block_and_id,
        Vec::new(),
        Vec::new(),
    )
}

pub fn get_sample_btc_block_json_string() -> String {
    read_to_string(SAMPLE_BTC_BLOCK_JSON_PATH)
        .unwrap()
}

pub fn get_sample_btc_block_json() -> Result<SubmissionMaterialJson> {
    parse_submission_material_to_json(
        &get_sample_btc_block_json_string()
    )
}

pub fn get_sample_btc_block_and_id() -> Result<BtcBlockAndId> {
    parse_btc_block_from_submission_material(
        &get_sample_btc_block_json()
            .unwrap()
    )
}

pub fn get_sample_btc_block_in_db_format() -> Result<BtcBlockInDbFormat> {
    get_sample_btc_block_and_id()
        .and_then(convert_sample_block_to_db_format)
}

pub fn get_sample_testnet_block_and_txs() -> Result<BtcBlockAndId> {
    parse_submission_material_to_json(
        &read_to_string(&SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH).unwrap()
    )
        .and_then(|json| parse_btc_block_from_submission_material(&json))
}

pub fn get_sample_btc_tx() -> BtcTransaction {
    get_sample_testnet_block_and_txs()
        .unwrap()
        .block
        .txdata[SAMPLE_TRANSACTION_INDEX]
        .clone()
}

pub fn get_sample_op_return_utxo_and_value() -> BtcUtxoAndValue {
    create_op_return_btc_utxo_and_value_from_tx_output(
        &get_sample_btc_tx(),
        SAMPLE_OUTPUT_INDEX_OF_UTXO,
    )
}

fn create_op_return_btc_utxo_and_value_from_tx_output(
    tx: &BtcTransaction,
    output_index: u32,
) -> BtcUtxoAndValue {
    BtcUtxoAndValue::new(
        tx.output[output_index as usize].value,
        &create_unsigned_utxo_from_tx(tx, output_index),
        None,
        None,
    )
}

pub fn get_sample_p2sh_utxo_and_value() -> Result<BtcUtxoAndValue> {
    get_sample_btc_block_n(5)
        .and_then(|block_and_id| {
            let output_index = 0;
            let tx = block_and_id.block.txdata[1].clone();
            let nonce = 1337;
            let btc_deposit_address = "2N2LHYbt8K1KDBogd6XUG9VBv5YM6xefdM2".to_string();
            let eth_address = "0xfEDFe2616EB3661CB8FEd2782F5F0cC91D59DCaC".to_string();
            let eth_address_and_nonce_hash = "98eaf3812c998a46e0ee997ccdadf736c7bc13c18a5292df7a8d39089fd28d9e"
                .to_string();
            let version = Some("0".to_string());
            let user_data = vec![];
            let deposit_info_json = DepositAddressInfoJson::new(
                nonce,
                eth_address,
                btc_deposit_address,
                eth_address_and_nonce_hash,
                version,
                &user_data,
            )?;
            Ok(BtcUtxoAndValue::new(
                tx.output[output_index].value,
                &create_unsigned_utxo_from_tx(&tx, output_index as u32),
                Some(deposit_info_json),
                None,
            ))
        })
}

pub fn get_sample_p2sh_utxo_and_value_2() -> Result<BtcUtxoAndValue> {
    get_sample_btc_block_n(10)
        .and_then(|block_and_id| {
            let output_index = 0;
            let tx = block_and_id.block.txdata[50].clone();
            let nonce = 1_584_612_094;
            let btc_deposit_address = "2NB1SRPSujETy9zYbXRZAGkk1zuDZHFAtyk"
                .to_string();
            let eth_address = "provabletest"
                .to_string();
            let eth_address_and_nonce_hash =
            "1729dce0b4e54e39610a95376a8bc96335fd93da68ae6aa27a62d4c282fb1ad3"
                    .to_string();
            let version = Some("1".to_string());
            let user_data = vec![];
            let deposit_info_json = DepositAddressInfoJson::new(
                nonce,
                eth_address,
                btc_deposit_address,
                eth_address_and_nonce_hash,
                version,
                &user_data,
            )?;
            Ok(BtcUtxoAndValue::new(
                tx.output[output_index].value,
                &create_unsigned_utxo_from_tx(&tx, output_index as u32),
                Some(deposit_info_json),
                None,
            ))
        })
}

pub fn get_sample_p2sh_utxo_and_value_3() -> Result<BtcUtxoAndValue> {
    get_sample_btc_block_n(11)
        .map(|block_and_id| {
            let output_index = 0;
            let tx = block_and_id.block.txdata[95].clone();
            let nonce = 1_584_696_514;
            let btc_deposit_address = "2My5iu4S78DRiH9capTKo8sXEa98yHVkQXg"
                .to_string();
            let eth_address = "provabletest"
                .to_string();
            let eth_address_and_nonce_hash =
            "d11539e07a521c78c20381c98cc546e3ccdd8a5c97f1cffe83ae5537f61a6e39"
                .to_string();
            let version = Some("1".to_string());
            let user_data = vec![];
            let deposit_info_json = DepositAddressInfoJson::new(
                nonce,
                eth_address,
                btc_deposit_address,
                eth_address_and_nonce_hash,
                version,
                &user_data,
            ).unwrap();
            BtcUtxoAndValue::new(
                tx.output[output_index].value,
                &create_unsigned_utxo_from_tx(&tx, output_index as u32),
                Some(deposit_info_json),
                None,
            )
        })
}

pub fn get_sample_btc_block_n(n: usize) -> Result<BtcBlockAndId> {
    let block_path = match n {
        2 => Ok(SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_2),
        3 => Ok(SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_3),
        4 => Ok(SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_3),
        5 => Ok(SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_5),
        6 => Ok(SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_6),
        7 => Ok(SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_7),
        8 => Ok(SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_8),
        9 => Ok(SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_9),
        10 => Ok(SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_10),
        11 => Ok(SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_11),
        12 => Ok(SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_12),
        _ => Err(AppError::Custom("✘ Don't have sample for that number!".into()))
    }.unwrap();
    parse_submission_material_to_json(&read_to_string(&block_path)?)
        .and_then(|json| parse_btc_block_from_submission_material(&json))
}

pub fn get_sample_op_return_utxo_and_value_n(n: usize) -> Result<BtcUtxoAndValue> {
    // NOTE: Tuple = path on disk, block_index of utxo & output_index of utxo!
    let tuple = match n {
        2 => Ok((SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_2, 18, 2)),
        3 => Ok((SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_3, 28, 0)),
        4 => Ok((SAMPLE_TESTNET_BTC_BLOCK_JSON_PATH_3, 28, 1)),
        _ => Err(AppError::Custom("✘ Don't have sample for that number!".into()))
    }.unwrap();
    parse_submission_material_to_json(&read_to_string(&tuple.0)?)
        .and_then(|json| parse_btc_block_from_submission_material(&json))
        .map(|block_and_id| block_and_id.block.txdata[tuple.1].clone())
        .map(|tx| create_op_return_btc_utxo_and_value_from_tx_output(&tx, tuple.2))
}

pub fn get_sample_btc_private_key() -> BtcPrivateKey {
    BtcPrivateKey::from_wif(SAMPLE_BTC_PRIVATE_KEY_WIF)
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_get_sample_sequential_block_and_ids() {
        get_sample_sequential_btc_blocks_in_db_format();
    }

    #[test]
    fn should_not_panic_getting_sample_btc_block_string() {
        get_sample_btc_block_json_string();
    }

    #[test]
    fn should_not_panic_getting_sample_btc_block_json() {
        get_sample_btc_block_json()
            .unwrap();
    }

    #[test]
    fn should_not_panic_getting_sample_btc_block() {
        get_sample_btc_block_and_id()
            .unwrap();
    }

    #[test]
    fn should_not_panic_getting_testnet_sample_block() {
        get_sample_testnet_block_and_txs()
            .unwrap();
    }
}
