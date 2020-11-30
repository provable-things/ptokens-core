use secp256k1::key::ONE_KEY;
use bitcoin::{
    util::key::PrivateKey,
    network::constants::Network,
};
use crate::{
    utils::strip_hex_prefix,
    types::{
        Byte,
        Bytes,
        Result,
    },
    base58::{
        from as from_base58,
        encode_slice as base58_encode_slice,
    },
    chains::{
        eth::eth_utils::{
            convert_bytes_to_u64,
            convert_u64_to_bytes,
        },
        btc::btc_constants::{
            DEFAULT_BTC_SEQUENCE,
            PTOKEN_P2SH_SCRIPT_BYTES,
        },
    },
};
use bitcoin::{
    network::constants::Network as BtcNetwork,
    consensus::encode::serialize as btc_serialize,
    consensus::encode::deserialize as btc_deserialize,
    hashes::{
        Hash,
        sha256d,
    },
    blockdata::{
        opcodes,
        transaction::{
            TxIn as BtcUtxo,
            TxOut as BtcTxOut,
            OutPoint as BtcOutPoint,
            Transaction as BtcTransaction,
        },
        script::{
            Script as BtcScript,
            Builder as BtcScriptBuilder,
        },
    },
};

pub fn convert_hex_to_sha256_hash(hex: &str) -> Result<sha256d::Hash> {
    Ok(sha256d::Hash::from_slice(&hex::decode(strip_hex_prefix(&hex)?)?)?)
}

pub fn get_btc_one_key() -> PrivateKey {
    PrivateKey {
        key: ONE_KEY,
        compressed: false,
        network: Network::Bitcoin,
    }
}

pub fn get_p2sh_redeem_script_sig(
    utxo_spender_pub_key_slice: &[u8],
    eth_address_and_nonce_hash: &sha256d::Hash,
) -> BtcScript {
    info!("✔ Generating `p2sh`'s redeem `script_sig`");
    debug!(
        "✔ Using `eth_address_and_nonce_hash`: {}",
        hex::encode(eth_address_and_nonce_hash)
    );
    debug!(
        "✔ Using `pub key slice`: {}",
        hex::encode(utxo_spender_pub_key_slice)
    );
    BtcScriptBuilder::new()
        .push_slice(&eth_address_and_nonce_hash[..])
        .push_opcode(opcodes::all::OP_DROP)
        .push_slice(&utxo_spender_pub_key_slice)
        .push_opcode(opcodes::all::OP_CHECKSIG)
        .into_script()
}

pub fn get_p2sh_script_sig_from_redeem_script(
    signature_slice: &[u8],
    redeem_script: &BtcScript,
) -> BtcScript {
    BtcScriptBuilder::new()
        .push_slice(&signature_slice)
        .push_slice(redeem_script.as_bytes())
        .into_script()
}

pub fn create_unsigned_utxo_from_tx(tx: &BtcTransaction, output_index: u32) -> BtcUtxo {
    let outpoint = BtcOutPoint {
        txid: tx.txid(),
        vout: output_index,
    };
    BtcUtxo {
        witness: vec![], // NOTE: We don't currently support segwit txs.
        previous_output: outpoint,
        sequence: DEFAULT_BTC_SEQUENCE,
        script_sig: tx
            .output[output_index as usize]
            .script_pubkey
            .clone(),
    }
}

pub fn convert_btc_network_to_bytes(network: BtcNetwork) -> Result<Bytes> {
    match network {
        BtcNetwork::Bitcoin => Ok(convert_u64_to_bytes(0)),
        BtcNetwork::Testnet => Ok(convert_u64_to_bytes(1)),
        BtcNetwork::Regtest=> Ok(convert_u64_to_bytes(2)),
    }
}

pub fn convert_bytes_to_btc_network(bytes: &[Byte]) -> Result<BtcNetwork> {
    match convert_bytes_to_u64(bytes)? {
        1 => Ok(BtcNetwork::Testnet),
        2 => Ok(BtcNetwork::Regtest),
        _ => Ok(BtcNetwork::Bitcoin),
    }
}

pub fn get_hex_tx_from_signed_btc_tx(
    signed_btc_tx: &BtcTransaction
) -> String {
    hex::encode(btc_serialize(signed_btc_tx))
}

pub fn get_script_sig<'a>(
    signature_slice: &'a[u8],
    utxo_spender_pub_key_slice: &'a[u8]
) -> BtcScript {
    let script_builder = BtcScriptBuilder::new();
    script_builder
        .push_slice(&signature_slice)
        .push_slice(&utxo_spender_pub_key_slice)
        .into_script()
}

pub fn create_new_tx_output(value: u64, script: BtcScript) -> Result<BtcTxOut> {
    Ok(BtcTxOut { value, script_pubkey: script })
}

pub fn create_new_pay_to_pub_key_hash_output(
    value: u64,
    recipient: &str,
) -> Result<BtcTxOut> {
    create_new_tx_output(value, get_pay_to_pub_key_hash_script(recipient)?)
}

pub fn calculate_btc_tx_fee(
    num_inputs: usize,
    num_outputs: usize,
    sats_per_byte: u64,
) -> u64 {
    calculate_btc_tx_size(num_inputs, num_outputs) * sats_per_byte
}

// NOTE: Assumes compressed keys and no multi-sigs!
pub fn calculate_btc_tx_size(num_inputs: usize, num_outputs: usize) -> u64 {
    ((num_inputs * (148 + PTOKEN_P2SH_SCRIPT_BYTES)) + (num_outputs * 34) + 10 + num_inputs) as u64
}

pub fn serialize_btc_utxo(btc_utxo: &BtcUtxo) -> Bytes {
    btc_serialize(btc_utxo)
}

pub fn deserialize_btc_utxo(bytes: &[Byte]) -> Result<BtcUtxo> {
    Ok(btc_deserialize(bytes)?)
}

pub fn convert_btc_address_to_bytes(
    btc_address: &str
) -> Result<Bytes> {
    Ok(from_base58(btc_address)?)
}

pub fn convert_bytes_to_btc_address(encoded_bytes: Bytes) -> String {
    base58_encode_slice(&encoded_bytes[..])
}

pub fn convert_btc_address_to_pub_key_hash_bytes(
    btc_address: &str
) -> Result<Bytes> {
    Ok(from_base58(btc_address)?[1..21].to_vec())
}

pub fn get_pay_to_pub_key_hash_script(btc_address: &str) -> Result<BtcScript> {
    let script = BtcScriptBuilder::new();
    Ok(
        script
            .push_opcode(opcodes::all::OP_DUP)
            .push_opcode(opcodes::all::OP_HASH160)
            .push_slice(
                &convert_btc_address_to_pub_key_hash_bytes(btc_address)?[..]
            )
            .push_opcode(opcodes::all::OP_EQUALVERIFY)
            .push_opcode(opcodes::all::OP_CHECKSIG)
            .into_script()
    )
}

pub fn get_btc_tx_id_from_str(tx_id: &str) -> Result<sha256d::Hash> {
    match hex::decode(tx_id) {
        Err(_) => Err("Could not decode tx_id hex string!".into()),
        Ok(bytes) => Ok(sha256d::Hash::from_slice(&bytes)?),
    }
}

#[cfg(test)] // TODO Create then move this to chains/btc_test_utils!
pub fn get_tx_id_from_signed_btc_tx(
    signed_btc_tx: &BtcTransaction
) -> String {
    let mut tx_id = signed_btc_tx
        .txid()
        .to_vec();
    tx_id.reverse();
    hex::encode(tx_id)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use ethereum_types::Address as EthAddress;
    use bitcoin::{
        util::address::Address as BtcAddress,
        hashes::{
            Hash,
            sha256d,
        },
    };
    use crate::{
        chains::btc::{
            utxo_manager::utxo_types::BtcUtxosAndValues,
            btc_test_utils::{
                get_sample_btc_utxo,
                SAMPLE_TRANSACTION_INDEX,
                SAMPLE_TARGET_BTC_ADDRESS,
                SAMPLE_SERIALIZED_BTC_UTXO,
                get_sample_btc_private_key,
                SAMPLE_OUTPUT_INDEX_OF_UTXO,
                get_sample_btc_block_and_id,
                get_sample_testnet_block_and_txs,
                get_sample_p2sh_redeem_script_sig,
                get_sample_op_return_utxo_and_value_n,
                create_op_return_btc_utxo_and_value_from_tx_output,
            },
        },
        btc_on_eth::{
            utils::convert_satoshis_to_ptoken,
            btc::minting_params::{
                BtcOnEthMintingParams,
                BtcOnEthMintingParamStruct,
            },
        },
    };

    #[test]
    fn should_create_new_pay_to_pub_key_hash_output() {
        let expected_script = get_pay_to_pub_key_hash_script(SAMPLE_TARGET_BTC_ADDRESS).unwrap();
        let value = 1;
        let result = create_new_pay_to_pub_key_hash_output(value, SAMPLE_TARGET_BTC_ADDRESS).unwrap();
        assert_eq!(result.value, value);
        assert_eq!(result.script_pubkey, expected_script);
    }

    #[test]
    fn should_create_new_tx_output() {
        let value = 1;
        let script = get_pay_to_pub_key_hash_script(SAMPLE_TARGET_BTC_ADDRESS).unwrap();
        let result = create_new_tx_output(value, script.clone()).unwrap();
        assert_eq!(result.value, value);
        assert_eq!(result.script_pubkey, script);
    }

    #[test]
    fn should_calculate_btc_tx_size() {
        let expected_result = 193;
        let result = calculate_btc_tx_size(1, 1);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_serialize_btc_utxo() {
        let result = hex::encode(serialize_btc_utxo(&get_sample_btc_utxo()));
        assert_eq!(result, SAMPLE_SERIALIZED_BTC_UTXO);
    }

    #[test]
    fn should_deserialize_btc_utxo() {
        let expected_vout = SAMPLE_OUTPUT_INDEX_OF_UTXO;
        let expected_witness_length = 0;
        let expected_sequence = 4294967295;
        let expected_txid = sha256d::Hash::from_str(
            "04bf43a86a99fca519dbfce42566b78cda0895d78c0a07484162d5888f588d0e"
        ).unwrap();
        let serialized_btc_utxo = hex::decode(SAMPLE_SERIALIZED_BTC_UTXO).unwrap();
        let result = deserialize_btc_utxo(&serialized_btc_utxo).unwrap();
        assert_eq!(result.sequence, expected_sequence);
        assert_eq!(result.previous_output.txid, expected_txid);
        assert_eq!(result.previous_output.vout, expected_vout);
        assert_eq!(result.witness.len(), expected_witness_length);
    }

    #[test]
    fn should_convert_btc_address_to_bytes() {
        let expected_result_hex = "6f54102783c8640c5144d039cea53eb7dbb470081462fbafd9";
        let result = convert_btc_address_to_bytes(&SAMPLE_TARGET_BTC_ADDRESS.to_string()).unwrap();
        let result_hex = hex::encode(result);
        assert_eq!(result_hex, expected_result_hex);
    }

    #[test]
    fn should_convert_bytes_to_btc_address() {
        let bytes = convert_btc_address_to_bytes(&SAMPLE_TARGET_BTC_ADDRESS.to_string()).unwrap();
        let result = convert_bytes_to_btc_address(bytes);
        assert_eq!(result, SAMPLE_TARGET_BTC_ADDRESS);
    }

    #[test]
    fn should_convert_btc_address_to_pub_key_hash_bytes() {
        let expected_result = "54102783c8640c5144d039cea53eb7dbb4700814";
        let result = convert_btc_address_to_pub_key_hash_bytes(SAMPLE_TARGET_BTC_ADDRESS).unwrap();
        assert_eq!(hex::encode(result), expected_result);
    }

    #[test]
    fn should_get_pay_to_pub_key_hash_script() {
        let example_script = get_sample_testnet_block_and_txs()
            .unwrap()
            .block
            .txdata[SAMPLE_TRANSACTION_INDEX as usize]
            .output[SAMPLE_OUTPUT_INDEX_OF_UTXO as usize]
            .script_pubkey
            .clone();
        let expected_result = "76a91454102783c8640c5144d039cea53eb7dbb470081488ac";
        let result_script = get_pay_to_pub_key_hash_script(SAMPLE_TARGET_BTC_ADDRESS).unwrap();
        let hex_result = hex::encode(result_script.as_bytes());
        assert!(!result_script.is_p2sh());
        assert!(result_script.is_p2pkh());
        assert_eq!(hex_result, expected_result);
        assert_eq!(result_script, example_script);
    }

    #[test]
    fn should_get_script_sig() {
        let expected_result = "4730440220275e800c20aa5096a49e6c36aae8f532093fc3fdc4a1dd6039314b250efd62300220492fe4b7e27bf555648f023811fb2258bbcd057fd54967f96942cf1f606e4fe7012103d2a5e3b162eb580fe2ce023cd5e0dddbb6286923acde77e3e5468314dc9373f7";
        let hash_type = 1;
        let hash = sha256d::Hash::hash(b"a message");
        let btc_pk = get_sample_btc_private_key();
        let signature = btc_pk.sign_hash_and_append_btc_hash_type(hash.to_vec(), hash_type) .unwrap();
        let pub_key_slice = btc_pk.to_public_key_slice();
        let result_script = get_script_sig(&signature, &pub_key_slice);
        let hex_result = hex::encode(result_script.as_bytes());
        assert_eq!(hex_result, expected_result);
    }

    #[test]
    fn should_get_total_value_of_utxos_and_values() {
        let expected_result = 1942233;
        let utxos = BtcUtxosAndValues::new(vec![
            get_sample_op_return_utxo_and_value_n(2).unwrap(),
            get_sample_op_return_utxo_and_value_n(3).unwrap(),
            get_sample_op_return_utxo_and_value_n(4).unwrap(),
        ]);
        let result = utxos.iter().fold(0, |acc, utxo_and_value| acc + utxo_and_value.value);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_serde_minting_params() {
        let expected_serialization =  vec![
91, 123, 34, 97, 109, 111, 117, 110, 116, 34, 58, 34, 48, 120, 99, 50, 56, 102, 50, 49, 57, 99, 52, 48, 48, 34, 44, 34, 101, 116, 104, 95, 97, 100, 100, 114, 101, 115, 115, 34, 58, 34, 48, 120, 102, 101, 100, 102, 101, 50, 54, 49, 54, 101, 98, 51, 54, 54, 49, 99, 98, 56, 102, 101, 100, 50, 55, 56, 50, 102, 53, 102, 48, 99, 99, 57, 49, 100, 53, 57, 100, 99, 97, 99, 34, 44, 34, 111, 114, 105, 103, 105, 110, 97, 116, 105, 110, 103, 95, 116, 120, 95, 104, 97, 115, 104, 34, 58, 34, 57, 101, 56, 100, 100, 50, 57, 102, 48, 56, 51, 57, 56, 100, 55, 97, 100, 102, 57, 50, 53, 50, 56, 97, 99, 49, 49, 51, 98, 99, 99, 55, 51, 54, 102, 55, 97, 100, 99, 100, 55, 99, 57, 57, 101, 101, 101, 48, 52, 54, 56, 97, 57, 57, 50, 99, 56, 49, 102, 51, 101, 97, 57, 56, 34, 44, 34, 111, 114, 105, 103, 105, 110, 97, 116, 105, 110, 103, 95, 116, 120, 95, 97, 100, 100, 114, 101, 115, 115, 34, 58, 34, 50, 78, 50, 76, 72, 89, 98, 116, 56, 75, 49, 75, 68, 66, 111, 103, 100, 54, 88, 85, 71, 57, 86, 66, 118, 53, 89, 77, 54, 120, 101, 102, 100, 77, 50, 34, 125, 93
                ];
        let amount = convert_satoshis_to_ptoken(1337);
        let originating_tx_address = BtcAddress::from_str("2N2LHYbt8K1KDBogd6XUG9VBv5YM6xefdM2").unwrap();
        let eth_address = EthAddress::from_slice(&hex::decode("fedfe2616eb3661cb8fed2782f5f0cc91d59dcac").unwrap());
        let originating_tx_hash = sha256d::Hash::from_slice(
            &hex::decode("98eaf3812c998a46e0ee997ccdadf736c7bc13c18a5292df7a8d39089fd28d9e").unwrap()
        ).unwrap();
        let minting_param_struct = BtcOnEthMintingParamStruct::new(
            amount,
            hex::encode(eth_address),
            originating_tx_hash,
            originating_tx_address,
        ).unwrap();
        let minting_params = BtcOnEthMintingParams::new(vec![minting_param_struct]);
        let serialized_minting_params = minting_params.to_bytes().unwrap();
        assert_eq!(serialized_minting_params, expected_serialization);
        let deserialized = BtcOnEthMintingParams::from_bytes(&serialized_minting_params).unwrap();
        assert_eq!(deserialized.len(), minting_params.len());
        deserialized
            .iter()
            .enumerate()
            .for_each(|(i, minting_param_struct)| assert_eq!(minting_param_struct, &minting_params[i]));
    }

    #[test]
    fn should_get_p2sh_redeem_script_sig() {
        let result = get_sample_p2sh_redeem_script_sig();
        let result_hex = hex::encode(result.as_bytes());
        let expected_result = "2071a8e55edefe53f703646a679e66799cfef657b98474ff2e4148c3a1ea43169c752103d2a5e3b162eb580fe2ce023cd5e0dddbb6286923acde77e3e5468314dc9373f7ac";
        assert_eq!(result_hex, expected_result);
    }

    #[test]
    fn should_get_p2sh_script_sig_from_redeem_script() {
        let signature_slice = &vec![6u8, 6u8, 6u8][..];
        let redeem_script = get_sample_p2sh_redeem_script_sig();
        let expected_result = "03060606452071a8e55edefe53f703646a679e66799cfef657b98474ff2e4148c3a1ea43169c752103d2a5e3b162eb580fe2ce023cd5e0dddbb6286923acde77e3e5468314dc9373f7ac";
        let result = get_p2sh_script_sig_from_redeem_script(&signature_slice, &redeem_script);
        let result_hex = hex::encode(result.as_bytes());
        assert_eq!(result_hex, expected_result);
    }

    #[test]
    fn should_create_unsigned_utxo_from_tx() {
        let expected_result = "f80c2f7c35f5df8441a5a5b52e2820793fc7e69f4603d38ba7217be41c20691d0000000016001497cfc76442fe717f2a3f0cc9c175f7561b661997ffffffff";
        let index = 0;
        let tx = get_sample_btc_block_and_id().unwrap().block.txdata[0].clone();
        let result = create_unsigned_utxo_from_tx(&tx, index);
        let result_hex = hex::encode(btc_serialize(&result));
        assert_eq!(result_hex, expected_result);
    }

    #[test]
    fn should_create_op_return_btc_utxo_and_value_from_tx_output() {
        let expected_value = 1261602424;
        let expected_utxo = "f80c2f7c35f5df8441a5a5b52e2820793fc7e69f4603d38ba7217be41c20691d0000000016001497cfc76442fe717f2a3f0cc9c175f7561b661997ffffffff";
        let index = 0;
        let tx = get_sample_btc_block_and_id().unwrap().block.txdata[0].clone();
        let result = create_op_return_btc_utxo_and_value_from_tx_output(&tx, index);
        assert_eq!(result.maybe_pointer, None);
        assert_eq!(result.value, expected_value);
        assert_eq!(result.maybe_extra_data, None);
        assert_eq!(result.maybe_deposit_info_json, None);
        assert_eq!(hex::encode(result.serialized_utxo), expected_utxo);
    }

    #[test]
    fn should_serde_btc_network_correctly() {
        let network = BtcNetwork::Bitcoin;
        let bytes = convert_btc_network_to_bytes(network).unwrap();
        let result = convert_bytes_to_btc_network(&bytes).unwrap();
        assert_eq!(result, network);
    }
}
