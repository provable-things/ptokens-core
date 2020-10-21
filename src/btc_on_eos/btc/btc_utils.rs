use crate::{
    types::{
        Byte,
        Bytes,
        Result,
    },
    base58::{
        from as from_base58,
        encode_slice as base58_encode_slice,
    },
    utils::{
        convert_bytes_to_u64,
        convert_u64_to_bytes,
    },
    chains::btc::btc_constants::{
        DEFAULT_BTC_SEQUENCE,
        PTOKEN_P2SH_SCRIPT_BYTES,
    },
    btc_on_eos::{
        btc::btc_types::{
            MintingParams,
            MintingParamStruct,
            BtcBlockInDbFormat,
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

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedBlockAndId {
    pub id: Bytes,
    pub block: Bytes,
    pub height: Bytes,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SerializedBlockInDbFormat {
    pub id: Bytes,
    pub block: Bytes,
    pub height: Bytes,
    pub extra_data: Bytes,
    pub minting_params: Bytes,
}

impl SerializedBlockInDbFormat {
    pub fn new(
        serialized_id: Bytes,
        serialized_block: Bytes,
        serialized_height: Bytes,
        serialized_extra_data: Bytes,
        serialized_minting_params: Bytes,
    ) -> Self {
        SerializedBlockInDbFormat {
            id: serialized_id,
            block: serialized_block,
            height: serialized_height,
            extra_data: serialized_extra_data,
            minting_params: serialized_minting_params,
        }
    }
}

pub fn get_p2sh_redeem_script_sig(
    utxo_spender_pub_key_slice: &[u8],
    address_and_nonce_hash: &sha256d::Hash,
) -> BtcScript {
    info!("✔ Generating `p2sh`'s redeem `script_sig`");
    debug!("✔ Using `address_and_nonce_hash`: {}", hex::encode(address_and_nonce_hash));
    debug!("✔ Using `pub key slice`: {}", hex::encode(utxo_spender_pub_key_slice));
    BtcScriptBuilder::new()
        .push_slice(&address_and_nonce_hash[..])
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

pub fn serialize_minting_params(
    minting_params: &[MintingParamStruct]
) -> Result<Bytes> {
    Ok(serde_json::to_vec(minting_params)?)
}

pub fn deserialize_minting_params(
    serialized_minting_params: Bytes
) -> Result<MintingParams> {
    Ok(serde_json::from_slice(&serialized_minting_params[..])?)
}

pub fn create_unsigned_utxo_from_tx(
    tx: &BtcTransaction,
    output_index: u32,
) -> BtcUtxo {
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

pub fn serialize_btc_block_in_db_format(
    btc_block_in_db_format: &BtcBlockInDbFormat,
) -> Result<(Bytes, Bytes)> {
    let serialized_id = btc_block_in_db_format.id.to_vec();
    Ok(
        (
            serialized_id.clone(),
            serde_json::to_vec(
                &SerializedBlockInDbFormat::new(
                    serialized_id,
                    btc_serialize(&btc_block_in_db_format.block),
                    convert_u64_to_bytes(btc_block_in_db_format.height),
                    btc_block_in_db_format.extra_data.clone(),
                    serialize_minting_params(
                        &btc_block_in_db_format.minting_params
                    )?,
                )
            )?
        )
    )
}

pub fn deserialize_btc_block_in_db_format(
    serialized_block_in_db_format: &[Byte]
) -> Result<BtcBlockInDbFormat> {
    let serialized_struct: SerializedBlockInDbFormat = serde_json::from_slice(
        &serialized_block_in_db_format
    )?;
    BtcBlockInDbFormat::new(
        convert_bytes_to_u64(&serialized_struct.height)?,
        sha256d::Hash::from_slice(&serialized_struct.id)?,
        deserialize_minting_params(
            serialized_struct.minting_params
        )?,
        btc_deserialize(&serialized_struct.block)?,
        serialized_struct.extra_data,
    )
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
