pub use serde_json::{
    json,
    Value as JsonValue,
};
use crate::{
    types::{
        Bytes,
        Result,
    },
    btc_on_eth::eth::{
        parse_eth_block_and_receipts::parse_eth_block_and_receipts_json,
        eth_types::{
            EthLog,
            EthBlock,
            EthReceipt,
            EthBlockAndReceipts,
            EthSignature
        },
    }
};

fn encode_eth_log_as_json(eth_log: &EthLog) -> Result<JsonValue> {
    let topic_strings = eth_log
        .topics
        .iter()
        .map(|topic_hash| format!("0x{}", hex::encode(topic_hash.as_bytes())))
        .collect::<Vec<String>>();
    Ok(
        json!({
            "topics": topic_strings,
            "address": format!(
                "0x{}",
                hex::encode(eth_log.address.as_bytes())
            ),
            "data": format!(
                "0x{}",
                hex::encode(eth_log.data.clone())
            ),
        })
    )
}

fn encode_eth_receipt_as_json(
    eth_receipt: &EthReceipt
) -> Result<JsonValue> {
    let encoded_logs = eth_receipt
        .logs
        .iter()
        .map(encode_eth_log_as_json)
        .collect::<Result<Vec<JsonValue>>>()?;
    Ok(
        json!({
            "logs": encoded_logs,
            "status": eth_receipt.status,
            "gasUsed": eth_receipt.gas_used.as_usize(),
            "blockNumber": eth_receipt.block_number.as_usize(),
            "transactionIndex": eth_receipt.transaction_index.as_usize(),
            "cumulativeGasUsed": eth_receipt.cumulative_gas_used.as_usize(),
            "contractAddress": format!(
                "0x{:x}",
                eth_receipt.contract_address
            ),
            "to": format!(
                "0x{}",
                hex::encode(eth_receipt.to.as_bytes())
            ),
            "from": format!(
                "0x{}",
                hex::encode(eth_receipt.from.as_bytes()),
            ),
            "transactionHash": format!(
                "0x{}",
                hex::encode(
                    eth_receipt.transaction_hash.as_bytes()
                ),
            ),
            "blockHash": format!(
                "0x{}",
                hex::encode(eth_receipt.block_hash.as_bytes()),
            ),
            "logsBloom": format!(
                "0x{}",
                hex::encode(eth_receipt.logs_bloom.as_bytes())
            ),
        })
    )
}

fn encode_eth_block_as_json(
    eth_block: &EthBlock
) -> Result<JsonValue> {
    let encoded_transactions = eth_block
        .transactions
        .iter()
        .map(|tx_hash| format!("0x{}", hex::encode(tx_hash.as_bytes())))
        .collect::<Vec<String>>();
    let encoded_uncles = eth_block
        .uncles
        .iter()
        .map(|uncle_hash| format!("0x{}", hex::encode(uncle_hash.as_bytes())))
        .collect::<Vec<String>>();
    Ok(
        json!({
            "nonce": format!("0x{}", hex::encode(eth_block.nonce.clone())),
            "uncles": encoded_uncles,
            "size": eth_block.size.as_usize(),
            "transactions": encoded_transactions,
            "number": eth_block.number.as_usize(),
            "gasUsed": eth_block.gas_used.as_usize(),
            "gasLimit": eth_block.gas_limit.as_usize(),
            "timestamp": eth_block.timestamp.as_usize(),
            "difficulty": eth_block.difficulty.to_string(),
            "totalDifficulty": eth_block.total_difficulty.to_string(),
            "logsBloom": format!(
                "0x{}",
                hex::encode(eth_block.logs_bloom)
            ),
            "hash": format!(
                "0x{}",
                hex::encode(eth_block.hash.as_bytes())
            ),
            "miner": format!(
                "0x{}",
                hex::encode(eth_block.miner.as_bytes())
            ),
            "extraData": format!(
                "0x{}",
                hex::encode(eth_block.extra_data.clone())
            ),
            "mixHash": format!(
                "0x{}",
                hex::encode(eth_block.mix_hash.as_bytes())
            ),
            "stateRoot": format!(
                "0x{}",
                hex::encode(eth_block.state_root.as_bytes())
            ),
            "parentHash": format!(
                "0x{}",
                hex::encode(eth_block.parent_hash.as_bytes())
            ),
            "sha3Uncles": format!(
                "0x{}",
                hex::encode(eth_block.sha3_uncles.as_bytes())
            ),
            "receiptsRoot": format!(
                "0x{}",
                hex::encode(eth_block.receipts_root.as_bytes())
            ),
            "transactionsRoot": format!(
                "0x{}",
                hex::encode(eth_block.transactions_root.as_bytes())
            ),
        })
    )
}

fn encode_eth_block_and_receipts_as_json(
    eth_block_and_receipts: &EthBlockAndReceipts
) -> Result<JsonValue> {
    let encoded_receipts = eth_block_and_receipts
        .receipts
        .iter()
        .map(encode_eth_receipt_as_json)
        .collect::<Result<Vec<JsonValue>>>()?;
    Ok(
        json!({
            "receipts": encoded_receipts,
            "block": encode_eth_block_as_json(&eth_block_and_receipts.block)?
        })
    )
}

pub fn decode_eth_block_and_receipts_from_json_bytes(
    block_and_receipt_bytes: Bytes
) -> Result<EthBlockAndReceipts> {
    parse_eth_block_and_receipts_json(
        serde_json::from_slice(&block_and_receipt_bytes)?
    )
}

pub fn encode_eth_block_and_receipts_as_json_bytes(
    eth_block_and_receipts: &EthBlockAndReceipts
) -> Result<Bytes> {
    Ok(
        serde_json::to_vec(
            &encode_eth_block_and_receipts_as_json(eth_block_and_receipts)?
        )?
    )
}

pub fn encode_eth_signed_message_as_json(
    message: &str,
    signature: &EthSignature
) -> Result<JsonValue> {
    info!("✔ Encoding eth signed message as json...");
    Ok(json!({
        "message": message,
        "signature": format!("0x{}", hex::encode(&signature[..]))
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc_on_eth::eth::eth_test_utils::{
        get_sample_log_with_desired_topic,
        get_sample_eth_block_and_receipts,
        get_sample_receipt_with_desired_topic,
    };

    #[test]
    fn should_encode_eth_log_as_json() {
        let log = get_sample_log_with_desired_topic();
        if let Err(e) = encode_eth_log_as_json(&log) {
            panic!("Error encoding eth log as json: {}", e)
        }
    }

    #[test]
    fn should_encode_eth_receipt_as_json() {
        let receipt = get_sample_receipt_with_desired_topic();
        if let Err(e) = encode_eth_receipt_as_json(&receipt) {
            panic!("Error encoding eth receipt as json: {}", e)
        }
    }

    #[test]
    fn should_encode_eth_block_as_json() {
        let block = get_sample_eth_block_and_receipts().block;
        if let Err(e) = encode_eth_block_as_json(&block) {
            panic!("Error encoding eth block as json: {}", e)
        }
    }

    #[test]
    fn should_encode_eth_block_and_receipts_as_json() {
        let block_and_receipts = get_sample_eth_block_and_receipts();
        if let Err(e) = encode_eth_block_and_receipts_as_json(
            &block_and_receipts
        ) {
            panic!("Error encoding eth block and receipts as json: {}", e)
        }
    }

    #[test]
    fn should_encode_eth_block_and_receipts_as_json_bytes() {
        let block_and_receipts = get_sample_eth_block_and_receipts();
        if let Err(e) = encode_eth_block_and_receipts_as_json_bytes(
            &block_and_receipts
        ) {
            panic!("Error encoding eth block and receipts as json bytes: {}", e)
        }
    }

    #[test]
    fn should_decode_block_and_recipts_json_correctly() {
        let block_and_receipts = get_sample_eth_block_and_receipts();
        let bytes = encode_eth_block_and_receipts_as_json_bytes(
            &block_and_receipts
        ).unwrap();
        let result = decode_eth_block_and_receipts_from_json_bytes(bytes)
            .unwrap();
        assert_eq!(result.block, block_and_receipts.block);
        block_and_receipts
            .receipts
            .iter()
            .enumerate()
            .map(|(i, receipt)| assert_eq!(receipt, &result.receipts[i]))
            .for_each(drop);
    }

    #[test]
    fn should_encode_eth_signed_message_as_json() {
        let valid_json = json!({
            "message": "Arbitrary message",
            "signature": "0x0000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"
        });

        assert_eq!(
            encode_eth_signed_message_as_json("Arbitrary message", &[0u8; 65]).unwrap(),
            valid_json,
            "✘ Message signature json is invalid!"
        )
    }
}
