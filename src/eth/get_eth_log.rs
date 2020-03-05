use ethereum_types::{
    Bloom,
    BloomInput,
};
use crate::{
    types::Result,
    eth::eth_types::{
        EthLog,
        EthLogJson,
        EthReceiptJson,
    },
    utils::{
        convert_hex_to_bytes,
        convert_hex_to_address,
        convert_hex_strings_to_h256s,
    },
};

fn calculate_bloom_from_log(log: &EthLog) -> Bloom {
    log.topics
        .iter()
        .fold(
            Bloom::from(BloomInput::Raw(log.address.as_bytes())),
            |mut bloom, topic| {
                bloom.accrue(BloomInput::Raw(topic.as_bytes()));
                bloom
            }
        )
}

fn get_log_from_json(log_json: &EthLogJson) -> Result<EthLog> {
    Ok(
        EthLog {
            address: convert_hex_to_address(log_json.address.clone())?,
            topics: convert_hex_strings_to_h256s(log_json.topics.clone())?,
            data: convert_hex_to_bytes(log_json.data.clone())?,
        }
    )
}

pub fn get_logs_bloom_from_logs(logs: &Vec<EthLog>) -> Result<Bloom> {
    Ok(
        logs
            .iter()
            .fold(Bloom::default(), |mut bloom, log| {
                bloom.accrue_bloom(&calculate_bloom_from_log(log));
                bloom
            })
    )
}

pub fn get_logs_from_receipt_json(
    receipt_json: &EthReceiptJson
) -> Result <Vec<EthLog>> {
    trace!("✔ Parsing logs in receipt...");
    receipt_json
        .logs
        .iter()
        .map(|x| get_log_from_json(x))
        .collect::<Result<Vec<EthLog>>>()
}

#[cfg(test)]
mod tests {
    use hex;
    use super::*;
    use crate::eth::eth_test_utils::{
        get_expected_log,
        SAMPLE_RECEIPT_INDEX,
        get_expected_receipt,
        get_sample_eth_block_and_receipts_json,
    };

    #[test]
    fn should_get_logs_from_receipt_json() {
        let expected_result = get_expected_log();
        let eth_block_and_receipt_json = get_sample_eth_block_and_receipts_json()
            .unwrap();
        let result = get_logs_from_receipt_json(
            &eth_block_and_receipt_json.receipts[SAMPLE_RECEIPT_INDEX]
        ).unwrap();
        assert!(result[0] == expected_result);
    }

    #[test]
    fn should_get_logs_bloom_from_logs_correctly() {
        let receipt = get_expected_receipt();
        let logs = receipt.logs.clone();
        let result = get_logs_bloom_from_logs(&logs).unwrap();
        assert!(result == receipt.logs_bloom);
    }

    #[test]
    fn should_get_log_from_log_json_correctly() {
        let eth_block_and_receipt_json = get_sample_eth_block_and_receipts_json()
            .unwrap();
        let log_json = eth_block_and_receipt_json
            .receipts[SAMPLE_RECEIPT_INDEX]
            .logs[0]
            .clone();
        let result = get_log_from_json(&log_json).unwrap();
        let expected_result = get_expected_log();
        assert!(result == expected_result)
    }

    #[test]
    fn should_get_logs_bloom_from_logs() {
        let expected_bloom = "00000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000010000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000800000000000000000000010000000000000000008000000000000000000000000000000000000000000000200000003000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000020000000";
        let expected_bloom_bytes = &hex::decode(expected_bloom)
            .unwrap()[..];
        let eth_block_and_receipt_json = get_sample_eth_block_and_receipts_json()
            .unwrap();
        let receipt = eth_block_and_receipt_json
            .receipts[SAMPLE_RECEIPT_INDEX]
            .clone();
        let logs = get_logs_from_receipt_json(&receipt)
            .unwrap();
        let result = get_logs_bloom_from_logs(&logs)
            .unwrap();
        assert!(result.as_bytes() == expected_bloom_bytes)
    }
}
