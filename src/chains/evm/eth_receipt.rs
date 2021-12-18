use std::cmp::Ordering;

use derive_more::{Constructor, Deref, From, Into};
use ethereum_types::{Address as EthAddress, Bloom, H160, H256 as EthHash, U256};
use rlp::RlpStream;
use serde::Deserialize;
use serde_json::{json, Value as JsonValue};

use crate::{
    chains::evm::{
        eth_log::{EthLog, EthLogJson, EthLogs},
        eth_utils::{convert_hex_to_address, convert_hex_to_h256, convert_json_value_to_string},
        nibble_utils::{get_nibbles_from_bytes, Nibbles},
        trie::{put_in_trie_recursively, Trie},
    },
    types::{Bytes, Result},
};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Constructor, Deref, From, Into)]
pub struct EthReceipts(pub Vec<EthReceipt>);

impl EthReceipts {
    pub fn from_jsons(jsons: &[EthReceiptJson]) -> Result<Self> {
        Ok(Self(
            jsons
                .iter()
                .cloned()
                .map(|json| EthReceipt::from_json(&json))
                .collect::<Result<Vec<EthReceipt>>>()?,
        ))
    }

    fn get_receipts_containing_log_from_address(&self, address: &EthAddress) -> Self {
        Self::new(
            self.0
                .iter()
                .filter(|receipt| receipt.contains_log_from_address(address))
                .cloned()
                .collect(),
        )
    }

    fn get_receipts_containing_log_with_topic(&self, topic: &EthHash) -> Self {
        Self::new(
            self.0
                .iter()
                .filter(|receipt| receipt.contains_log_with_topic(topic))
                .cloned()
                .collect(),
        )
    }

    pub fn get_receipts_containing_logs_from_address_and_with_topic(
        &self,
        address: &EthAddress,
        topic: &EthHash,
    ) -> Self {
        self.get_receipts_containing_log_from_address(address)
            .get_receipts_containing_log_with_topic(topic)
    }

    pub fn get_receipts_containing_log_from_address_and_with_topics(
        &self,
        address: &EthAddress,
        topics: &[EthHash],
    ) -> Self {
        Self::new(
            topics
                .iter()
                .map(|topic| {
                    self.get_receipts_containing_logs_from_address_and_with_topic(address, topic)
                        .0
                })
                .collect::<Vec<Vec<EthReceipt>>>()
                .concat(),
        )
    }

    pub fn get_receipts_containing_log_from_addresses_and_with_topics(
        &self,
        addresses: &[EthAddress],
        topics: &[EthHash],
    ) -> Self {
        Self::new(
            addresses
                .iter()
                .map(|address| {
                    self.get_receipts_containing_log_from_address_and_with_topics(address, topics)
                        .0
                })
                .collect::<Vec<Vec<EthReceipt>>>()
                .concat(),
        )
    }

    fn get_logs(&self) -> EthLogs {
        EthLogs::new(
            self.iter()
                .cloned()
                .map(|receipt| receipt.logs.0)
                .collect::<Vec<Vec<EthLog>>>()
                .concat(),
        )
    }

    pub fn get_logs_from_address_with_topic(&self, address: &EthAddress, topic: &EthHash) -> EthLogs {
        self.get_logs()
            .filter_for_those_from_address_containing_topic(address, topic)
    }

    pub fn get_rlp_encoded_receipts_and_nibble_tuples(&self) -> Result<Vec<(Nibbles, Bytes)>> {
        self.0
            .iter()
            .map(|receipt| receipt.get_rlp_encoded_receipt_and_encoded_key_tuple())
            .collect()
    }

    pub fn get_merkle_root(&self) -> Result<EthHash> {
        self.get_rlp_encoded_receipts_and_nibble_tuples()
            .and_then(|key_value_tuples| put_in_trie_recursively(Trie::get_new_trie()?, key_value_tuples, 0))
            .map(|trie| trie.root)
    }
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EthReceiptJson {
    pub from: String,
    pub status: bool,
    pub gas_used: usize,
    pub block_hash: String,
    pub logs_bloom: String,
    pub logs: Vec<EthLogJson>,
    pub block_number: usize,
    pub to: serde_json::Value,
    pub transaction_hash: String,
    pub transaction_index: usize,
    pub cumulative_gas_used: usize,
    pub contract_address: serde_json::Value,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct EthReceipt {
    pub to: EthAddress,
    pub from: EthAddress,
    pub status: bool,
    pub gas_used: U256,
    pub block_hash: EthHash,
    pub transaction_hash: EthHash,
    pub cumulative_gas_used: U256,
    pub block_number: U256,
    pub transaction_index: U256,
    pub contract_address: EthAddress,
    pub logs: EthLogs,
    pub logs_bloom: Bloom,
}

impl EthReceipt {
    pub fn to_json(&self) -> Result<JsonValue> {
        let encoded_logs = self
            .logs
            .0
            .iter()
            .map(|eth_log| eth_log.to_json())
            .collect::<Result<Vec<JsonValue>>>()?;
        Ok(json!({
            "logs": encoded_logs,
            "status": self.status,
            "gasUsed": self.gas_used.as_usize(),
            "blockNumber": self.block_number.as_usize(),
            "transactionIndex": self.transaction_index.as_usize(),
            "to": format!("0x{}", hex::encode(self.to.as_bytes())),
            "cumulativeGasUsed": self.cumulative_gas_used.as_usize(),
            "from": format!("0x{}", hex::encode(self.from.as_bytes())),
            "contractAddress": format!("0x{:x}", self.contract_address),
            "blockHash": format!("0x{}", hex::encode(self.block_hash.as_bytes())),
            "logsBloom": format!("0x{}", hex::encode(self.logs_bloom.as_bytes())),
            "transactionHash": format!("0x{}", hex::encode( self.transaction_hash.as_bytes())),
        }))
    }

    pub fn from_json(eth_receipt_json: &EthReceiptJson) -> Result<Self> {
        let logs = EthLogs::from_receipt_json(eth_receipt_json)?;
        Ok(EthReceipt {
            status: eth_receipt_json.status,
            logs_bloom: logs.get_bloom(),
            gas_used: U256::from(eth_receipt_json.gas_used),
            from: convert_hex_to_address(&eth_receipt_json.from)?,
            block_number: U256::from(eth_receipt_json.block_number),
            block_hash: convert_hex_to_h256(&eth_receipt_json.block_hash)?,
            transaction_index: U256::from(eth_receipt_json.transaction_index),
            cumulative_gas_used: U256::from(eth_receipt_json.cumulative_gas_used),
            transaction_hash: convert_hex_to_h256(&eth_receipt_json.transaction_hash)?,
            to: match eth_receipt_json.to {
                serde_json::Value::Null => H160::zero(),
                _ => convert_hex_to_address(&convert_json_value_to_string(&eth_receipt_json.to)?)?,
            },
            contract_address: match eth_receipt_json.contract_address {
                serde_json::Value::Null => EthAddress::zero(),
                _ => convert_hex_to_address(&convert_json_value_to_string(&eth_receipt_json.contract_address)?)?,
            },
            logs,
        })
    }

    pub fn contains_log_with_topic(&self, topic: &EthHash) -> bool {
        self.logs.contain_topic(topic)
    }

    pub fn contains_log_from_address(&self, address: &EthAddress) -> bool {
        self.logs.contain_address(address)
    }

    pub fn rlp_encode(&self) -> Result<Bytes> {
        let mut rlp_stream = RlpStream::new();
        rlp_stream.begin_list(4);
        match &self.status {
            true => rlp_stream.append(&self.status),
            false => rlp_stream.append_empty_data(),
        };
        rlp_stream
            .append(&self.cumulative_gas_used)
            .append(&self.logs_bloom)
            .append_list(&self.logs);
        Ok(rlp_stream.out().to_vec())
    }

    fn rlp_encode_transaction_index(&self) -> Bytes {
        let mut rlp_stream = RlpStream::new();
        rlp_stream.append(&self.transaction_index.as_usize());
        rlp_stream.out().to_vec()
    }

    pub fn get_rlp_encoded_receipt_and_encoded_key_tuple(&self) -> Result<(Nibbles, Bytes)> {
        self.rlp_encode()
            .map(|bytes| (get_nibbles_from_bytes(self.rlp_encode_transaction_index()), bytes))
    }

    pub fn get_logs_from_address_with_topic(&self, address: &EthAddress, topic: &EthHash) -> EthLogs {
        EthLogs::new(
            self.logs
                .iter()
                .filter(|log| log.is_from_address(address) && log.contains_topic(topic))
                .cloned()
                .collect(),
        )
    }

    pub fn get_logs_from_addresses_with_topic(&self, addresses: &[EthAddress], topic: &EthHash) -> EthLogs {
        EthLogs::new(
            addresses
                .iter()
                .map(|address| self.get_logs_from_address_with_topic(address, topic).0)
                .collect::<Vec<Vec<EthLog>>>()
                .concat(),
        )
    }
}

impl Ord for EthReceipt {
    fn cmp(&self, other: &Self) -> Ordering {
        self.transaction_index.cmp(&other.transaction_index)
    }
}

impl PartialOrd for EthReceipt {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::evm::eth_test_utils::{
        get_expected_receipt,
        get_sample_contract_address,
        get_sample_contract_topic,
        get_sample_eth_submission_material,
        get_sample_eth_submission_material_json,
        get_sample_receipt_with_desired_topic,
        get_valid_state_with_invalid_block_and_receipts,
        SAMPLE_RECEIPT_INDEX,
    };

    #[test]
    fn should_encode_eth_receipt_as_json() {
        let receipt = get_sample_receipt_with_desired_topic();
        let result = receipt.to_json().unwrap();
        let expected_result = json!({
            "status": true,
            "gasUsed": 37947,
            "transactionIndex": 2,
            "blockNumber": 8503804,
            "cumulativeGasUsed": 79947,
            "to": "0x60a640e2d10e020fee94217707bfa9543c8b59e0",
            "from": "0x250abfa8bc8371709fa4b601d821b1421667a886",
            "contractAddress": "0x0000000000000000000000000000000000000000",
            "blockHash": "0xb626a7546311dd56c6f5e9fd07d00c86074077bbd6d5a4c4f8269a2490aa47c0",
            "transactionHash":  "0xab8078c9aa8720c5f9206bd2673f25f359d8a01b62212da99ff3b53c1ca3d440",
            "logsBloom": "0x00000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000010000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000800000000000000000000010000000000000000008000000000000000000000000000000000000000000000200000003000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000020000000",
            "logs": vec![
                json!({
                    "address": "0x60a640e2d10e020fee94217707bfa9543c8b59e0",
                    "data": "0x00000000000000000000000000000000000000000000000589ba7ab174d54000",
                    "topics": vec![
                        "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                        "0x000000000000000000000000250abfa8bc8371709fa4b601d821b1421667a886",
                        "0x0000000000000000000000005a7dd68907e103c3239411dae0b0eef968468ef2",
                    ],
                })
            ],
        });
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_encode_eth_submission_material_as_json() {
        let block_and_receipts = get_sample_eth_submission_material();
        let result = block_and_receipts.to_json();
        assert!(result.is_ok());
    }

    #[test]
    fn should_encode_eth_submission_material_as_bytes() {
        let block_and_receipts = get_sample_eth_submission_material();
        let result = block_and_receipts.to_bytes();
        assert!(result.is_ok());
    }

    #[test]
    fn should_parse_eth_receipt_json() {
        let eth_json = get_sample_eth_submission_material_json().unwrap();
        let receipt_json = eth_json.receipts[SAMPLE_RECEIPT_INDEX].clone();
        match EthReceipt::from_json(&receipt_json) {
            Ok(receipt) => assert_eq!(receipt, get_expected_receipt()),
            _ => panic!("Should have parsed receipt!"),
        }
    }

    #[test]
    fn should_parse_eth_receipt_jsons() {
        let eth_json = get_sample_eth_submission_material_json().unwrap();
        if EthReceipts::from_jsons(&eth_json.receipts).is_err() {
            panic!("Should have generated receipts correctly!")
        }
    }

    #[test]
    fn should_filter_receipts_for_topics() {
        let expected_num_receipts_after = 1;
        let receipts = get_sample_eth_submission_material().receipts;
        let num_receipts_before = receipts.len();
        let topic = get_sample_contract_topic();
        let topics = vec![topic];
        let address = get_sample_contract_address();
        let result = receipts.get_receipts_containing_log_from_address_and_with_topics(&address, &topics);
        let num_receipts_after = result.len();
        assert_eq!(num_receipts_after, expected_num_receipts_after);
        assert!(num_receipts_before > num_receipts_after);
        result
            .0
            .iter()
            .for_each(|receipt| assert!(receipt.logs.contain_topic(&topic)));
    }

    fn get_encoded_receipt() -> String {
        "f901a7018301384bb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000010000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000800000000000000000000010000000000000000008000000000000000000000000000000000000000000000200000003000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000020000000f89df89b9460a640e2d10e020fee94217707bfa9543c8b59e0f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000250abfa8bc8371709fa4b601d821b1421667a886a00000000000000000000000005a7dd68907e103c3239411dae0b0eef968468ef2a000000000000000000000000000000000000000000000000589ba7ab174d54000".to_string()
    }

    #[test]
    fn should_rlp_encode_receipt() {
        let result = get_expected_receipt().rlp_encode().unwrap();
        assert_eq!(hex::encode(result), get_encoded_receipt())
    }

    #[test]
    fn should_get_encoded_receipt_and_hash_tuple() {
        let result = get_expected_receipt()
            .get_rlp_encoded_receipt_and_encoded_key_tuple()
            .unwrap();
        let expected_encoded_nibbles = get_nibbles_from_bytes(vec![0x02]); // NOTE: The tx index of sample receipt
        assert_eq!(result.0, expected_encoded_nibbles);
        assert_eq!(hex::encode(result.1), get_encoded_receipt());
    }

    #[test]
    fn should_get_encoded_receipts_and_hash_tuples() {
        let expected_encoded_nibbles = get_nibbles_from_bytes(vec![0x02]);
        let receipts = EthReceipts::new(vec![get_expected_receipt(), get_expected_receipt()]);
        let results = receipts.get_rlp_encoded_receipts_and_nibble_tuples().unwrap();
        results.iter().for_each(|result| {
            assert_eq!(result.0, expected_encoded_nibbles);
            assert_eq!(hex::encode(&result.1), get_encoded_receipt());
        });
    }

    #[test]
    fn should_get_receipts_merkle_root_from_receipts() {
        let block_and_receipts = get_sample_eth_submission_material();
        let result = block_and_receipts.receipts.get_merkle_root().unwrap();
        let expected_result = block_and_receipts.get_receipts_root().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_return_false_if_receipts_root_is_not_correct() {
        let state = get_valid_state_with_invalid_block_and_receipts().unwrap();
        let block_and_receipts = state.get_eth_submission_material().unwrap();
        let result = block_and_receipts.receipts_are_valid().unwrap();
        assert!(!result);
    }

    #[test]
    fn should_get_eth_logs_from_receipts() {
        let receipts = get_sample_eth_submission_material().receipts;
        let result = receipts.get_logs();
        assert_eq!(result.len(), 51);
    }

    #[test]
    fn should_get_logs_from_address_with_topic() {
        let topic = get_sample_contract_topic();
        let address = get_sample_contract_address();
        let receipts = get_sample_eth_submission_material().receipts;
        let logs_before = receipts.get_logs();
        let logs_after = receipts.get_logs_from_address_with_topic(&address, &topic);
        assert!(logs_before.len() > logs_after.len());
        assert_eq!(logs_after.len(), 1);
        logs_after.iter().for_each(|log| {
            assert!(log.is_from_address(&address));
            assert!(log.contains_topic(&topic));
        })
    }
}
