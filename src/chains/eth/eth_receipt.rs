use std::cmp::Ordering;

use derive_more::{Constructor, Deref, From, Into};
use ethereum_types::{Address as EthAddress, Bloom, H160, H256 as EthHash, U256};
use keccak_hasher::KeccakHasher;
use rlp::RlpStream;
use serde::Deserialize;
use serde_json::{json, Value as JsonValue};
use triehash::trie_root;

use crate::{
    chains::eth::{
        eth_log::{EthLog, EthLogJson, EthLogs},
        eth_receipt_type::EthReceiptType,
        eth_utils::{convert_hex_to_address, convert_hex_to_h256, convert_json_value_to_string},
    },
    types::{Bytes, NoneError, Result},
    utils::{add_key_and_value_to_json, strip_hex_prefix},
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
            self.iter()
                .filter(|receipt| receipt.contains_log_from_address(address))
                .cloned()
                .collect(),
        )
    }

    fn get_receipts_containing_log_with_topic(&self, topic: &EthHash) -> Self {
        Self::new(
            self.iter()
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

    pub fn get_rlp_encoded_indicies_and_rlp_encoded_receipt_tuples(&self) -> Result<Vec<(Bytes, Bytes)>> {
        self.0
            .iter()
            .map(|receipt| receipt.get_rlp_encoded_index_and_rlp_encoded_receipt_tuple())
            .collect()
    }

    pub fn get_merkle_root(&self) -> Result<EthHash> {
        self.get_rlp_encoded_indicies_and_rlp_encoded_receipt_tuples()
            .map(|key_value_tuples| EthHash::from_slice(&trie_root::<KeccakHasher, _, _, _>(key_value_tuples)))
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
    #[serde(rename = "type")]
    pub receipt_type: Option<String>,
}

impl EthReceiptJson {
    pub fn from_str(s: &str) -> Result<Self> {
        Ok(serde_json::from_str(s)?)
    }
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
    pub receipt_type: Option<EthReceiptType>,
}

impl EthReceipt {
    pub fn to_string(&self) -> Result<String> {
        Ok(self.to_json()?.to_string())
    }

    pub fn from_str(s: &str) -> Result<Self> {
        Self::from_json(&EthReceiptJson::from_str(s)?)
    }

    fn get_receipt_type(&self) -> Result<EthReceiptType> {
        self.receipt_type
            .clone()
            .ok_or(NoneError("Could not get receipt type from receipt!"))
    }

    pub fn to_json(&self) -> Result<JsonValue> {
        let encoded_logs = self
            .logs
            .iter()
            .map(|eth_log| eth_log.to_json())
            .collect::<Result<Vec<JsonValue>>>()?;
        if self.receipt_type.is_none() {
            self.to_json_legacy(encoded_logs)
        } else {
            self.to_eip_2718_json(encoded_logs)
        }
    }

    fn to_eip_2718_json(&self, encoded_logs: Vec<JsonValue>) -> Result<JsonValue> {
        add_key_and_value_to_json(
            "type",
            json!(self
                .receipt_type
                .as_ref()
                .map(|eth_receipt_type| eth_receipt_type.to_string())),
            self.to_json_legacy(encoded_logs)?,
        )
    }

    fn to_json_legacy(&self, encoded_logs: Vec<JsonValue>) -> Result<JsonValue> {
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
            "transactionHash": format!("0x{}", hex::encode(self.transaction_hash.as_bytes())),
        }))
    }

    pub fn from_json(json: &EthReceiptJson) -> Result<Self> {
        let logs = EthLogs::from_receipt_json(json)?;
        Ok(Self {
            status: json.status,
            logs_bloom: logs.get_bloom(),
            gas_used: U256::from(json.gas_used),
            from: convert_hex_to_address(&json.from)?,
            block_number: U256::from(json.block_number),
            block_hash: convert_hex_to_h256(&json.block_hash)?,
            transaction_index: U256::from(json.transaction_index),
            cumulative_gas_used: U256::from(json.cumulative_gas_used),
            transaction_hash: convert_hex_to_h256(&json.transaction_hash)?,
            to: match json.to {
                serde_json::Value::Null => H160::zero(),
                _ => convert_hex_to_address(&convert_json_value_to_string(&json.to)?)?,
            },
            contract_address: match json.contract_address {
                serde_json::Value::Null => EthAddress::zero(),
                _ => convert_hex_to_address(&convert_json_value_to_string(&json.contract_address)?)?,
            },
            receipt_type: match json.receipt_type {
                Some(ref hex) => Some(EthReceiptType::from_byte(&hex::decode(&strip_hex_prefix(hex))?[0])),
                None => None,
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
        match self.get_receipt_type() {
            Ok(EthReceiptType::EIP2718) => {
                debug!("RLP encoding EIP2718 receipt...");
                self.encode_eip_2718_receipt()
            },
            Ok(EthReceiptType::Legacy) | Err(_) => {
                debug!("RLP encoding LEGACY receipt...");
                self.rlp_encode_legacy()
            },
        }
    }

    fn encode_eip_2718_receipt(&self) -> Result<Bytes> {
        // NOTE: Per EIP-2718: https://github.com/ethereum/EIPs/blob/master/EIPS/eip-2718.md
        // the encoding for these transactions are `TransactionType concatenated w/ ReceiptPayload`
        // The `ReceiptPayload` for this transaction type is rlp([
        //   status, cumulative_transaction_gas_used, logs_bloom, logs
        // ]), which is the same as the RLP encoding for legacy receipts.
        Ok([EthReceiptType::EIP2718.to_bytes(), self.rlp_encode_legacy()?].concat())
    }

    fn rlp_encode_legacy(&self) -> Result<Bytes> {
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

    pub fn get_rlp_encoded_index_and_rlp_encoded_receipt_tuple(&self) -> Result<(Bytes, Bytes)> {
        self.rlp_encode()
            .map(|bytes| (self.rlp_encode_transaction_index(), bytes))
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

    pub fn get_logs_from_addresses_with_topics(&self, addresses: &[EthAddress], topics: &[EthHash]) -> EthLogs {
        debug!("Getting logs from addresses: {:?}", addresses);
        debug!("Getting logs with topics: {:?}", topics);
        EthLogs::new(
            topics
                .iter()
                .map(|topic| self.get_logs_from_addresses_with_topic(addresses, topic).0)
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
    use crate::chains::eth::eth_test_utils::{
        get_expected_receipt,
        get_sample_contract_address,
        get_sample_contract_topic,
        get_sample_eip1559_mainnet_submission_material,
        get_sample_eth_submission_material,
        get_sample_eth_submission_material_json,
        get_sample_receipt_with_desired_topic,
        get_valid_state_with_invalid_block_and_receipts,
        SAMPLE_RECEIPT_INDEX,
    };

    fn get_eip1559_non_legacy_receipt() -> EthReceipt {
        get_sample_eip1559_mainnet_submission_material().receipts[0].clone()
    }

    fn get_eip1559_legacy_receipt() -> EthReceipt {
        get_sample_eip1559_mainnet_submission_material().receipts[1].clone()
    }

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
        });
    }

    #[test]
    fn should_get_logs_from_addresses_and_with_topic_from_receipt() {
        let topic = get_sample_contract_topic();
        let addresses = vec![get_sample_contract_address()];
        let receipt = get_sample_eth_submission_material()
            .receipts
            .get_receipts_containing_log_from_addresses_and_with_topics(&addresses, &vec![topic])[0]
            .clone();
        let result = receipt.get_logs_from_addresses_with_topic(&addresses, &topic);
        assert_eq!(result.len(), 1);
        result.iter().for_each(|log| {
            assert!(log.is_from_address(&addresses[0]));
            assert!(log.contains_topic(&topic));
        });
    }

    #[test]
    fn should_get_logs_from_addresses_and_with_topics_from_receipt() {
        let topics = vec![get_sample_contract_topic()];
        let addresses = vec![get_sample_contract_address()];
        let receipt = get_sample_eth_submission_material()
            .receipts
            .get_receipts_containing_log_from_addresses_and_with_topics(&addresses, &topics)[0]
            .clone();
        let result = receipt.get_logs_from_addresses_with_topics(&addresses, &topics);
        assert_eq!(result.len(), 1);
        result.iter().for_each(|log| {
            assert!(log.is_from_address(&addresses[0]));
            assert!(log.contains_topic(&topics[0]));
        });
    }

    #[test]
    fn non_legacy_mainnet_eip1559_receipt_should_have_receipt_type_field() {
        let receipt = get_eip1559_non_legacy_receipt();
        assert!(receipt.receipt_type.is_some())
    }

    #[test]
    fn non_legacy_eip1559_receipt_should_make_json_str_roundtrip() {
        let receipt = get_eip1559_non_legacy_receipt();
        let s = receipt.to_string().unwrap();
        let result = EthReceipt::from_str(&s).unwrap();
        assert_eq!(result, receipt);
    }

    #[test]
    fn legacy_eip1559_receipt_should_make_json_str_roundtrip() {
        let receipt = get_eip1559_legacy_receipt();
        let s = receipt.to_string().unwrap();
        let result = EthReceipt::from_str(&s).unwrap();
        assert_eq!(result, receipt);
    }

    #[test]
    fn should_get_receipt_type_from_non_legacy_receipt() {
        let receipt = get_eip1559_non_legacy_receipt();
        let expected_result = EthReceiptType::EIP2718;
        let result = receipt.get_receipt_type().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_encode_legacy_receipt_correctly() {
        let receipt = get_eip1559_legacy_receipt();
        let result = receipt.rlp_encode().unwrap();
        let expected_result = "f905bd0183062c30b9010000000002010000000000000000000000000000000000000000000000040000000000000000000000000008000000000002000000080020008000000000000000000000000000000808000008000000000000000000000000000000000000000000000000000000000000100002000000000000000000000200000014000800002000000000002000000000000400001000000000010000000000000000000000000100000800200000000008800000000000000000000000002000000008000000000002000000000000000000000000000000000000000000000000000000000000200000000000000010000000000100000000000000000000000000000000f904b2f89b94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000088e6a0c2ddd26feeb64f039a2c41296fcb3f5640a0000000000000000000000000e592427a0aece92de3edee1f18e0157c05861564a00000000000000000000000000000000000000000000000026064e85c5caf57dff89b94a0b86991c6218b36c1d19d4a2e9eb0ce3606eb48f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa00000000000000000000000007238a14518d70b6d8fe63878dd19cb89210c5c66a000000000000000000000000088e6a0c2ddd26feeb64f039a2c41296fcb3f5640a0000000000000000000000000000000000000000000000000000000203b169961f9011c9488e6a0c2ddd26feeb64f039a2c41296fcb3f5640f863a0c42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67a0000000000000000000000000e592427a0aece92de3edee1f18e0157c05861564a0000000000000000000000000e592427a0aece92de3edee1f18e0157c05861564b8a0000000000000000000000000000000000000000000000000000000203b169961fffffffffffffffffffffffffffffffffffffffffffffffd9f9b17a3a350a8210000000000000000000000000000000000004585c7a608dbfc4835aa9f44a8740000000000000000000000000000000000000000000000007c5de12db7429eb8000000000000000000000000000000000000000000000000000000000002fca2f89b948762db106b2c2a0bccb3a80d1ed41273552616e8f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000ba8eb224b656681b2b8cce9c3fc920d98594675ba00000000000000000000000007238a14518d70b6d8fe63878dd19cb89210c5c66a000000000000000000000000000000000000000000002cb527e45ebb1f39485bdf89b94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000e592427a0aece92de3edee1f18e0157c05861564a0000000000000000000000000ba8eb224b656681b2b8cce9c3fc920d98594675ba00000000000000000000000000000000000000000000000026064e85c5caf57dff9011c94ba8eb224b656681b2b8cce9c3fc920d98594675bf863a0c42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67a0000000000000000000000000e592427a0aece92de3edee1f18e0157c05861564a00000000000000000000000007238a14518d70b6d8fe63878dd19cb89210c5c66b8a0fffffffffffffffffffffffffffffffffffffffffffd34ad81ba144e0c6b7a430000000000000000000000000000000000000000000000026064e85c5caf57df000000000000000000000000000000000000000000ee653c0e75c3b7a964179d0000000000000000000000000000000000000000000068c0e87a58032f4082ddfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe4931";
        assert_eq!(hex::encode(result), expected_result);
    }

    #[test]
    fn should_encode_non_legacy_receipt_correctly() {
        let receipt = get_eip1559_non_legacy_receipt();
        let result = receipt.rlp_encode().unwrap();
        let expected_result = "02f903640183019b2bb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000002000100080020000000000000000000000000000000000800000008000000000000000000000000000000000000000000000000000000000000000002000000000000000000000000000014000800002000000000002000000000000400001000000000000000000000000000000000000100000800000000000000000000000000000000000000000000000000000000000006000000000000000000000000000000000000000000000000000000000000200000000000000100000000000100000000000000000000000000000000f90259f89b948762db106b2c2a0bccb3a80d1ed41273552616e8f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000ba8eb224b656681b2b8cce9c3fc920d98594675ba000000000000000000000000000000000003b3cc22af3ae1eac0440bcee416b40a000000000000000000000000000000000000000000000541eb0a0ce7492aaf122f89b94c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa000000000000000000000000000000000003b3cc22af3ae1eac0440bcee416b40a0000000000000000000000000ba8eb224b656681b2b8cce9c3fc920d98594675ba000000000000000000000000000000000000000000000000045cf942999229eb4f9011c94ba8eb224b656681b2b8cce9c3fc920d98594675bf863a0c42079f94a6350d7e6235f29174924f928cc2ac818eb64fed8004e115fbcca67a000000000000000000000000000000000003b3cc22af3ae1eac0440bcee416b40a000000000000000000000000000000000003b3cc22af3ae1eac0440bcee416b40b8a0ffffffffffffffffffffffffffffffffffffffffffffabe14f5f318b6d550ede00000000000000000000000000000000000000000000000045cf942999229eb4000000000000000000000000000000000000000000e9290d4fa549b17685b3750000000000000000000000000000000000000000000074f082db6efc6c9d3457fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffe4775";
        assert_eq!(hex::encode(result), expected_result);
    }
}
