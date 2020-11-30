use std::cmp::Ordering;
use rlp::{
    RlpStream,
    Encodable,
};
use serde_json::{
    json,
    Value as JsonValue,
};
use derive_more::{
    Constructor,
    Deref,
    From,
    Into,
};
use ethereum_types::{
    H160,
    U256,
    Bloom,
    H256 as EthHash,
    Address as EthAddress,
};
use crate::{
    types::{
        Bytes,
        Result,
    },
    btc_on_eth::eth::redeem_info::BtcOnEthRedeemInfo,
    erc20_on_eos::eth::peg_in_info::{
        Erc20OnEosPegInInfo,
        Erc20OnEosPegInInfos,
    },
    chains::{
        eos::eos_erc20_dictionary::EosErc20Dictionary,
        eth::{
            eth_log::{
                EthLogs,
                EthLogJson,
            },
            trie::{
                Trie,
                put_in_trie_recursively,
            },
            nibble_utils::{
                Nibbles,
                get_nibbles_from_bytes,
            },
            eth_utils::{
                convert_hex_to_h256,
                convert_hex_to_address,
                convert_json_value_to_string,
            },
        },
    },
};

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Constructor, Deref, From, Into)]
pub struct EthReceipts(pub Vec<EthReceipt>);

impl EthReceipts {
    pub fn from_jsons(jsons: &[EthReceiptJson]) -> Result<Self> {
        Ok(Self(jsons.iter().cloned().map(|json| EthReceipt::from_json(&json)).collect::<Result<Vec<EthReceipt>>>()?))
    }

    fn filter_for_receipts_containing_log_with_address(&self, address: &EthAddress) -> Self {
        Self::new(self.0.iter().filter(|receipt| receipt.contains_log_with_address(address)).cloned().collect())
    }

    fn filter_for_receipts_containing_log_with_topic(&self, topic: &EthHash) -> Self {
        Self::new(self.0.iter().filter(|receipt| receipt.contains_log_with_topic(topic)).cloned().collect())
    }

    fn filter_for_receipts_containing_log_with_address_and_topic(&self, address: &EthAddress, topic: &EthHash) -> Self {
        self
            .filter_for_receipts_containing_log_with_address(address)
            .filter_for_receipts_containing_log_with_topic(topic)
    }

    pub fn filter_for_receipts_containing_log_with_address_and_topics(
        &self,
        address: &EthAddress,
        topics: &[EthHash],
    ) -> Self {
        Self::new(
            topics
                .iter()
                .map(|topic| self.filter_for_receipts_containing_log_with_address_and_topic(address, topic).0)
                .flatten()
                .collect()
        )
    }

    pub fn get_rlp_encoded_receipts_and_nibble_tuples(&self) -> Result<Vec<(Nibbles, Bytes)>> {
        self.0.iter().map(|receipt| receipt.get_rlp_encoded_receipt_and_encoded_key_tuple()).collect()
    }

    pub fn get_merkle_root(&self) -> Result<EthHash> {
        self
            .get_rlp_encoded_receipts_and_nibble_tuples()
            .and_then(|key_value_tuples| put_in_trie_recursively(Trie::get_new_trie()?, key_value_tuples, 0))
            .map(|trie| trie.root)
    }
}

#[allow(non_snake_case)]
#[derive(Clone, Debug, Deserialize)]
pub struct EthReceiptJson {
    pub from: String,
    pub status: bool,
    pub gasUsed: usize,
    pub blockHash: String,
    pub logsBloom: String,
    pub logs: Vec<EthLogJson>,
    pub blockNumber: usize,
    pub to: serde_json::Value,
    pub transactionHash: String,
    pub transactionIndex: usize,
    pub cumulativeGasUsed: usize,
    pub contractAddress: serde_json::Value,
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
        Ok(
            json!({
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
            })
        )
    }

    pub fn from_json(eth_receipt_json: &EthReceiptJson) -> Result<Self> {
        let logs = EthLogs::from_receipt_json(&eth_receipt_json)?;
        Ok(
            EthReceipt {
                status: eth_receipt_json.status,
                logs_bloom: logs.get_bloom(),
                gas_used: U256::from(eth_receipt_json.gasUsed),
                from: convert_hex_to_address(&eth_receipt_json.from)?,
                block_number: U256::from(eth_receipt_json.blockNumber),
                block_hash: convert_hex_to_h256(&eth_receipt_json.blockHash)?,
                transaction_index: U256::from(eth_receipt_json.transactionIndex),
                cumulative_gas_used: U256::from(eth_receipt_json.cumulativeGasUsed),
                transaction_hash: convert_hex_to_h256(&eth_receipt_json.transactionHash)?,
                to: match eth_receipt_json.to {
                    serde_json::Value::Null => H160::zero(),
                    _ => convert_hex_to_address(&convert_json_value_to_string(&eth_receipt_json.to)?)?,
                },
                contract_address: match eth_receipt_json.contractAddress {
                    serde_json::Value::Null => EthAddress::zero(),
                    _ => convert_hex_to_address(&convert_json_value_to_string(&eth_receipt_json.contractAddress)?)?,
                },
                logs,
            }
        )
    }

    pub fn contains_log_with_topic(&self, topic: &EthHash) -> bool {
        self.logs.contain_topic(topic)
    }

    pub fn contains_log_with_address(&self, address: &EthAddress) -> bool {
        self.logs.contain_address(address)
    }

    pub fn rlp_encode(&self) -> Result<Bytes> {
        let mut rlp_stream = RlpStream::new();
        rlp_stream.append(self);
        Ok(rlp_stream.out())
    }

    fn rlp_encode_transaction_index(&self) -> Bytes {
        let mut rlp_stream = RlpStream::new();
        rlp_stream.append(&self.transaction_index.as_usize());
        rlp_stream.out()
    }

    pub fn get_rlp_encoded_receipt_and_encoded_key_tuple(&self) -> Result<(Nibbles, Bytes)> {
        self.rlp_encode().map(|bytes| (get_nibbles_from_bytes(self.rlp_encode_transaction_index()), bytes))
    }

    pub fn get_btc_on_eth_redeem_infos(&self) -> Result<Vec<BtcOnEthRedeemInfo>> {
        info!("✔ Getting redeem `btc_on_eth` redeem infos from receipt...");
        self
            .logs
            .0
            .iter()
            .filter(|log| matches!(log.is_btc_on_eth_redeem(), Ok(true)))
            .map(|log|
                Ok(BtcOnEthRedeemInfo::new(
                    log.get_btc_on_eth_redeem_amount()?,
                    self.from,
                    log.get_btc_on_eth_btc_redeem_address()?,
                    self.transaction_hash
                ))
            )
            .collect()
    }

    pub fn contains_supported_erc20_peg_in(&self, eos_erc20_dictionary: &EosErc20Dictionary) -> bool {
        self.get_supported_erc20_peg_in_logs(eos_erc20_dictionary).len() > 0
    }

    fn get_supported_erc20_peg_in_logs(&self, eos_erc20_dictionary: &EosErc20Dictionary) -> EthLogs {
        EthLogs::new(self
            .logs
            .iter()
            .filter(|log| matches!(log.is_supported_erc20_peg_in(eos_erc20_dictionary), Ok(true)))
            .cloned()
            .collect()
        )
    }

    pub fn get_erc20_on_eos_peg_in_infos(
        &self,
        eos_erc20_dictionary: &EosErc20Dictionary,
    ) -> Result<Erc20OnEosPegInInfos> {
        info!("✔ Getting `erc20-on-eos` peg in infos from receipt...");
        Ok(Erc20OnEosPegInInfos::new(
            self
                .get_supported_erc20_peg_in_logs(eos_erc20_dictionary)
                .iter()
                .map(|log| {
                    let token_contract_address = log.get_erc20_on_eos_peg_in_token_contract_address()?;
                    let eth_amount = log.get_erc20_on_eos_peg_in_amount()?;
                    let peg_in_info = Erc20OnEosPegInInfo::new(
                        eth_amount,
                        log.get_erc20_on_eos_peg_in_token_sender_address()?,
                        token_contract_address,
                        log.get_erc20_on_eos_peg_in_eos_address()?,
                        self.transaction_hash,
                        eos_erc20_dictionary.get_eos_account_name_from_eth_token_address(&token_contract_address)?,
                        eos_erc20_dictionary.convert_u256_to_eos_asset_string(&token_contract_address, &eth_amount)?,
                    );
                    info!("✔ Parsed peg-in info: {:?}", peg_in_info);
                    Ok(peg_in_info)
                })
                .collect::<Result<Vec<Erc20OnEosPegInInfo>>>()?
        ))
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

impl Encodable for EthReceipt {
    fn rlp_append(&self, rlp_stream: &mut RlpStream) {
        let rlp = rlp_stream.begin_list(4);
        match &self.status {
            true => rlp.append(&self.status),
            false => rlp.append_empty_data()
        };
        rlp.append(&self.cumulative_gas_used).append(&self.logs_bloom).append_list(&self.logs.0);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use crate::{
        chains::{
            eos::{
                eos_erc20_dictionary::EosErc20DictionaryEntry,
                eos_test_utils::get_sample_eos_erc20_dictionary,
            },
            eth::{
                eth_log::EthLog,
                eth_submission_material::EthSubmissionMaterial,
                eth_test_utils::{
                    get_sample_erc20_on_eos_peg_in_info,
                    get_sample_receipt_with_erc20_peg_in_event,
                },
            },
        },
        btc_on_eth::eth::eth_test_utils::{
            get_expected_receipt,
            SAMPLE_RECEIPT_INDEX,
            get_sample_contract_topic,
            get_sample_contract_address,
            get_sample_eth_submission_material,
            get_sample_eth_submission_material_n,
            get_sample_receipt_with_desired_topic,
            get_sample_eth_submission_material_json,
            get_valid_state_with_invalid_block_and_receipts,
        },
    };

    fn get_sample_block_with_redeem() -> EthSubmissionMaterial {
        get_sample_eth_submission_material_n(4)
            .unwrap()
    }

    fn get_tx_hash_of_redeem_tx() -> &'static str {
        "442612aba789ce873bb3804ff62ced770dcecb07d19ddcf9b651c357eebaed40"
    }

    fn get_sample_receipt_with_redeem() -> EthReceipt {
        let hash = EthHash::from_str(get_tx_hash_of_redeem_tx())
            .unwrap();
        get_sample_block_with_redeem()
            .receipts
            .0
            .iter()
            .filter(|receipt| receipt.transaction_hash == hash)
            .collect::<Vec<&EthReceipt>>()
            [0]
            .clone()
    }

    fn get_expected_redeem_params() -> BtcOnEthRedeemInfo {
        let amount = U256::from_dec_str("666").unwrap();
        let from = EthAddress::from_str("edb86cd455ef3ca43f0e227e00469c3bdfa40628").unwrap();
        let recipient = "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string();
        let originating_tx_hash = EthHash::from_slice(&hex::decode(get_tx_hash_of_redeem_tx()).unwrap()[..]);
        BtcOnEthRedeemInfo::new(amount, from, recipient, originating_tx_hash)
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
        let result = receipts.filter_for_receipts_containing_log_with_address_and_topics(&address, &topics);
        let num_receipts_after = result.len();
        assert_eq!(num_receipts_after, expected_num_receipts_after);
        assert!(num_receipts_before > num_receipts_after);
        result.0.iter().for_each(|receipt| assert!(receipt.logs.contain_topic(&topic)));
    }

    fn get_encoded_receipt() -> String {
        "f901a7018301384bb9010000000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000010000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000800000000000000000000010000000000000000008000000000000000000000000000000000000000000000200000003000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000020000000f89df89b9460a640e2d10e020fee94217707bfa9543c8b59e0f863a0ddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3efa0000000000000000000000000250abfa8bc8371709fa4b601d821b1421667a886a00000000000000000000000005a7dd68907e103c3239411dae0b0eef968468ef2a000000000000000000000000000000000000000000000000589ba7ab174d54000".to_string()
    }

    #[test]
    fn should_rlp_encode_receipt() {
        let result =get_expected_receipt().rlp_encode().unwrap();
        assert_eq!(hex::encode(result), get_encoded_receipt())
    }

    #[test]
    fn should_get_encoded_receipt_and_hash_tuple() {
        let result = get_expected_receipt().get_rlp_encoded_receipt_and_encoded_key_tuple().unwrap();
        let expected_encoded_nibbles = get_nibbles_from_bytes(vec![0x02]); // NOTE: The tx index of sample receipt
        assert_eq!(result.0, expected_encoded_nibbles);
        assert_eq!(hex::encode(result.1), get_encoded_receipt());
    }

    #[test]
    fn should_get_encoded_receipts_and_hash_tuples() {
        let expected_encoded_nibbles = get_nibbles_from_bytes(vec![0x02]);
        let receipts = EthReceipts::new(vec![get_expected_receipt(), get_expected_receipt()]);
        let results = receipts.get_rlp_encoded_receipts_and_nibble_tuples().unwrap();
        results
            .iter()
            .for_each(|result| {
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
    fn should_parse_btc_on_eth_redeem_params_from_receipt() {
        let expected_num_results = 1;
        let result = get_sample_receipt_with_redeem().get_btc_on_eth_redeem_infos().unwrap();
        assert_eq!(result.len(), expected_num_results);
        assert_eq!(result[0], get_expected_redeem_params());
    }

    #[test]
    fn should_return_true_if_receipt_contains_log_with_erc20_peg_in() {
        let dictionary = get_sample_eos_erc20_dictionary();
        let receipt = get_sample_receipt_with_erc20_peg_in_event().unwrap();
        let result = receipt.contains_supported_erc20_peg_in(&dictionary);
        assert!(result);
    }

    #[test]
    fn should_return_false_if_receipt_does_not_contain_log_with_erc20_peg_in() {
        let dictionary = EosErc20Dictionary::new(vec![]);
        let receipt = get_sample_receipt_with_erc20_peg_in_event().unwrap();
        let result = receipt.contains_supported_erc20_peg_in(&dictionary);
        assert!(!result);
    }

    #[test]
    fn should_get_get_erc20_redeem_infos_from_receipt() {
        let eth_token_decimals = 18;
        let eos_token_decimals = 9;
        let eth_symbol = "SAM".to_string();
        let eos_symbol = "SAM".to_string();
        let token_name = "SampleToken".to_string();
        let token_address = EthAddress::from_slice(
            &hex::decode("9f57CB2a4F462a5258a49E88B4331068a391DE66").unwrap()
        );
        let eos_erc20_dictionary = EosErc20Dictionary::new(vec![
            EosErc20DictionaryEntry::new(
                eth_token_decimals,
                eos_token_decimals,
                eth_symbol,
                eos_symbol,
                token_name,
                token_address
            )
        ]);
        let expected_num_results = 1;
        let expected_result = get_sample_erc20_on_eos_peg_in_info().unwrap();
        let receipt = get_sample_receipt_with_erc20_peg_in_event().unwrap();
        let result = receipt.get_erc20_on_eos_peg_in_infos(&eos_erc20_dictionary).unwrap();
        assert_eq!(result.len(), expected_num_results);
        assert_eq!(result.0[0], expected_result);
    }

    #[test]
    fn should_not_get_get_erc20_redeem_infos_from_receipt_if_token_not_supported() {
        let eos_erc20_dictionary = EosErc20Dictionary::new(vec![]);
        let expected_num_results = 0;
        let receipt = get_sample_receipt_with_erc20_peg_in_event().unwrap();
        let result = receipt.get_erc20_on_eos_peg_in_infos(&eos_erc20_dictionary).unwrap();
        assert_eq!(result.len(), expected_num_results);
    }

    #[test]
    fn should_get_supported_erc20_peg_in_logs() {
        let expected_result = EthLogs::new(vec![EthLog {
            address: EthAddress::from_slice(&hex::decode("d0a3d2d3d19a6ac58e60254fd606ec766638c3ba").unwrap()),
            topics: vec![EthHash::from_slice(&hex::decode("42877668473c4cba073df41397388516dc85c3bbae14b33603513924cec55e36").unwrap())],
            data: hex::decode("0000000000000000000000009f57cb2a4f462a5258a49e88b4331068a391de66000000000000000000000000fedfe2616eb3661cb8fed2782f5f0cc91d59dcac00000000000000000000000000000000000000000000000000000000000005390000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000c616e656f73616464726573730000000000000000000000000000000000000000").unwrap(),
        }]);
        let expected_num_logs = 1;
        let dictionary = get_sample_eos_erc20_dictionary();
        let receipt = get_sample_receipt_with_erc20_peg_in_event().unwrap();
        let result = receipt.get_supported_erc20_peg_in_logs(&dictionary);
        assert_eq!(result.len(), expected_num_logs);
        assert_eq!(result, expected_result);
    }
}
