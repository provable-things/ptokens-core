use crate::{
    btc_on_eth::utils::convert_ptoken_to_satoshis,
    chains::{
        eos::eos_erc20_dictionary::EosErc20Dictionary,
        eth::{
            eth_constants::{
                BTC_ON_ETH_REDEEM_EVENT_TOPIC_HEX,
                ERC20_PEG_IN_EVENT_TOPIC_HEX,
                ETH_ADDRESS_SIZE_IN_BYTES,
                ETH_WORD_SIZE_IN_BYTES,
                LOG_DATA_BTC_ADDRESS_START_INDEX,
            },
            eth_receipt::EthReceiptJson,
            eth_utils::{convert_hex_strings_to_h256s, convert_hex_to_address, convert_hex_to_bytes},
        },
    },
    constants::{SAFE_BTC_ADDRESS, SAFE_EOS_ADDRESS},
    types::{Bytes, Result},
};
use bitcoin::util::address::Address as BtcAddress;
use derive_more::{Constructor, Deref};
use eos_primitives::AccountName as EosAccountName;
use ethereum_types::{Address as EthAddress, Bloom, BloomInput, H256 as EthHash, U256};
use rlp::{Encodable, RlpStream};
use serde_json::{json, Value as JsonValue};
use std::str::FromStr;

#[allow(non_snake_case)]
#[derive(Clone, Debug, Deserialize)]
pub struct EthLogJson {
    pub data: String,
    pub address: String,
    pub topics: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct EthLog {
    pub address: EthAddress,
    pub topics: Vec<EthHash>,
    pub data: Bytes,
}

pub const NOT_ENOUGH_BYTES_IN_LOG_DATA_ERR: &str = "Not enough bytes in log data!";

impl EthLog {
    pub fn from_json(log_json: &EthLogJson) -> Result<Self> {
        Ok(EthLog {
            data: convert_hex_to_bytes(&log_json.data)?,
            address: convert_hex_to_address(&log_json.address)?,
            topics: convert_hex_strings_to_h256s(log_json.topics.iter().map(AsRef::as_ref).collect())?,
        })
    }

    pub fn to_json(&self) -> Result<JsonValue> {
        let topic_strings = self
            .topics
            .iter()
            .map(|topic_hash| format!("0x{}", hex::encode(topic_hash.as_bytes())))
            .collect::<Vec<String>>();
        Ok(json!({
            "topics": topic_strings,
            "data": format!("0x{}", hex::encode(self.data.clone())),
            "address": format!("0x{}", hex::encode(self.address.as_bytes())),
        }))
    }

    pub fn get_bloom(&self) -> Bloom {
        self.topics.iter().fold(
            Bloom::from(BloomInput::Raw(self.address.as_bytes())),
            |mut bloom, topic| {
                bloom.accrue(BloomInput::Raw(topic.as_bytes()));
                bloom
            },
        )
    }

    pub fn contains_topic(&self, topic: &EthHash) -> bool {
        self.topics.iter().any(|log_topic| log_topic == topic)
    }

    pub fn contains_address(&self, address: &EthAddress) -> bool {
        self.address == *address
    }

    pub fn is_btc_on_eth_redeem(&self) -> Result<bool> {
        Ok(self.contains_topic(&EthHash::from_slice(
            &hex::decode(&BTC_ON_ETH_REDEEM_EVENT_TOPIC_HEX)?[..],
        )))
    }

    fn is_erc20_peg_in(&self) -> Result<bool> {
        Ok(self.contains_topic(&EthHash::from_slice(&hex::decode(&ERC20_PEG_IN_EVENT_TOPIC_HEX)?[..])))
    }

    pub fn is_supported_erc20_peg_in(&self, eos_erc20_dictionary: &EosErc20Dictionary) -> Result<bool> {
        match self.is_erc20_peg_in()? {
            false => Ok(false),
            true => self
                .get_erc20_on_eos_peg_in_token_contract_address()
                .map(|token_contract_address| eos_erc20_dictionary.is_token_supported(&token_contract_address)),
        }
    }

    fn check_is_btc_on_eth_redeem(&self) -> Result<()> {
        trace!("✔ Checking if log is a `btc_on_eth` redeem...");
        match self.is_btc_on_eth_redeem()? {
            true => Ok(()),
            false => Err("✘ Log is not from a pToken redeem event!".into()),
        }
    }

    fn check_is_erc20_peg_in(&self) -> Result<()> {
        trace!("✔ Checking if log is a erc20 peg in...");
        match self.is_erc20_peg_in()? {
            true => Ok(()),
            false => Err("✘ Log is not from a erc20 peg in event!".into()),
        }
    }

    pub fn get_btc_on_eth_redeem_amount(&self) -> Result<U256> {
        self.check_is_btc_on_eth_redeem().and_then(|_| {
            info!("✔ Parsing redeem amount from log...");
            if self.data.len() >= ETH_WORD_SIZE_IN_BYTES {
                Ok(U256::from(convert_ptoken_to_satoshis(U256::from(
                    &self.data[..ETH_WORD_SIZE_IN_BYTES],
                ))))
            } else {
                Err("✘ Not enough bytes in log data to get redeem amount!".into())
            }
        })
    }

    pub fn get_btc_on_eth_btc_redeem_address(&self) -> Result<String> {
        self.check_is_btc_on_eth_redeem().map(|_| {
            info!("✔ Parsing BTC address from log...");
            let default_address_error_string = format!("✔ Defaulting to safe BTC address: {}!", SAFE_BTC_ADDRESS);
            let maybe_btc_address = self.data[LOG_DATA_BTC_ADDRESS_START_INDEX..]
                .iter()
                .filter(|byte| *byte != &0u8)
                .map(|byte| *byte as char)
                .collect::<String>();
            info!("✔ Maybe BTC address parsed from log: {}", maybe_btc_address);
            match BtcAddress::from_str(&maybe_btc_address) {
                Ok(address) => {
                    info!("✔ Good BTC address parsed from log: {}", address);
                    address.to_string()
                },
                Err(_) => {
                    info!("✔ Failed to parse BTC address from log!");
                    info!("{}", default_address_error_string);
                    SAFE_BTC_ADDRESS.to_string()
                },
            }
        })
    }

    pub fn get_erc20_on_eos_peg_in_amount(&self) -> Result<U256> {
        self.check_is_erc20_peg_in().and_then(|_| {
            const START_INDEX: usize = ETH_WORD_SIZE_IN_BYTES * 2;
            const END_INDEX: usize = ETH_WORD_SIZE_IN_BYTES * 3;
            match self.data.len() >= END_INDEX {
                true => {
                    let amount = U256::from(&self.data[START_INDEX..END_INDEX]);
                    info!("✔ Parsed `erc20-on-eos` peg in amount from log: {}", amount.to_string());
                    Ok(amount)
                },
                false => Err(NOT_ENOUGH_BYTES_IN_LOG_DATA_ERR.into()),
            }
        })
    }

    pub fn get_erc20_on_eos_peg_in_token_contract_address(&self) -> Result<EthAddress> {
        self.check_is_erc20_peg_in().and_then(|_| {
            info!("✔ Parsing `erc20-on-eos` peg in token contract address from log...");
            const START_INDEX: usize = ETH_WORD_SIZE_IN_BYTES - ETH_ADDRESS_SIZE_IN_BYTES;
            const END_INDEX: usize = START_INDEX + ETH_ADDRESS_SIZE_IN_BYTES;
            match self.data.len() >= END_INDEX {
                true => Ok(EthAddress::from_slice(&self.data[START_INDEX..END_INDEX])),
                false => Err(NOT_ENOUGH_BYTES_IN_LOG_DATA_ERR.into()),
            }
        })
    }

    pub fn get_erc20_on_eos_peg_in_token_sender_address(&self) -> Result<EthAddress> {
        self.check_is_erc20_peg_in().and_then(|_| {
            info!("✔ Parsing `erc20-on-eos` peg in token sender address from log...");
            const START_INDEX: usize = ETH_WORD_SIZE_IN_BYTES * 2 - ETH_ADDRESS_SIZE_IN_BYTES;
            const END_INDEX: usize = START_INDEX + ETH_ADDRESS_SIZE_IN_BYTES;
            match self.data.len() >= END_INDEX {
                true => Ok(EthAddress::from_slice(&self.data[START_INDEX..END_INDEX])),
                false => Err(NOT_ENOUGH_BYTES_IN_LOG_DATA_ERR.into()),
            }
        })
    }

    fn extract_eos_address_string(&self) -> Result<String> {
        info!("✔ Parsing `erc20-on-eos` peg in EOS address from log...");
        const START_INDEX: usize = ETH_WORD_SIZE_IN_BYTES * 5;
        Ok(self.data[START_INDEX..]
            .iter()
            .filter(|byte| *byte != &0u8)
            .map(|byte| *byte as char)
            .collect())
    }

    // TODO get sample log w/ bad address & test this!
    fn extract_eos_address_or_default_to_safe_address(&self) -> Result<String> {
        self.extract_eos_address_string().map(|maybe_eos_address: String| {
            match EosAccountName::from_str(&maybe_eos_address) {
                Ok(_) => maybe_eos_address,
                Err(_) => {
                    info!("✘ Could not parse EOS address from: {}", maybe_eos_address);
                    info!("✔ Defaulting to safe EOS address: {}", SAFE_EOS_ADDRESS);
                    SAFE_EOS_ADDRESS.to_string()
                },
            }
        })
    }

    pub fn get_erc20_on_eos_peg_in_eos_address(&self) -> Result<String> {
        self.check_is_erc20_peg_in()
            .and_then(|_| self.extract_eos_address_or_default_to_safe_address())
    }
}

impl Encodable for EthLog {
    fn rlp_append(&self, rlp_stream: &mut RlpStream) {
        rlp_stream
            .begin_list(3)
            .append(&self.address)
            .append_list(&self.topics)
            .append(&self.data);
    }
}

#[derive(Debug, Clone, Eq, PartialEq, Deserialize, Deref, Constructor)]
pub struct EthLogs(pub Vec<EthLog>);

impl EthLogs {
    pub fn get_bloom(&self) -> Bloom {
        self.0.iter().fold(Bloom::default(), |mut bloom, log| {
            bloom.accrue_bloom(&log.get_bloom());
            bloom
        })
    }

    pub fn from_receipt_json(json: &EthReceiptJson) -> Result<Self> {
        Ok(Self(
            json.logs
                .iter()
                .map(|log_json| EthLog::from_json(log_json))
                .collect::<Result<Vec<EthLog>>>()?,
        ))
    }

    pub fn contain_topic(&self, topic: &EthHash) -> bool {
        self.0.iter().any(|log| log.contains_topic(topic))
    }

    pub fn contain_address(&self, address: &EthAddress) -> bool {
        self.0.iter().any(|log| log.contains_address(address))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        btc_on_eth::eth::eth_test_utils::{
            get_expected_log,
            get_sample_contract_address,
            get_sample_contract_topic,
            get_sample_eth_submission_material_json,
            get_sample_eth_submission_material_n,
            get_sample_log_n,
            get_sample_log_with_desired_address,
            get_sample_log_with_desired_topic,
            get_sample_log_without_desired_address,
            get_sample_logs_with_desired_topic,
            get_sample_logs_without_desired_topic,
            get_sample_receipt_with_desired_address,
            get_sample_receipt_without_desired_address,
            SAMPLE_RECEIPT_INDEX,
        },
        chains::{
            eos::eos_erc20_dictionary::EosErc20DictionaryEntry,
            eth::{
                eth_receipt::EthReceipt,
                eth_submission_material::EthSubmissionMaterial,
                eth_test_utils::{get_sample_log_with_erc20_peg_in_event, get_sample_log_with_erc20_peg_in_event_2},
            },
        },
    };
    use std::str::FromStr;

    fn get_tx_hash_of_redeem_tx() -> &'static str {
        "442612aba789ce873bb3804ff62ced770dcecb07d19ddcf9b651c357eebaed40"
    }

    fn get_sample_block_with_redeem() -> EthSubmissionMaterial {
        // TODO coalesce these three!
        get_sample_eth_submission_material_n(4).unwrap()
    }

    fn get_sample_receipt_with_redeem() -> EthReceipt {
        let hash = EthHash::from_str(get_tx_hash_of_redeem_tx()).unwrap();
        get_sample_block_with_redeem()
            .receipts
            .0
            .iter()
            .filter(|receipt| receipt.transaction_hash == hash)
            .collect::<Vec<&EthReceipt>>()[0]
            .clone()
    }

    fn get_sample_log_with_redeem() -> EthLog {
        get_sample_receipt_with_redeem().logs.0[2].clone()
    }

    fn get_sample_log_with_p2sh_redeem() -> EthLog {
        get_sample_log_n(5, 23, 2).unwrap()
    }

    #[test]
    fn should_get_logs_bloom_from_logs() {
        let expected_bloom = "00000000000000000000000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000010000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000010000000000000000000000000000000000000000000000000800000000000000000000010000000000000000008000000000000000000000000000000000000000000000200000003000000000000000000000000000000000000000000000000000000000002000000000000000000000000000000000000000000000000000020000000";
        let expected_bloom_bytes = &hex::decode(expected_bloom).unwrap()[..];
        let eth_block_and_receipt_json = get_sample_eth_submission_material_json().unwrap();
        let receipt_json = eth_block_and_receipt_json.receipts[SAMPLE_RECEIPT_INDEX].clone();
        let logs = EthLogs::from_receipt_json(&receipt_json).unwrap();
        let result = logs.get_bloom();
        assert_eq!(result.as_bytes(), expected_bloom_bytes)
    }

    #[test]
    fn should_get_logs_from_receipt_json() {
        let expected_result = get_expected_log();
        let eth_block_and_receipt_json = get_sample_eth_submission_material_json().unwrap();
        let result = EthLogs::from_receipt_json(&eth_block_and_receipt_json.receipts[SAMPLE_RECEIPT_INDEX]).unwrap();
        assert_eq!(result.0[0], expected_result);
    }

    #[test]
    fn should_get_log_from_log_json_correctly() {
        let eth_block_and_receipt_json = get_sample_eth_submission_material_json().unwrap();
        let log_json = eth_block_and_receipt_json.receipts[SAMPLE_RECEIPT_INDEX].logs[0].clone();
        let result = EthLog::from_json(&log_json).unwrap();
        let expected_result = get_expected_log();
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_encode_eth_log_as_json() {
        let log = get_sample_log_with_desired_topic();
        let result = log.to_json().unwrap();
        let expected_result = json!({
            "address": "0x60a640e2d10e020fee94217707bfa9543c8b59e0",
            "data": "0x00000000000000000000000000000000000000000000000589ba7ab174d54000",
            "topics": vec![
                "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef",
                "0x000000000000000000000000250abfa8bc8371709fa4b601d821b1421667a886",
                "0x0000000000000000000000005a7dd68907e103c3239411dae0b0eef968468ef2",
            ]
        });
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_return_true_if_log_contains_desired_topic() {
        let log = get_sample_log_with_desired_topic();
        let topic = get_sample_contract_topic();
        let result = log.contains_topic(&topic);
        assert!(result);
    }

    #[test]
    fn sample_logs_with_desired_topic_should_contain_topic() {
        let logs = get_sample_logs_with_desired_topic();
        let topic = get_sample_contract_topic();
        let result = logs.contain_topic(&topic);
        assert!(result);
    }

    #[test]
    fn sample_logs_without_desired_topic_should_contain_topic() {
        let logs = get_sample_logs_without_desired_topic();
        let topic = get_sample_contract_topic();
        let result = logs.contain_topic(&topic);
        assert!(!result);
    }

    #[test]
    fn sample_log_receipt_with_desired_address_should_return_true() {
        let log = get_sample_log_with_desired_address();
        let address = get_sample_contract_address();
        let result = log.contains_address(&address);
        assert!(result);
    }

    #[test]
    fn sample_log_without_desired_address_should_return_false() {
        let log = get_sample_log_without_desired_address();
        let address = get_sample_contract_address();
        let result = log.contains_address(&address);
        assert!(!result);
    }

    #[test]
    fn sample_receipt_with_desired_address_should_return_true() {
        let receipt = get_sample_receipt_with_desired_address();
        let address = get_sample_contract_address();
        let result = receipt.logs.contain_address(&address);
        assert!(result);
    }

    #[test]
    fn sample_receipt_without_desired_address_should_return_false() {
        let receipt = get_sample_receipt_without_desired_address();
        let address = get_sample_contract_address();
        let result = receipt.logs.contain_address(&address);
        assert!(!result);
    }

    #[test]
    fn redeem_log_should_be_redeem() {
        let result = get_sample_log_with_redeem().is_btc_on_eth_redeem().unwrap();
        assert!(result);
    }

    #[test]
    fn non_redeem_log_should_not_be_redeem() {
        let result = &get_sample_receipt_with_redeem().logs.0[1]
            .is_btc_on_eth_redeem()
            .unwrap();
        assert!(!result);
    }

    #[test]
    fn should_parse_redeem_amount_from_log() {
        let expected_result = U256::from_dec_str("666").unwrap();
        let log = get_sample_log_with_redeem();
        let result = log.get_btc_on_eth_redeem_amount().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_parse_btc_address_from_log() {
        let expected_result = "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM";
        let log = get_sample_log_with_redeem();
        let result = log.get_btc_on_eth_btc_redeem_address().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_parse_p2sh_btc_address_from_log() {
        let expected_result = "2MyT7cyDnsHFwkhGDJa3LhayYtPN3cSE7wx";
        let log = get_sample_log_with_p2sh_redeem();
        let result = log.get_btc_on_eth_btc_redeem_address().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn check_is_erc20_peg_in_should_be_ok() {
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = log.check_is_erc20_peg_in();
        assert!(result.is_ok());
    }

    #[test]
    fn erc20_log_with_peg_in_should_be_erc20_log_with_peg_in() {
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = log.is_erc20_peg_in().unwrap();
        assert!(result);
    }

    #[test]
    fn erc20_log_with_peg_in_should_not_be_a_btc_on_eth_redeem() {
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = log.is_btc_on_eth_redeem().unwrap();
        assert!(!result);
    }

    #[test]
    fn should_get_erc20_peg_in_amount() {
        let expected_result = U256::from(1337);
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = log.get_erc20_on_eos_peg_in_amount().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_erc20_peg_in_token_contract_address() {
        let expected_result = EthAddress::from_slice(&hex::decode("9f57cb2a4f462a5258a49e88b4331068a391de66").unwrap());
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = log.get_erc20_on_eos_peg_in_token_contract_address().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_erc20_peg_in_token_sender_address() {
        let expected_result = EthAddress::from_slice(&hex::decode("fedfe2616eb3661cb8fed2782f5f0cc91d59dcac").unwrap());
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = log.get_erc20_on_eos_peg_in_token_sender_address().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_erc20_peg_in_eos_address() {
        let expected_result = "aneosaddress";
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = log.get_erc20_on_eos_peg_in_eos_address().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn is_supported_erc20_peg_in_should_be_true_if_supported() {
        let eth_token_decimals = 18;
        let eos_token_decimals = 9;
        let eth_symbol = "SAM".to_string();
        let eos_symbol = "SYM".to_string();
        let token_name = "SampleToken".to_string();
        let token_address = EthAddress::from_slice(&hex::decode("9f57CB2a4F462a5258a49E88B4331068a391DE66").unwrap());
        let eos_erc20_account_names = EosErc20Dictionary::new(vec![EosErc20DictionaryEntry::new(
            eth_token_decimals,
            eos_token_decimals,
            eth_symbol,
            eos_symbol,
            token_name,
            token_address,
        )]);
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = log.is_supported_erc20_peg_in(&eos_erc20_account_names).unwrap();
        assert!(result);
    }

    #[test]
    fn is_supported_erc20_peg_in_should_be_false_if_not_supported() {
        let eth_token_decimals = 18;
        let eos_token_decimals = 9;
        let eth_symbol = "SAM".to_string();
        let eos_symbol = "SYM".to_string();
        let token_name = "SampleToken".to_string();
        let token_address = EthAddress::from_slice(&hex::decode("8f57CB2a4F462a5258a49E88B4331068a391DE66").unwrap());
        let eos_erc20_account_names = EosErc20Dictionary::new(vec![EosErc20DictionaryEntry::new(
            eth_token_decimals,
            eos_token_decimals,
            eth_symbol,
            eos_symbol,
            token_name,
            token_address,
        )]);
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = log.is_supported_erc20_peg_in(&eos_erc20_account_names).unwrap();
        assert!(!result);
    }

    #[test]
    fn is_supported_erc20_peg_in_2_should_be_true_if_supported() {
        let eth_token_decimals = 18;
        let eos_token_decimals = 9;
        let eth_symbol = "SAM".to_string();
        let eos_symbol = "SYM".to_string();
        let token_name = "SampleToken".to_string();
        let token_address = EthAddress::from_slice(
            &hex::decode("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(), // NOTE wETH address on mainnet!
        );
        let eos_erc20_account_names = EosErc20Dictionary::new(vec![EosErc20DictionaryEntry::new(
            eth_token_decimals,
            eos_token_decimals,
            eth_symbol,
            eos_symbol,
            token_name,
            token_address,
        )]);
        let log = get_sample_log_with_erc20_peg_in_event_2().unwrap();
        let result = log.is_supported_erc20_peg_in(&eos_erc20_account_names).unwrap();
        assert!(result);
    }
}
