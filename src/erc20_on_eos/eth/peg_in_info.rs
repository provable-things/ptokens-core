use std::str::FromStr;

use derive_more::{Constructor, Deref};
use eos_primitives::AccountName as EosAccountName;
use ethereum_types::{Address as EthAddress, H256 as EthHash, U256};

use crate::{
    chains::{
        eos::{eos_eth_token_dictionary::EosEthTokenDictionary, eos_utils::remove_symbol_from_eos_asset},
        eth::{
            eth_constants::{
                ERC20_ON_EOS_PEG_IN_EVENT_TOPIC,
                ERC20_PEG_IN_EVENT_TOPIC_HEX,
                ETH_ADDRESS_SIZE_IN_BYTES,
                ETH_WORD_SIZE_IN_BYTES,
            },
            eth_database_utils::{get_erc20_on_eos_smart_contract_address_from_db, get_eth_canon_block_from_db},
            eth_log::{EthLog, EthLogs},
            eth_receipt::{EthReceipt, EthReceipts},
            eth_state::EthState,
            eth_submission_material::EthSubmissionMaterial,
        },
    },
    constants::SAFE_EOS_ADDRESS,
    traits::DatabaseInterface,
    types::Result,
};

pub const NOT_ENOUGH_BYTES_IN_LOG_DATA_ERR: &str = "Not enough bytes in log data!";

#[derive(Debug, Clone, PartialEq, Eq, Constructor)]
pub struct Erc20OnEosPegInInfo {
    pub token_amount: U256,
    pub token_sender: EthAddress,
    pub eth_token_address: EthAddress,
    pub eos_address: String,
    pub originating_tx_hash: EthHash,
    pub eos_token_address: String,
    pub eos_asset_amount: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Constructor, Deref)]
pub struct Erc20OnEosPegInInfos(pub Vec<Erc20OnEosPegInInfo>);

impl Erc20OnEosPegInInfos {
    pub fn filter_out_zero_eos_values(&self) -> Result<Self> {
        Ok(Self::new(
            self.iter()
                .filter(|peg_in_info| {
                    match remove_symbol_from_eos_asset(&peg_in_info.eos_asset_amount).parse::<f64>() != Ok(0.0) {
                        true => true,
                        false => {
                            info!(
                                "✘ Filtering out peg in info due to zero EOS asset amount: {:?}",
                                peg_in_info
                            );
                            false
                        },
                    }
                })
                .cloned()
                .collect::<Vec<Erc20OnEosPegInInfo>>(),
        ))
    }

    fn is_log_erc20_peg_in(log: &EthLog) -> Result<bool> {
        Ok(log.contains_topic(&EthHash::from_slice(&hex::decode(&ERC20_PEG_IN_EVENT_TOPIC_HEX)?[..])))
    }

    pub fn is_log_supported_erc20_peg_in(log: &EthLog, token_dictionary: &EosEthTokenDictionary) -> Result<bool> {
        match Self::is_log_erc20_peg_in(log)? {
            false => Ok(false),
            true => Self::get_token_contract_address_from_log(log)
                .map(|token_contract_address| token_dictionary.is_token_supported(&token_contract_address)),
        }
    }

    fn check_log_is_erc20_peg_in(log: &EthLog) -> Result<()> {
        trace!("✔ Checking if log is an erc20 peg in...");
        match Self::is_log_erc20_peg_in(log)? {
            true => Ok(()),
            false => Err("✘ Log is not from an erc20 peg in event!".into()),
        }
    }

    fn get_peg_in_amount_from_log(log: &EthLog) -> Result<U256> {
        Self::check_log_is_erc20_peg_in(log).and_then(|_| {
            const START_INDEX: usize = ETH_WORD_SIZE_IN_BYTES * 2;
            const END_INDEX: usize = ETH_WORD_SIZE_IN_BYTES * 3;
            match log.data.len() >= END_INDEX {
                true => {
                    let amount = U256::from(&log.data[START_INDEX..END_INDEX]);
                    info!("✔ Parsed `erc20-on-eos` peg in amount from log: {}", amount.to_string());
                    Ok(amount)
                },
                false => Err(NOT_ENOUGH_BYTES_IN_LOG_DATA_ERR.into()),
            }
        })
    }

    fn get_token_contract_address_from_log(log: &EthLog) -> Result<EthAddress> {
        Self::check_log_is_erc20_peg_in(log).and_then(|_| {
            info!("✔ Parsing `erc20-on-eos` peg in token contract address from log...");
            const START_INDEX: usize = ETH_WORD_SIZE_IN_BYTES - ETH_ADDRESS_SIZE_IN_BYTES;
            const END_INDEX: usize = START_INDEX + ETH_ADDRESS_SIZE_IN_BYTES;
            match log.data.len() >= END_INDEX {
                true => Ok(EthAddress::from_slice(&log.data[START_INDEX..END_INDEX])),
                false => Err(NOT_ENOUGH_BYTES_IN_LOG_DATA_ERR.into()),
            }
        })
    }

    fn get_token_sender_address_from_log(log: &EthLog) -> Result<EthAddress> {
        Self::check_log_is_erc20_peg_in(log).and_then(|_| {
            info!("✔ Parsing `erc20-on-eos` peg in token sender address from log...");
            const START_INDEX: usize = ETH_WORD_SIZE_IN_BYTES * 2 - ETH_ADDRESS_SIZE_IN_BYTES;
            const END_INDEX: usize = START_INDEX + ETH_ADDRESS_SIZE_IN_BYTES;
            match log.data.len() >= END_INDEX {
                true => Ok(EthAddress::from_slice(&log.data[START_INDEX..END_INDEX])),
                false => Err(NOT_ENOUGH_BYTES_IN_LOG_DATA_ERR.into()),
            }
        })
    }

    fn get_eos_address_from_log(log: &EthLog) -> Result<String> {
        Self::check_log_is_erc20_peg_in(log).and(Ok(Self::extract_eos_address_or_default_to_safe_address(log)))
    }

    fn extract_eos_address_from_log(log: &EthLog) -> String {
        info!("✔ Parsing EOS address from log...");
        const START_INDEX: usize = ETH_WORD_SIZE_IN_BYTES * 5;
        log.data[START_INDEX..]
            .iter()
            .filter(|byte| *byte != &0u8)
            .map(|byte| *byte as char)
            .collect()
    }

    fn extract_eos_address_or_default_to_safe_address(log: &EthLog) -> String {
        let maybe_eos_address = Self::extract_eos_address_from_log(log);
        match EosAccountName::from_str(&maybe_eos_address) {
            Ok(_) => maybe_eos_address,
            Err(_) => {
                info!("✘ Could not parse EOS address from: {}", maybe_eos_address);
                info!("✔ Defaulting to safe EOS address: {}", SAFE_EOS_ADDRESS);
                SAFE_EOS_ADDRESS.to_string()
            },
        }
    }

    fn receipt_contains_supported_erc20_peg_in(receipt: &EthReceipt, token_dictionary: &EosEthTokenDictionary) -> bool {
        Self::get_supported_erc20_peg_in_logs_from_receipt(receipt, token_dictionary).len() > 0
    }

    fn get_supported_erc20_peg_in_logs_from_receipt(
        receipt: &EthReceipt,
        token_dictionary: &EosEthTokenDictionary,
    ) -> EthLogs {
        EthLogs::new(
            receipt
                .logs
                .iter()
                .filter(|log| matches!(Self::is_log_supported_erc20_peg_in(&log, token_dictionary), Ok(true)))
                .cloned()
                .collect(),
        )
    }

    fn from_eth_receipt(receipt: &EthReceipt, token_dictionary: &EosEthTokenDictionary) -> Result<Self> {
        info!("✔ Getting `erc20-on-eos` peg in infos from receipt...");
        Ok(Self::new(
            Self::get_supported_erc20_peg_in_logs_from_receipt(receipt, token_dictionary)
                .iter()
                .map(|log| {
                    let token_contract_address = Self::get_token_contract_address_from_log(&log)?;
                    let eth_amount = Self::get_peg_in_amount_from_log(&log)?;
                    let peg_in_info = Erc20OnEosPegInInfo::new(
                        eth_amount,
                        Self::get_token_sender_address_from_log(&log)?,
                        token_contract_address,
                        Self::get_eos_address_from_log(&log)?,
                        receipt.transaction_hash,
                        token_dictionary.get_eos_account_name_from_eth_token_address(&token_contract_address)?,
                        token_dictionary.convert_u256_to_eos_asset_string(&token_contract_address, &eth_amount)?,
                    );
                    info!("✔ Parsed peg in info: {:?}", peg_in_info);
                    Ok(peg_in_info)
                })
                .collect::<Result<Vec<Erc20OnEosPegInInfo>>>()?,
        ))
    }

    fn filter_eth_sub_mat_for_supported_peg_ins(
        submission_material: &EthSubmissionMaterial,
        token_dictionary: &EosEthTokenDictionary,
    ) -> Result<EthSubmissionMaterial> {
        info!("✔ Filtering submission material receipts for those pertaining to `erc20-on-eos` peg-ins...");
        info!(
            "✔ Num receipts before filtering: {}",
            submission_material.receipts.len()
        );
        let filtered_receipts = EthReceipts::new(
            submission_material
                .receipts
                .iter()
                .filter(|receipt| {
                    Erc20OnEosPegInInfos::receipt_contains_supported_erc20_peg_in(&receipt, token_dictionary)
                })
                .cloned()
                .collect(),
        );
        info!("✔ Num receipts after filtering: {}", filtered_receipts.len());
        Ok(EthSubmissionMaterial::new(
            submission_material.get_block()?,
            filtered_receipts,
            submission_material.eos_ref_block_num,
            submission_material.eos_ref_block_prefix,
        ))
    }

    pub fn from_submission_material(
        submission_material: &EthSubmissionMaterial,
        eos_eth_token_dictionary: &EosEthTokenDictionary,
    ) -> Result<Self> {
        info!("✔ Getting `Erc20OnEosPegInInfos` from submission material...");
        Ok(Self::new(
            submission_material
                .get_receipts()
                .iter()
                .map(|receipt| Self::from_eth_receipt(&receipt, eos_eth_token_dictionary))
                .collect::<Result<Vec<Erc20OnEosPegInInfos>>>()?
                .iter()
                .map(|infos| infos.iter().cloned().collect())
                .collect::<Vec<Vec<Erc20OnEosPegInInfo>>>()
                .concat(),
        ))
    }
}

pub fn maybe_parse_peg_in_info_from_canon_block_and_add_to_state<D: DatabaseInterface>(
    state: EthState<D>,
) -> Result<EthState<D>> {
    info!("✔ Maybe parsing `erc20-on-eos` peg-in infos...");
    get_eth_canon_block_from_db(&state.db).and_then(|submission_material| {
        match submission_material.receipts.is_empty() {
            true => {
                info!("✔ No receipts in canon block ∴ no info to parse!");
                Ok(state)
            },
            false => {
                info!(
                    "✔ {} receipts in canon block ∴ parsing info...",
                    submission_material.receipts.len()
                );
                EosEthTokenDictionary::get_from_db(&state.db)
                    .and_then(|account_names| {
                        Erc20OnEosPegInInfos::from_submission_material(&submission_material, &account_names)
                    })
                    .and_then(|peg_in_infos| state.add_erc20_on_eos_peg_in_infos(peg_in_infos))
            },
        }
    })
}

pub fn filter_out_zero_value_peg_ins_from_state<D: DatabaseInterface>(state: EthState<D>) -> Result<EthState<D>> {
    info!("✔ Maybe filtering `erc20-on-eos` peg-in infos...");
    debug!("✔ Num peg-in infos before: {}", state.erc20_on_eos_peg_in_infos.len());
    state
        .erc20_on_eos_peg_in_infos
        .filter_out_zero_eos_values()
        .and_then(|filtered_peg_ins| {
            debug!("✔ Num peg-in infos after: {}", filtered_peg_ins.len());
            state.replace_erc20_on_eos_peg_in_infos(filtered_peg_ins)
        })
}

pub fn filter_submission_material_for_peg_in_events_in_state<D: DatabaseInterface>(
    state: EthState<D>,
) -> Result<EthState<D>> {
    info!("✔ Filtering receipts for those containing `erc20-on-eos` peg in events...");
    state
        .get_eth_submission_material()?
        .get_receipts_containing_log_from_address_and_with_topics(
            &get_erc20_on_eos_smart_contract_address_from_db(&state.db)?,
            &ERC20_ON_EOS_PEG_IN_EVENT_TOPIC.to_vec(),
        )
        .and_then(|filtered_submission_material| {
            Erc20OnEosPegInInfos::filter_eth_sub_mat_for_supported_peg_ins(
                &filtered_submission_material,
                state.get_eos_eth_token_dictionary()?,
            )
        })
        .and_then(|filtered_submission_material| state.update_eth_submission_material(filtered_submission_material))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::{
        eos::{
            eos_eth_token_dictionary::EosEthTokenDictionaryEntry,
            eos_test_utils::get_sample_eos_eth_token_dictionary,
        },
        eth::eth_test_utils::{
            get_sample_erc20_on_eos_peg_in_info,
            get_sample_erc20_on_eos_peg_in_infos,
            get_sample_log_with_erc20_peg_in_event,
            get_sample_log_with_erc20_peg_in_event_2,
            get_sample_receipt_with_erc20_peg_in_event,
            get_sample_submission_material_with_erc20_peg_in_event,
        },
    };

    fn get_sample_zero_eos_asset_peg_in_info() -> Erc20OnEosPegInInfo {
        Erc20OnEosPegInInfo::new(
            U256::from_dec_str("1337").unwrap(),
            EthAddress::from_slice(&hex::decode("edB86cd455ef3ca43f0e227e00469C3bDFA40628").unwrap()),
            EthAddress::from_slice(&hex::decode("d879D3C8782aB95a43C69Fa73d8DCC50C8815d5e").unwrap()),
            "aneosaddress".to_string(),
            EthHash::from_slice(
                &hex::decode("7b7f73183fe4d1d6e23c494ba0b579718c7dd6e1c62426fd5411a6a21b3203aa").unwrap(),
            ),
            "aneosaccount".to_string(),
            "0.000000000 SAM".to_string(),
        )
    }

    #[test]
    fn should_filter_out_zero_eos_asset_peg_ins() {
        let expected_num_peg_ins_before = 1;
        let expected_num_peg_ins_after = 0;
        let peg_ins = Erc20OnEosPegInInfos::new(vec![get_sample_zero_eos_asset_peg_in_info()]);
        assert_eq!(peg_ins.len(), expected_num_peg_ins_before);
        let result = peg_ins.filter_out_zero_eos_values().unwrap();
        assert_eq!(result.len(), expected_num_peg_ins_after);
    }

    #[test]
    fn log_is_supported_erc20_peg_in_should_be_true_if_supported() {
        let eth_token_decimals = 18;
        let eos_token_decimals = 9;
        let eth_symbol = "SAM".to_string();
        let eos_symbol = "SYM".to_string();
        let token_name = "SampleToken".to_string();
        let token_address = EthAddress::from_slice(&hex::decode("9f57CB2a4F462a5258a49E88B4331068a391DE66").unwrap());
        let token_dictionary = EosEthTokenDictionary::new(vec![EosEthTokenDictionaryEntry::new(
            eth_token_decimals,
            eos_token_decimals,
            eth_symbol,
            eos_symbol,
            token_name,
            token_address,
        )]);
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = Erc20OnEosPegInInfos::is_log_supported_erc20_peg_in(&log, &token_dictionary).unwrap();
        assert!(result);
    }

    #[test]
    fn log_is_supported_erc20_peg_in_should_be_false_if_not_supported() {
        let eth_token_decimals = 18;
        let eos_token_decimals = 9;
        let eth_symbol = "SAM".to_string();
        let eos_symbol = "SYM".to_string();
        let token_name = "SampleToken".to_string();
        let token_address = EthAddress::from_slice(&hex::decode("8f57CB2a4F462a5258a49E88B4331068a391DE66").unwrap());
        let token_dictionary = EosEthTokenDictionary::new(vec![EosEthTokenDictionaryEntry::new(
            eth_token_decimals,
            eos_token_decimals,
            eth_symbol,
            eos_symbol,
            token_name,
            token_address,
        )]);
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = Erc20OnEosPegInInfos::is_log_supported_erc20_peg_in(&log, &token_dictionary).unwrap();
        assert!(!result);
    }

    #[test]
    fn log_is_supported_erc20_peg_in_2_should_be_true_if_supported() {
        let eth_token_decimals = 18;
        let eos_token_decimals = 9;
        let eth_symbol = "SAM".to_string();
        let eos_symbol = "SYM".to_string();
        let token_name = "SampleToken".to_string();
        let token_address = EthAddress::from_slice(
            &hex::decode("c02aaa39b223fe8d0a0e5c4f27ead9083c756cc2").unwrap(), // NOTE wETH address on mainnet!
        );
        let token_dictionary = EosEthTokenDictionary::new(vec![EosEthTokenDictionaryEntry::new(
            eth_token_decimals,
            eos_token_decimals,
            eth_symbol,
            eos_symbol,
            token_name,
            token_address,
        )]);
        let log = get_sample_log_with_erc20_peg_in_event_2().unwrap();
        let result = Erc20OnEosPegInInfos::is_log_supported_erc20_peg_in(&log, &token_dictionary).unwrap();
        assert!(result);
    }

    #[test]
    fn erc20_log_with_peg_in_should_be_erc20_log_with_peg_in() {
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = Erc20OnEosPegInInfos::is_log_erc20_peg_in(&log).unwrap();
        assert!(result);
    }

    #[test]
    fn check_is_erc20_peg_in_should_be_ok() {
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = Erc20OnEosPegInInfos::check_log_is_erc20_peg_in(&log);
        assert!(result.is_ok());
    }

    #[test]
    fn should_get_erc20_peg_in_amount() {
        let expected_result = U256::from(1337);
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = Erc20OnEosPegInInfos::get_peg_in_amount_from_log(&log).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_erc20_peg_in_token_contract_address() {
        let expected_result = EthAddress::from_slice(&hex::decode("9f57cb2a4f462a5258a49e88b4331068a391de66").unwrap());
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = Erc20OnEosPegInInfos::get_token_contract_address_from_log(&log).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_erc20_peg_in_token_sender_address() {
        let expected_result = EthAddress::from_slice(&hex::decode("fedfe2616eb3661cb8fed2782f5f0cc91d59dcac").unwrap());
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = Erc20OnEosPegInInfos::get_token_sender_address_from_log(&log).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_erc20_peg_in_eos_address() {
        let expected_result = "aneosaddress";
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = Erc20OnEosPegInInfos::get_eos_address_from_log(&log).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_return_true_if_receipt_contains_log_with_erc20_peg_in() {
        let dictionary = get_sample_eos_eth_token_dictionary();
        let receipt = get_sample_receipt_with_erc20_peg_in_event().unwrap();
        let result = Erc20OnEosPegInInfos::receipt_contains_supported_erc20_peg_in(&receipt, &dictionary);
        assert!(result);
    }

    #[test]
    fn should_return_false_if_receipt_does_not_contain_log_with_erc20_peg_in() {
        let dictionary = EosEthTokenDictionary::new(vec![]);
        let receipt = get_sample_receipt_with_erc20_peg_in_event().unwrap();
        let result = Erc20OnEosPegInInfos::receipt_contains_supported_erc20_peg_in(&receipt, &dictionary);
        assert!(!result);
    }

    #[test]
    fn should_get_supported_erc20_peg_in_logs() {
        let expected_result = EthLogs::new(vec![EthLog {
            address: EthAddress::from_slice(&hex::decode("d0a3d2d3d19a6ac58e60254fd606ec766638c3ba").unwrap()),
            topics: vec![EthHash::from_slice(&hex::decode("42877668473c4cba073df41397388516dc85c3bbae14b33603513924cec55e36").unwrap())],
            data: hex::decode("0000000000000000000000009f57cb2a4f462a5258a49e88b4331068a391de66000000000000000000000000fedfe2616eb3661cb8fed2782f5f0cc91d59dcac00000000000000000000000000000000000000000000000000000000000005390000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000000c616e656f73616464726573730000000000000000000000000000000000000000").unwrap(),
        }]);
        let expected_num_logs = 1;
        let dictionary = get_sample_eos_eth_token_dictionary();
        let receipt = get_sample_receipt_with_erc20_peg_in_event().unwrap();
        let result = Erc20OnEosPegInInfos::get_supported_erc20_peg_in_logs_from_receipt(&receipt, &dictionary);
        assert_eq!(result.len(), expected_num_logs);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_get_erc20_redeem_infos_from_receipt() {
        let eth_token_decimals = 18;
        let eos_token_decimals = 9;
        let eth_symbol = "SAM".to_string();
        let eos_symbol = "SAM".to_string();
        let token_name = "SampleToken".to_string();
        let token_address = EthAddress::from_slice(&hex::decode("9f57CB2a4F462a5258a49E88B4331068a391DE66").unwrap());
        let token_dictionary = EosEthTokenDictionary::new(vec![EosEthTokenDictionaryEntry::new(
            eth_token_decimals,
            eos_token_decimals,
            eth_symbol,
            eos_symbol,
            token_name,
            token_address,
        )]);
        let expected_num_results = 1;
        let expected_result = get_sample_erc20_on_eos_peg_in_info().unwrap();
        let receipt = get_sample_receipt_with_erc20_peg_in_event().unwrap();
        let result = Erc20OnEosPegInInfos::from_eth_receipt(&receipt, &token_dictionary).unwrap();
        assert_eq!(result.len(), expected_num_results);
        assert_eq!(result.0[0], expected_result);
    }

    #[test]
    fn should_not_get_get_erc20_redeem_infos_from_receipt_if_token_not_supported() {
        let token_dictionary = EosEthTokenDictionary::new(vec![]);
        let expected_num_results = 0;
        let receipt = get_sample_receipt_with_erc20_peg_in_event().unwrap();
        let result = Erc20OnEosPegInInfos::from_eth_receipt(&receipt, &token_dictionary).unwrap();
        assert_eq!(result.len(), expected_num_results);
    }

    #[test]
    fn should_filter_submission_material_for_receipts_containing_supported_erc20_peg_ins() {
        let expected_num_receipts_after = 1;
        let expected_num_receipts_before = 69;
        let token_dictionary = get_sample_eos_eth_token_dictionary();
        let submission_material = get_sample_submission_material_with_erc20_peg_in_event().unwrap();
        let num_receipts_before = submission_material.receipts.len();
        assert_eq!(num_receipts_before, expected_num_receipts_before);
        let filtered_submission_material =
            Erc20OnEosPegInInfos::filter_eth_sub_mat_for_supported_peg_ins(&submission_material, &token_dictionary)
                .unwrap();
        let num_receipts_after = filtered_submission_material.receipts.len();
        assert_eq!(num_receipts_after, expected_num_receipts_after);
    }

    #[test]
    fn should_get_erc20_on_eos_peg_in_infos() {
        let eth_token_decimals = 18;
        let eos_token_decimals = 9;
        let eth_symbol = "SAM".to_string();
        let eos_symbol = "SAM".to_string();
        let token_name = "SampleToken".to_string();
        let token_address = EthAddress::from_slice(&hex::decode("9f57CB2a4F462a5258a49E88B4331068a391DE66").unwrap());
        let token_dictionary = EosEthTokenDictionary::new(vec![EosEthTokenDictionaryEntry::new(
            eth_token_decimals,
            eos_token_decimals,
            eth_symbol,
            eos_symbol,
            token_name,
            token_address,
        )]);
        let expected_num_results = 1;
        let submission_material = get_sample_submission_material_with_erc20_peg_in_event().unwrap();
        let expected_result = get_sample_erc20_on_eos_peg_in_infos().unwrap();
        let result = Erc20OnEosPegInInfos::from_submission_material(&submission_material, &token_dictionary).unwrap();
        assert_eq!(result.len(), expected_num_results);
        assert_eq!(result, expected_result);
    }
}
