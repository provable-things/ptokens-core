use serde_json::{
    json,
    Value as JsonValue,
};
use ethereum_types::{
    U256,
    H256 as EthHash,
    Address as EthAddress,
};
use crate::{
    types::{
        Byte,
        Bytes,
        Result,
        NoneError,
    },
    traits::DatabaseInterface,
    btc_on_eth::eth::redeem_info::{
        BtcOnEthRedeemInfo,
        BtcOnEthRedeemInfos,
    },
    erc20_on_eos::eth::peg_in_info::{
        Erc20OnEosPegInInfo,
        Erc20OnEosPegInInfos,
    },
    chains::{
        eos::eos_erc20_dictionary::EosErc20Dictionary,
        eth::{
            eth_state::EthState,
            eth_block::{
                EthBlock,
                EthBlockJson,
            },
            eth_receipt::{
                EthReceipt,
                EthReceipts,
                EthReceiptJson,
            },
        },
    },
};

// TODO This could have some enum in it that defines what it's submission material for?
// TODO The same would need to be true of the Receipts themselves since that's where the redeem param parsing is done!
#[derive(Clone, Debug, PartialEq, Eq, Deserialize)]
pub struct EthSubmissionMaterial {
    pub block: Option<EthBlock>,
    pub receipts: EthReceipts,
    pub eos_ref_block_num: Option<u16>,
    pub eos_ref_block_prefix: Option<u32>,
    pub hash: Option<EthHash>,
    pub block_number: Option<U256>,
    pub parent_hash: Option<EthHash>,
    pub receipts_root: Option<EthHash>,
}

impl EthSubmissionMaterial {
    fn new(
        block: EthBlock,
        receipts: EthReceipts,
        eos_ref_block_num: Option<u16>,
        eos_ref_block_prefix: Option<u32>
    ) -> Self {
        Self {
            receipts,
            eos_ref_block_num,
            eos_ref_block_prefix,
            hash: Some(block.hash),
            block_number: Some(block.number),
            parent_hash: Some(block.parent_hash),
            receipts_root: Some(block.receipts_root),
            block: Some(block),
        }
    }

    pub fn get_block(&self) -> Result<EthBlock> {
        self.block.clone().ok_or(NoneError("✘ No block in ETH submisson material!"))
    }

    pub fn get_block_hash(&self) -> Result<EthHash> {
        self.hash.ok_or(NoneError("✘ No `hash` in ETH submission material!"))
    }

    pub fn get_parent_hash(&self) -> Result<EthHash> {
        self.parent_hash.ok_or(NoneError("✘ No` parent_hash` in ETH submission material!"))
    }

    pub fn get_block_number(&self) -> Result<U256> {
        self.block_number.ok_or(NoneError("✘ No `block_number` in ETH submission material!"))
    }

    pub fn get_receipts_root(&self) -> Result<EthHash> {
        self.receipts_root.ok_or(NoneError("✘ No `receipts_root` in ETH submission material!"))
    }

    pub fn get_eos_ref_block_num(&self) -> Result<u16> {
        self.eos_ref_block_num.ok_or(NoneError("No `eos_ref_block_num` in submission material!"))
    }

    pub fn get_eos_ref_block_prefix(&self) -> Result<u32> {
        self.eos_ref_block_prefix.ok_or(NoneError("No `eos_ref_block_prefix` in submission material!"))
    }

    pub fn get_receipts(&self) -> Vec<EthReceipt> {
        self.receipts.0.clone()
    }

    pub fn to_json(&self) -> Result<JsonValue> {
        let block_json = match &self.block {
            Some(block) => Some(block.to_json()?),
            None => None,
        };
        Ok(json!({
            "hash": self.hash,
            "block": block_json,
            "parent_hash": self.parent_hash,
            "block_number": self.block_number,
            "receipts_root": self.receipts_root,
            "eos_ref_block_num": self.eos_ref_block_num,
            "eos_ref_block_prefix": self.eos_ref_block_prefix,
            "receipts": self.receipts.0.iter().map(|receipt| receipt.to_json()).collect::<Result<Vec<JsonValue>>>()?,
        }))
    }

    pub fn from_bytes(bytes: &[Byte]) -> Result<Self> {
        Self::from_json(&serde_json::from_slice(bytes)?)
    }

    pub fn to_bytes(&self) -> Result<Bytes> {
        Ok(serde_json::to_vec(&self.to_json()?)?)
    }

    pub fn from_json(json: &EthSubmissionMaterialJson) -> Result<Self> {
        /*
         * NOTE: Legacy cores originally stored the full block. To reduce the size of the encrypted DB,
         * cores v1.19.0 and later remove the ETH block when saving to the db. Hence why here we
         * first check if there *is* a block in the json retrieved from the DB and then create the correct
         * (new) struct that way. Otherwise, we check the json correctly adheres to the new format
         * and if so create the struct from that instead.
         */
        let block = match json.block {
            Some(ref block_json) => Some(EthBlock::from_json(block_json)?),
            None => None,
        };
        let receipts = EthReceipts::from_jsons(&json.receipts.clone())?;
        match block {
            Some(block) => Ok(EthSubmissionMaterial {
                receipts,
                hash: Some(block.hash),
                block_number: Some(block.number),
                parent_hash: Some(block.parent_hash),
                receipts_root: Some(block.receipts_root),
                eos_ref_block_num: json.eos_ref_block_num,
                eos_ref_block_prefix: json.eos_ref_block_prefix,
                block: Some(block),
            }),
            None =>  {
                if json.hash.is_none() {
                    return Err("Error parsing `EthSubmissionInfo` from json: missing `hash`!".into())
                } else if json.parent_hash.is_none() {
                    return Err("Error parsing `EthSubmissionInfo` from json: missing `parent_hash`!".into())
                } else if json.block_number.is_none() {
                    return Err("Error parsing `EthSubmissionInfo` from json: missing `block_number`!".into())
                } else if json.receipts_root.is_none() {
                    return Err("Error parsing `EthSubmissionInfo` from json: missing `receipts_root`!".into())
                };
                Ok(EthSubmissionMaterial {
                    receipts,
                    block: None,
                    hash: json.hash,
                    parent_hash: json.parent_hash,
                    block_number: json.block_number,
                    receipts_root:json.receipts_root,
                    eos_ref_block_num: json.eos_ref_block_num,
                    eos_ref_block_prefix: json.eos_ref_block_prefix,
                })
            }
        }
    }

    pub fn from_str(json_str: &str) -> Result<Self> {
        Self::from_json(&EthSubmissionMaterialJson::from_str(json_str)?)
    }

    #[cfg(test)]
    pub fn to_string(&self) -> Result<String> {
        Ok(self.to_json()?.to_string())
    }

    pub fn filter_for_receipts_containing_log_with_address_and_topics(
        &self,
        address: &EthAddress,
        topics: &[EthHash],
    ) -> Result<Self> {
        info!("✔ Number of receipts before filtering: {}", self.receipts.len());
        let filtered = Self::new(
            self.get_block()?,
            self.receipts.filter_for_receipts_containing_log_with_address_and_topics(address, topics),
            self.eos_ref_block_num,
            self.eos_ref_block_prefix,
        );
        info!("✔ Number of receipts after filtering:  {}", filtered.receipts.len());
        Ok(filtered)
    }

    pub fn filter_receipts_containing_supported_erc20_peg_ins(
        &self,
        erc20_dictionary: &EosErc20Dictionary,
    ) -> Result<Self> {
        info!("✔ Num receipts before filtering for those pertaining to ERC20 dictionary: {}", self.receipts.len());
        let filtered_receipts = EthReceipts::new(
            self
                .receipts
                .iter()
                .filter(|receipt| receipt.contains_supported_erc20_peg_in(erc20_dictionary))
                .cloned()
                .collect()
        );
        info!("✔ Num receipts after filtering for those pertaining to ERC20 dictionary: {}", filtered_receipts.len());
        Ok(Self::new(self.get_block()?, filtered_receipts, self.eos_ref_block_num, self.eos_ref_block_prefix))
    }

    pub fn receipts_are_valid(&self) -> Result<bool> {
        self
            .receipts
            .get_merkle_root()
            .and_then(|calculated_root| {
                let receipts_root = self.get_receipts_root()?;
                info!("✔    Block's receipts root: {}", receipts_root.to_string());
                info!("✔ Calculated receipts root: {}", calculated_root.to_string());
                Ok(calculated_root == receipts_root)
            })
    }

    pub fn get_btc_on_eth_redeem_infos(&self) -> Result<BtcOnEthRedeemInfos> {
        info!("✔ Getting `btc-on-eth` redeem infos from submission material...");
        Ok(BtcOnEthRedeemInfos::new(
            self
                .get_receipts()
                .iter()
                .map(|receipt| receipt.get_btc_on_eth_redeem_infos())
                .collect::<Result<Vec<Vec<BtcOnEthRedeemInfo>>>>()?
                .concat()
        ))
    }

    pub fn get_erc20_on_eos_peg_in_infos(
        &self,
        eos_erc20_dictionary: &EosErc20Dictionary
    ) -> Result<Erc20OnEosPegInInfos> {
        info!("✔ Getting `erc20-on-eos` peg in infos from submission material...");
        Ok(Erc20OnEosPegInInfos::new(
            self
                .get_receipts()
                .iter()
                .map(|receipt| receipt.get_erc20_on_eos_peg_in_infos(eos_erc20_dictionary))
                .collect::<Result<Vec<Erc20OnEosPegInInfos>>>()?
                .iter()
                .map(|infos| infos.iter().cloned().collect())
                .collect::<Vec<Vec<Erc20OnEosPegInInfo>>>()
                .concat()
        ))
    }

    pub fn remove_receipts(&self) -> Self {
        EthSubmissionMaterial {
            hash: self.hash,
            receipts: vec![].into(),
            block: self.block.clone(),
            parent_hash: self.parent_hash,
            block_number: self.block_number,
            receipts_root: self.receipts_root,
            eos_ref_block_num: self.eos_ref_block_num,
            eos_ref_block_prefix: self.eos_ref_block_prefix,
        }
    }

    pub fn remove_block(&self) -> Self {
        EthSubmissionMaterial {
            block: None,
            hash: self.hash,
            parent_hash: self.parent_hash,
            receipts: self.receipts.clone(),
            block_number: self.block_number,
            receipts_root: self.receipts_root,
            eos_ref_block_num: self.eos_ref_block_num,
            eos_ref_block_prefix: self.eos_ref_block_prefix,
        }
    }
}

#[derive(Clone, Debug, Deserialize)]
pub struct EthSubmissionMaterialJson {
    pub block: Option<EthBlockJson>,
    pub receipts: Vec<EthReceiptJson>,
    pub eos_ref_block_num: Option<u16>,
    pub eos_ref_block_prefix: Option<u32>,
    pub hash: Option<EthHash>,
    pub block_number: Option<U256>,
    pub parent_hash: Option<EthHash>,
    pub receipts_root: Option<EthHash>,
}

impl EthSubmissionMaterialJson {
    pub fn from_str(json_str: &str) -> Result<Self> {
        match serde_json::from_str(&json_str) {
            Ok(result) => Ok(result),
            Err(e) => Err(e.into())
        }
    }
}

pub fn parse_eth_submission_material_and_put_in_state<D>(
    block_json: &str,
    state: EthState<D>,
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    info!("✔ Parsing ETH block & receipts...");
    EthSubmissionMaterial::from_str(&block_json).and_then(|result| state.add_eth_submission_material(result))
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
                eth_constants::BTC_ON_ETH_REDEEM_EVENT_TOPIC_HEX,
                eth_test_utils::{
                    get_sample_erc20_on_eos_peg_in_infos,
                    get_sample_submission_material_with_erc20_peg_in_event,
                },
            },
        },
        btc_on_eth::eth::eth_test_utils::{
            get_expected_block,
            get_expected_receipt,
            SAMPLE_RECEIPT_INDEX,
            get_sample_contract_topics,
            get_sample_contract_address,
            get_sample_eth_submission_material,
            get_sample_eth_submission_material_n,
            get_sample_eth_submission_material_string,
        },
    };

    #[test]
    fn should_parse_eth_submission_material_json_string() {
        let json_string = get_sample_eth_submission_material_string(0).unwrap();
        if EthSubmissionMaterial::from_str(&json_string).is_err() {
            panic!("SHould parse eth block and json string correctly!");
        }
    }

    #[test]
    fn should_parse_eth_submission_material_json() {
        let json_string = get_sample_eth_submission_material_string(0).unwrap();
        let submission_material = EthSubmissionMaterial::from_str(&json_string).unwrap();
        let block = submission_material.get_block().unwrap();
        let receipt = submission_material.receipts.0[SAMPLE_RECEIPT_INDEX].clone();
        let expected_block = get_expected_block();
        let expected_receipt = get_expected_receipt();
        assert_eq!(block, expected_block);
        assert_eq!(receipt, expected_receipt);
    }

    #[test]
    fn should_make_to_and_from_string_round_trip() {
        let block_and_receipts = EthSubmissionMaterial::from_str(
            &get_sample_eth_submission_material_string(0).unwrap()
        ).unwrap();
        let string = block_and_receipts.to_string().unwrap();
        let result = EthSubmissionMaterial::from_str(&string).unwrap();
        assert_eq!(result, block_and_receipts);
    }

    #[test]
    fn should_decode_block_and_recipts_json_correctly() {
        let block_and_receipts = get_sample_eth_submission_material();
        let bytes = block_and_receipts.to_bytes().unwrap();
        let result = EthSubmissionMaterial::from_bytes(&bytes).unwrap();
        assert_eq!(result.block, block_and_receipts.block);
        block_and_receipts
            .receipts
            .0
            .iter()
            .enumerate()
            .map(|(i, receipt)| assert_eq!(receipt, &result.receipts.0[i]))
            .for_each(drop);
    }

    #[test]
    fn should_make_to_and_from_bytes_round_trip_correctly() {
        let block_and_receipts = get_sample_eth_submission_material();
        let bytes = block_and_receipts.to_bytes().unwrap();
        let result = EthSubmissionMaterial::from_bytes(&bytes).unwrap();
        assert_eq!(result, block_and_receipts);
    }

    #[test]
    fn should_filter_eth_submission_material() {
        let block_and_receipts = get_sample_eth_submission_material();
        let num_receipts_before = block_and_receipts.receipts.len();
        let address = get_sample_contract_address();
        let topics = get_sample_contract_topics();
        let result = block_and_receipts.filter_for_receipts_containing_log_with_address_and_topics(&address, &topics)
            .unwrap();
        let num_receipts_after = result.receipts.len();
        assert!(num_receipts_before > num_receipts_after);
        result
            .receipts
            .0
            .iter()
            .map(|receipt| {
                assert!(receipt.logs.contain_topic(&topics[0]));
                receipt
            })
            .map(|receipt| assert!(receipt.logs.contain_address(&address)))
            .for_each(drop);
    }

    #[test]
    fn should_filter_eth_submission_material_2() {
        let expected_num_receipts_after = 1;
        let block_and_receipts = get_sample_eth_submission_material_n(6).unwrap();
        let num_receipts_before = block_and_receipts.receipts.len();
        let address = EthAddress::from_slice(&hex::decode("74630cfbc4066726107a4efe73956e219bbb46ab").unwrap());
        let topics = vec![EthHash::from_slice(&hex::decode(BTC_ON_ETH_REDEEM_EVENT_TOPIC_HEX).unwrap()) ];
        let result = block_and_receipts.filter_for_receipts_containing_log_with_address_and_topics(&address, &topics)
            .unwrap();
        let num_receipts_after = result.receipts.len();
        assert!(num_receipts_before > num_receipts_after);
        assert_eq!(num_receipts_after, expected_num_receipts_after);
        result
            .receipts
            .0
            .iter()
            .map(|receipt| {
                assert!(receipt.logs.contain_topic(&topics[0]));
                receipt
            })
            .map(|receipt| assert!(receipt.logs.contain_address(&address)))
            .for_each(drop);
    }

    #[test]
    fn should_return_true_if_receipts_root_is_correct() {
        let block_and_receipts = get_sample_eth_submission_material();
        let result = block_and_receipts.receipts_are_valid().unwrap();
        assert!(result);
    }

    fn get_sample_block_with_redeem() -> EthSubmissionMaterial {
        get_sample_eth_submission_material_n(4).unwrap()
    }

    fn get_tx_hash_of_redeem_tx() -> &'static str {
        "442612aba789ce873bb3804ff62ced770dcecb07d19ddcf9b651c357eebaed40"
    }

    #[test]
    fn should_parse_btc_on_eth_redeem_params_from_block() {
        let result = get_sample_block_with_redeem().get_btc_on_eth_redeem_infos().unwrap();
        let expected_result = BtcOnEthRedeemInfo {
            amount: U256::from_dec_str("666").unwrap(),
            from: EthAddress::from_str("edb86cd455ef3ca43f0e227e00469c3bdfa40628").unwrap(),
            recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
            originating_tx_hash: EthHash::from_slice(&hex::decode(get_tx_hash_of_redeem_tx()) .unwrap()[..]),
        };
        assert_eq!(expected_result.from, result.0[0].from);
        assert_eq!(expected_result.amount, result.0[0].amount);
        assert_eq!(expected_result.recipient, result.0[0].recipient);
        assert_eq!(expected_result.originating_tx_hash, result.0[0].originating_tx_hash);
    }

    #[test]
    fn should_remove_receipts_from_block_and_receipts() {
        let block_and_receipts = get_sample_eth_submission_material();
        let num_receipts_before = block_and_receipts.receipts.len();
        assert!(num_receipts_before > 0);
        let result = block_and_receipts.remove_receipts();
        let num_receipts_after = result.receipts.len();
        assert_eq!(num_receipts_after, 0);
    }

    #[test]
    fn should_get_erc20_on_eos_peg_in_infos() {
        let eth_token_decimals = 18;
        let eos_token_decimals = 9;
        let eth_symbol = "SAM".to_string();
        let eos_symbol = "SAM".to_string();
        let token_name = "SampleToken".to_string();
        let token_address = EthAddress::from_slice(
            &hex::decode("9f57CB2a4F462a5258a49E88B4331068a391DE66").unwrap()
        );
        let eos_erc20_account_names = EosErc20Dictionary::new(vec![
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
        let submission_material = get_sample_submission_material_with_erc20_peg_in_event().unwrap();
        let expected_result = get_sample_erc20_on_eos_peg_in_infos().unwrap();
        let result = submission_material.get_erc20_on_eos_peg_in_infos(&eos_erc20_account_names).unwrap();
        assert_eq!(result.len(), expected_num_results);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_filter_submission_material_for_receipts_containing_supported_erc20_peg_ins() {
        let expected_num_receipts_after = 1;
        let expected_num_receipts_before = 69;
        let erc20_dictionary = get_sample_eos_erc20_dictionary();
        let submission_material = get_sample_submission_material_with_erc20_peg_in_event().unwrap();
        let num_receipts_before = submission_material.receipts.len();
        assert_eq!(num_receipts_before, expected_num_receipts_before);
        let filtered_submission_material = submission_material
            .filter_receipts_containing_supported_erc20_peg_ins(&erc20_dictionary)
            .unwrap();
        let num_receipts_after = filtered_submission_material.receipts.len();
        assert_eq!(num_receipts_after, expected_num_receipts_after);
    }
}
