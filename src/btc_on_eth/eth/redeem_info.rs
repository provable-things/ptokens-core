use std::str::FromStr;

use bitcoin::util::address::Address as BtcAddress;
use derive_more::{Constructor, Deref, IntoIterator};
use ethereum_types::{Address as EthAddress, H256 as EthHash, U256};

use crate::{
    btc_on_eth::utils::convert_ptoken_to_satoshis,
    chains::{
        btc::btc_types::{BtcRecipientAndAmount, BtcRecipientsAndAmounts},
        eth::{
            eth_constants::{
                BTC_ON_ETH_REDEEM_EVENT_TOPIC_HEX,
                ETH_WORD_SIZE_IN_BYTES,
                LOG_DATA_BTC_ADDRESS_START_INDEX,
            },
            eth_database_utils::get_eth_canon_block_from_db,
            eth_log::EthLog,
            eth_receipt::EthReceipt,
            eth_state::EthState,
            eth_submission_material::EthSubmissionMaterial,
        },
    },
    constants::SAFE_BTC_ADDRESS,
    traits::DatabaseInterface,
    types::Result,
};

#[derive(Debug, Clone, PartialEq, Eq, Constructor)]
pub struct BtcOnEthRedeemInfo {
    pub amount: U256,
    pub from: EthAddress,
    pub recipient: String,
    pub originating_tx_hash: EthHash,
}

#[derive(Debug, Clone, PartialEq, Eq, Constructor, Deref, IntoIterator)]
pub struct BtcOnEthRedeemInfos(pub Vec<BtcOnEthRedeemInfo>);

impl BtcOnEthRedeemInfos {
    pub fn sum(&self) -> u64 {
        self.iter().fold(0, |acc, params| acc + params.amount.as_u64())
    }

    pub fn to_btc_addresses_and_amounts(&self) -> Result<BtcRecipientsAndAmounts> {
        info!("✔ Getting BTC addresses & amounts from redeem params...");
        self.iter()
            .map(|params| {
                let recipient_and_amount = BtcRecipientAndAmount::new(&params.recipient[..], params.amount.as_u64());
                info!(
                    "✔ Recipients & amount retrieved from redeem: {:?}",
                    recipient_and_amount
                );
                recipient_and_amount
            })
            .collect()
    }

    fn get_btc_on_eth_redeem_amount_from_log(log: &EthLog) -> Result<U256> {
        info!("✔ Parsing redeem amount from log...");
        if log.data.len() >= ETH_WORD_SIZE_IN_BYTES {
            Ok(U256::from(convert_ptoken_to_satoshis(U256::from(
                &log.data[..ETH_WORD_SIZE_IN_BYTES],
            ))))
        } else {
            Err("✘ Not enough bytes in log data to get redeem amount!".into())
        }
    }

    fn get_btc_on_eth_btc_redeem_address_from_log(log: &EthLog) -> String {
        info!("✔ Parsing BTC address from log...");
        let default_address_error_string = format!("✔ Defaulting to safe BTC address: {}!", SAFE_BTC_ADDRESS);
        let maybe_btc_address = log.data[LOG_DATA_BTC_ADDRESS_START_INDEX..]
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
    }

    fn log_is_btc_on_eth_redeem(log: &EthLog) -> Result<bool> {
        Ok(log.contains_topic(&EthHash::from_slice(
            &hex::decode(&BTC_ON_ETH_REDEEM_EVENT_TOPIC_HEX)?[..],
        )))
    }

    fn from_eth_receipt(receipt: &EthReceipt) -> Result<Self> {
        info!("✔ Getting redeem `btc_on_eth` redeem infos from receipt...");
        Ok(Self::new(
            receipt
                .logs
                .0
                .iter()
                .filter(|log| matches!(BtcOnEthRedeemInfos::log_is_btc_on_eth_redeem(&log), Ok(true)))
                .map(|log| {
                    Ok(BtcOnEthRedeemInfo::new(
                        Self::get_btc_on_eth_redeem_amount_from_log(&log)?,
                        receipt.from,
                        Self::get_btc_on_eth_btc_redeem_address_from_log(&log),
                        receipt.transaction_hash,
                    ))
                })
                .collect::<Result<Vec<BtcOnEthRedeemInfo>>>()?,
        ))
    }

    pub fn from_eth_submission_material(submission_material: &EthSubmissionMaterial) -> Result<Self> {
        info!("✔ Getting `btc-on-eth` redeem infos from ETH submission material...");
        Ok(Self::new(
            submission_material
                .get_receipts()
                .iter()
                .map(|receipt| Ok(Self::from_eth_receipt(receipt)?.0))
                .collect::<Result<Vec<Vec<BtcOnEthRedeemInfo>>>>()?
                .concat(),
        ))
    }
}

pub fn maybe_parse_redeem_infos_and_add_to_state<D: DatabaseInterface>(state: EthState<D>) -> Result<EthState<D>> {
    info!("✔ Maybe parsing redeem infos...");
    get_eth_canon_block_from_db(&state.db).and_then(|submission_material| {
        match submission_material.receipts.is_empty() {
            true => {
                info!("✔ No receipts in canon block ∴ no infos to parse!");
                Ok(state)
            },
            false => {
                info!("✔ Receipts in canon block ∴ parsing infos...");
                BtcOnEthRedeemInfos::from_eth_submission_material(&submission_material)
                    .and_then(|infos| state.add_btc_on_eth_redeem_infos(infos))
            },
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::eth::{
        eth_submission_material::EthSubmissionMaterial,
        eth_test_utils::{
            get_sample_eth_submission_material_n,
            get_sample_log_n,
            get_sample_log_with_erc777_redeem,
            get_sample_receipt_with_erc777_redeem,
        },
    };

    fn get_sample_log_with_p2sh_redeem() -> EthLog {
        get_sample_log_n(5, 23, 2).unwrap()
    }

    fn get_tx_hash_of_redeem_tx() -> &'static str {
        "442612aba789ce873bb3804ff62ced770dcecb07d19ddcf9b651c357eebaed40"
    }

    fn get_sample_block_with_redeem() -> EthSubmissionMaterial {
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

    fn get_expected_btc_on_eth_redeem_info() -> BtcOnEthRedeemInfo {
        let amount = U256::from_dec_str("666").unwrap();
        let from = EthAddress::from_str("edb86cd455ef3ca43f0e227e00469c3bdfa40628").unwrap();
        let recipient = "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string();
        let originating_tx_hash = EthHash::from_slice(&hex::decode(get_tx_hash_of_redeem_tx()).unwrap()[..]);
        BtcOnEthRedeemInfo::new(amount, from, recipient, originating_tx_hash)
    }

    #[test]
    fn should_parse_redeem_amount_from_log() {
        let expected_result = U256::from_dec_str("666").unwrap();
        let log = get_sample_log_with_erc777_redeem();
        let result = BtcOnEthRedeemInfos::get_btc_on_eth_redeem_amount_from_log(&log).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_parse_btc_address_from_log() {
        let expected_result = "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM";
        let log = get_sample_log_with_erc777_redeem();
        let result = BtcOnEthRedeemInfos::get_btc_on_eth_btc_redeem_address_from_log(&log);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_parse_p2sh_btc_address_from_log() {
        let expected_result = "2MyT7cyDnsHFwkhGDJa3LhayYtPN3cSE7wx";
        let log = get_sample_log_with_p2sh_redeem();
        let result = BtcOnEthRedeemInfos::get_btc_on_eth_btc_redeem_address_from_log(&log);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_parse_btc_on_eth_redeem_params_from_receipt() {
        let expected_num_results = 1;
        let result = BtcOnEthRedeemInfos::from_eth_receipt(&get_sample_receipt_with_redeem()).unwrap();
        assert_eq!(result.len(), expected_num_results);
        assert_eq!(result[0], get_expected_btc_on_eth_redeem_info());
    }

    #[test]
    fn redeem_log_should_be_redeem() {
        let result = BtcOnEthRedeemInfos::log_is_btc_on_eth_redeem(&get_sample_log_with_erc777_redeem()).unwrap();
        assert!(result);
    }

    #[test]
    fn non_redeem_log_should_not_be_redeem() {
        let result =
            BtcOnEthRedeemInfos::log_is_btc_on_eth_redeem(&get_sample_receipt_with_erc777_redeem().logs.0[1]).unwrap();
        assert!(!result);
    }

    #[test]
    fn should_get_btc_on_eth_redeem_infos_from_eth_submission_material() {
        let result = BtcOnEthRedeemInfos::from_eth_submission_material(&get_sample_block_with_redeem()).unwrap();
        let expected_result = BtcOnEthRedeemInfo {
            amount: U256::from_dec_str("666").unwrap(),
            from: EthAddress::from_str("edb86cd455ef3ca43f0e227e00469c3bdfa40628").unwrap(),
            recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
            originating_tx_hash: EthHash::from_slice(&hex::decode(get_tx_hash_of_redeem_tx()).unwrap()[..]),
        };
        assert_eq!(expected_result.from, result.0[0].from);
        assert_eq!(expected_result.amount, result.0[0].amount);
        assert_eq!(expected_result.recipient, result.0[0].recipient);
        assert_eq!(expected_result.originating_tx_hash, result.0[0].originating_tx_hash);
    }
}
