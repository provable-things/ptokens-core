use std::str::FromStr;

use bitcoin::util::address::Address as BtcAddress;
use derive_more::{Constructor, Deref, IntoIterator};
use ethereum_types::{Address as EthAddress, H256 as EthHash};

use crate::{
    btc_on_eth::utils::convert_wei_to_satoshis,
    chains::{
        btc::btc_types::{BtcRecipientAndAmount, BtcRecipientsAndAmounts},
        eth::{
            eth_contracts::erc777::{
                Erc777RedeemEvent,
                ERC_777_REDEEM_EVENT_TOPIC_WITHOUT_USER_DATA,
                ERC_777_REDEEM_EVENT_TOPIC_WITH_USER_DATA,
            },
            eth_database_utils::get_eth_canon_block_from_db,
            eth_log::EthLog,
            eth_receipt::EthReceipt,
            eth_state::EthState,
            eth_submission_material::EthSubmissionMaterial,
        },
    },
    constants::{FEE_BASIS_POINTS_DIVISOR, SAFE_BTC_ADDRESS},
    fees::fee_utils::sanity_check_basis_points_value,
    traits::DatabaseInterface,
    types::Result,
};

#[derive(Debug, Clone, PartialEq, Eq, Constructor)]
pub struct BtcOnEthRedeemInfo {
    pub amount_in_satoshis: u64,
    pub from: EthAddress,
    pub recipient: String,
    pub originating_tx_hash: EthHash,
}

impl BtcOnEthRedeemInfo {
    fn update_amount(&self, new_amount: u64) -> Self {
        let mut new_self = self.clone();
        new_self.amount_in_satoshis = new_amount;
        new_self
    }

    pub fn subtract_amount(&self, subtrahend: u64) -> Result<Self> {
        if subtrahend > self.amount_in_satoshis {
            Err("Cannot subtract amount from `BtcOnEthRedeemInfo`: subtrahend too large!".into())
        } else {
            let new_amount = self.amount_in_satoshis - subtrahend;
            info!(
                "Subtracted amount of {} from current redeem info amount of {} to get final amount of {}",
                subtrahend, self.amount_in_satoshis, new_amount
            );
            Ok(self.update_amount(new_amount))
        }
    }

    pub fn calculate_fee(&self, basis_points: u64) -> u64 {
        (self.amount_in_satoshis * basis_points) / FEE_BASIS_POINTS_DIVISOR
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Constructor, Deref, IntoIterator)]
pub struct BtcOnEthRedeemInfos(pub Vec<BtcOnEthRedeemInfo>);

impl BtcOnEthRedeemInfos {
    pub fn calculate_fees(&self, basis_points: u64) -> Result<(Vec<u64>, u64)> {
        sanity_check_basis_points_value(basis_points).map(|_| {
            let fees = self
                .iter()
                .map(|redeem_info| redeem_info.calculate_fee(basis_points))
                .collect::<Vec<u64>>();
            let total_fee = fees.iter().sum();
            (fees, total_fee)
        })
    }

    pub fn sum(&self) -> u64 {
        self.iter().fold(0, |acc, params| acc + params.amount_in_satoshis)
    }

    pub fn to_btc_addresses_and_amounts(&self) -> Result<BtcRecipientsAndAmounts> {
        info!("✔ Getting BTC addresses & amounts from redeem params...");
        self.iter()
            .map(|params| {
                let recipient_and_amount = BtcRecipientAndAmount::new(&params.recipient[..], params.amount_in_satoshis);
                info!(
                    "✔ Recipients & amount retrieved from redeem: {:?}",
                    recipient_and_amount
                );
                recipient_and_amount
            })
            .collect()
    }

    fn get_btc_address_or_revert_to_safe_address(maybe_btc_address: &str) -> String {
        info!("✔ Maybe BTC address: {}", maybe_btc_address);
        match BtcAddress::from_str(maybe_btc_address) {
            Ok(address) => {
                info!("✔ Good BTC address parsed: {}", address);
                address.to_string()
            },
            Err(_) => {
                info!(
                    "✔ Failed to parse BTC address! Default to safe BTC address: {}",
                    SAFE_BTC_ADDRESS
                );
                SAFE_BTC_ADDRESS.to_string()
            },
        }
    }

    fn log_is_btc_on_eth_redeem(log: &EthLog) -> Result<bool> {
        Ok(log.contains_topic(&ERC_777_REDEEM_EVENT_TOPIC_WITH_USER_DATA)
            || log.contains_topic(&ERC_777_REDEEM_EVENT_TOPIC_WITHOUT_USER_DATA))
    }

    fn from_eth_receipt(receipt: &EthReceipt) -> Result<Self> {
        info!("✔ Getting redeem `btc_on_eth` redeem infos from receipt...");
        Ok(Self::new(
            receipt
                .logs
                .0
                .iter()
                .filter(|log| matches!(BtcOnEthRedeemInfos::log_is_btc_on_eth_redeem(log), Ok(true)))
                .map(|log| {
                    let event_params = Erc777RedeemEvent::from_eth_log(log)?;
                    Ok(BtcOnEthRedeemInfo {
                        from: event_params.redeemer,
                        originating_tx_hash: receipt.transaction_hash,
                        amount_in_satoshis: convert_wei_to_satoshis(event_params.value),
                        recipient: Self::get_btc_address_or_revert_to_safe_address(
                            &event_params.underlying_asset_recipient,
                        ),
                    })
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
    use crate::{
        btc_on_eth::test_utils::{get_sample_btc_on_eth_redeem_info_1, get_sample_btc_on_eth_redeem_infos},
        chains::eth::{
            eth_submission_material::EthSubmissionMaterial,
            eth_test_utils::{
                get_sample_eth_submission_material_n,
                get_sample_log_with_erc777_redeem,
                get_sample_receipt_with_erc777_redeem,
            },
        },
        errors::AppError,
    };

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
        let amount = 666;
        let from = EthAddress::from_str("edb86cd455ef3ca43f0e227e00469c3bdfa40628").unwrap();
        let recipient = "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string();
        let originating_tx_hash = EthHash::from_slice(&hex::decode(get_tx_hash_of_redeem_tx()).unwrap()[..]);
        BtcOnEthRedeemInfo::new(amount, from, recipient, originating_tx_hash)
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
            amount_in_satoshis: 666,
            from: EthAddress::from_str("edb86cd455ef3ca43f0e227e00469c3bdfa40628").unwrap(),
            recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
            originating_tx_hash: EthHash::from_slice(&hex::decode(get_tx_hash_of_redeem_tx()).unwrap()[..]),
        };
        assert_eq!(expected_result.from, result.0[0].from);
        assert_eq!(expected_result.recipient, result.0[0].recipient);
        assert_eq!(expected_result.amount_in_satoshis, result.0[0].amount_in_satoshis);
        assert_eq!(expected_result.originating_tx_hash, result.0[0].originating_tx_hash);
    }

    #[test]
    fn new_erc777_contract_log_should_be_btc_on_eth_redeem() {
        let log = get_sample_eth_submission_material_n(10).unwrap().receipts[0].logs[2].clone();
        let result = BtcOnEthRedeemInfos::log_is_btc_on_eth_redeem(&log).unwrap();
        assert!(result);
    }

    #[test]
    fn should_get_redeem_info_from_new_style_erc777_contract() {
        let submission_material = get_sample_eth_submission_material_n(10).unwrap();
        let expected_num_results = 1;
        let expected_result = BtcOnEthRedeemInfo {
            amount_in_satoshis: 666,
            from: EthAddress::from_str("7d39fB393C5597dddccf1c428f030913fe7F67Ab").unwrap(),
            recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
            originating_tx_hash: EthHash::from_slice(
                &hex::decode("01920b62cd2e77204b2fa59932f9d6dd54fd43c99095aee808b700ed2b6ee9cf").unwrap(),
            ),
        };
        let results = BtcOnEthRedeemInfos::from_eth_submission_material(&submission_material).unwrap();
        let result = results[0].clone();
        assert_eq!(results.len(), expected_num_results);
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_get_btc_address_from_good_address() {
        let good_address = "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string();
        let result = BtcOnEthRedeemInfos::get_btc_address_or_revert_to_safe_address(&good_address);
        assert_eq!(result, good_address);
    }

    #[test]
    fn should_get_safe_btc_address_from_bad_address() {
        let bad_address = "not a BTC address".to_string();
        let result = BtcOnEthRedeemInfos::get_btc_address_or_revert_to_safe_address(&bad_address);
        assert_eq!(result, SAFE_BTC_ADDRESS.to_string());
    }

    #[test]
    fn should_subtract_amount_from_redeem_info() {
        let info = get_sample_btc_on_eth_redeem_info_1();
        let result = info.subtract_amount(1).unwrap();
        let expected_amount = 123456788;
        assert_eq!(result.amount_in_satoshis, expected_amount)
    }

    #[test]
    fn should_calculate_fee() {
        let basis_points = 25;
        let info = get_sample_btc_on_eth_redeem_info_1();
        let result = info.calculate_fee(basis_points);
        let expected_result = 308641;
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_calculate_fees() {
        let basis_points = 25;
        let info = get_sample_btc_on_eth_redeem_infos();
        let (fees, total_fee) = info.calculate_fees(basis_points).unwrap();
        let expected_fees = vec![308641, 2469135];
        let expected_total_fee = 2777776;
        assert_eq!(fees, expected_fees);
        assert_eq!(total_fee, expected_total_fee);
    }

    #[test]
    fn should_error_if_subtrahend_too_large_when_subtracting_amount() {
        let params = get_sample_btc_on_eth_redeem_info_1();
        let subtrahend = params.amount_in_satoshis + 1;
        let expected_error = "Cannot subtract amount from `BtcOnEthRedeemInfo`: subtrahend too large!";
        match params.subtract_amount(subtrahend) {
            Ok(_) => panic!("Should not have succeeded!"),
            Err(AppError::Custom(error)) => assert_eq!(error, expected_error),
            Err(_) => panic!("Wrong error received!"),
        }
    }
}
