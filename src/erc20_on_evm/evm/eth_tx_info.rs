use derive_more::{Constructor, Deref, IntoIterator};
use ethereum_types::{Address as EthAddress, H256 as EthHash, U256};

use crate::{
    chains::{
        eth::{
            eth_chain_id::EthChainId,
            eth_constants::{MAX_BYTES_FOR_ETH_USER_DATA, ZERO_ETH_VALUE},
            eth_contracts::{
                erc20_vault::{
                    encode_erc20_vault_peg_out_fxn_data_with_user_data,
                    encode_erc20_vault_peg_out_fxn_data_without_user_data,
                    ERC20_VAULT_PEGOUT_WITHOUT_USER_DATA_GAS_LIMIT,
                    ERC20_VAULT_PEGOUT_WITH_USER_DATA_GAS_LIMIT,
                },
                erc777::{Erc777RedeemEvent, ERC_777_REDEEM_EVENT_TOPIC_WITH_USER_DATA},
            },
            eth_crypto::{
                eth_private_key::EthPrivateKey,
                eth_transaction::{EthTransaction as EvmTransaction, EthTransactions as EvmTransactions},
            },
            eth_database_utils::{
                get_erc20_on_evm_smart_contract_address_from_db,
                get_eth_account_nonce_from_db,
                get_eth_chain_id_from_db,
                get_eth_gas_price_from_db,
                get_eth_private_key_from_db,
            },
            eth_utils::safely_convert_hex_to_eth_address,
        },
        evm::{
            eth_database_utils::{
                get_eth_canon_block_from_db as get_evm_canon_block_from_db,
                get_eth_chain_id_from_db as get_evm_chain_id_from_db,
            },
            eth_log::{EthLog, EthLogs},
            eth_receipt::{EthReceipt, EthReceipts},
            eth_state::EthState as EvmState,
            eth_submission_material::EthSubmissionMaterial as EvmSubmissionMaterial,
        },
    },
    constants::SAFE_ETH_ADDRESS,
    dictionaries::eth_evm::EthEvmTokenDictionary,
    erc20_on_evm::traits::{FeeCalculator, FeesCalculator},
    metadata::{
        metadata_origin_address::MetadataOriginAddress,
        metadata_protocol_id::MetadataProtocolId,
        metadata_traits::ToMetadata,
        Metadata,
    },
    traits::DatabaseInterface,
    types::{Bytes, Result},
};

#[derive(Debug, Clone, PartialEq, Eq, Constructor)]
pub struct EthOnEvmEthTxInfo {
    pub native_token_amount: U256,
    pub token_sender: EthAddress,
    pub originating_tx_hash: EthHash,
    pub evm_token_address: EthAddress,
    pub eth_token_address: EthAddress,
    pub destination_address: EthAddress,
    pub user_data: Bytes,
    pub origin_chain_id: EthChainId,
}

impl ToMetadata for EthOnEvmEthTxInfo {
    fn to_metadata(&self) -> Result<Metadata> {
        let user_data = if self.user_data.len() > MAX_BYTES_FOR_ETH_USER_DATA {
            // TODO Test for this case!
            info!(
                "✘ `user_data` redacted from `Metadata` ∵ it's > {} bytes",
                MAX_BYTES_FOR_ETH_USER_DATA
            );
            vec![]
        } else {
            self.user_data.clone()
        };
        Ok(Metadata::new(
            &user_data,
            &MetadataOriginAddress::new_from_eth_address(
                &self.token_sender,
                &self.origin_chain_id.to_metadata_chain_id(),
            )?,
        ))
    }

    fn to_metadata_bytes(&self) -> Result<Bytes> {
        self.to_metadata()?.to_bytes_for_protocol(&MetadataProtocolId::Ethereum)
    }
}

impl FeeCalculator for EthOnEvmEthTxInfo {
    fn get_token_address(&self) -> EthAddress {
        debug!(
            "Getting token address in `EthOnEvmEthTxInfo` of {}",
            self.evm_token_address
        );
        self.evm_token_address
    }

    fn get_amount(&self) -> U256 {
        debug!(
            "Getting token amount in `EthOnEvmEthTxInfo` of {}",
            self.native_token_amount
        );
        self.native_token_amount
    }

    fn subtract_amount(&self, subtrahend: U256) -> Result<Self> {
        if subtrahend >= self.native_token_amount {
            Err("Cannot subtract amount from `EthOnEvmEthTxInfo`: subtrahend too large!".into())
        } else {
            let new_amount = self.native_token_amount - subtrahend;
            debug!(
                "Subtracting {} from {} to get final amount of {} in `EthOnEvmEthTxInfo`!",
                subtrahend, self.native_token_amount, new_amount
            );
            Ok(self.update_amount(new_amount))
        }
    }
}

impl EthOnEvmEthTxInfo {
    fn update_amount(&self, new_amount: U256) -> Self {
        let mut new_self = self.clone();
        new_self.native_token_amount = new_amount;
        new_self
    }

    fn update_destination_address(&self, new_address: EthAddress) -> Self {
        let mut new_self = self.clone();
        new_self.destination_address = new_address;
        new_self
    }

    pub fn divert_to_safe_address_if_destination_is_token_contract_address(&self) -> Self {
        info!("✔ Checking if the destination address is the same as the ETH token contract address...");
        if self.destination_address == self.eth_token_address {
            info!("✔ Recipient address is same as ETH token address! Diverting to safe address...");
            self.update_destination_address(*SAFE_ETH_ADDRESS)
        } else {
            self.clone()
        }
    }

    pub fn to_eth_signed_tx(
        // TODO Get a sample with user data so we can use that test against!
        &self,
        nonce: u64,
        chain_id: &EthChainId,
        gas_price: u64,
        evm_private_key: &EthPrivateKey,
        vault_address: &EthAddress,
    ) -> Result<EvmTransaction> {
        let gas_limit = if self.user_data.is_empty() {
            ERC20_VAULT_PEGOUT_WITHOUT_USER_DATA_GAS_LIMIT
        } else {
            ERC20_VAULT_PEGOUT_WITH_USER_DATA_GAS_LIMIT
        };
        info!("✔ Signing ETH transaction for tx info: {:?}", self);
        debug!("✔ Signing with nonce:     {}", nonce);
        debug!("✔ Signing with chain id:  {}", chain_id);
        debug!("✔ Signing with gas limit: {}", gas_limit);
        debug!("✔ Signing with gas price: {}", gas_price);
        debug!(
            "✔ Signing tx to token recipient: {}",
            self.destination_address.to_string()
        );
        debug!(
            "✔ Signing tx for token address : {}",
            self.eth_token_address.to_string()
        );
        debug!(
            "✔ Signing tx for token amount: {}",
            self.native_token_amount.to_string()
        );
        debug!("✔ Signing tx for vault address: {}", vault_address.to_string());
        let encoded_tx_data = if self.user_data.is_empty() {
            encode_erc20_vault_peg_out_fxn_data_without_user_data(
                self.destination_address,
                self.eth_token_address,
                self.native_token_amount,
            )?
        } else {
            encode_erc20_vault_peg_out_fxn_data_with_user_data(
                self.destination_address,
                self.eth_token_address,
                self.native_token_amount,
                self.to_metadata_bytes()?,
            )?
        };
        EvmTransaction::new_unsigned(
            encoded_tx_data,
            nonce,
            ZERO_ETH_VALUE,
            *vault_address,
            chain_id,
            gas_limit,
            gas_price,
        )
        .sign(evm_private_key)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Constructor, Deref, IntoIterator)]
pub struct EthOnEvmEthTxInfos(pub Vec<EthOnEvmEthTxInfo>);

impl FeesCalculator for EthOnEvmEthTxInfos {
    fn get_fees(&self, dictionary: &EthEvmTokenDictionary) -> Result<Vec<(EthAddress, U256)>> {
        debug!("Calculating fees in `EthOnEvmEthTxInfo`...");
        self.iter()
            .map(|info| info.calculate_fee_via_dictionary(dictionary))
            .collect()
    }

    fn subtract_fees(&self, dictionary: &EthEvmTokenDictionary) -> Result<Self> {
        self.get_fees(dictionary).and_then(|fee_tuples| {
            Ok(Self::new(
                self.iter()
                    .zip(fee_tuples.iter())
                    .map(|(info, (_, fee))| {
                        if *fee == U256::zero() {
                            debug!("Not subtracting fee because `fee` is 0!");
                            Ok(info.clone())
                        } else {
                            info.subtract_amount(*fee)
                        }
                    })
                    .collect::<Result<Vec<EthOnEvmEthTxInfo>>>()?,
            ))
        })
    }
}

impl EthOnEvmEthTxInfos {
    pub fn divert_to_safe_address_if_destination_is_token_contract_address(&self) -> Self {
        Self::new(
            self.iter()
                .map(|info| info.divert_to_safe_address_if_destination_is_token_contract_address())
                .collect::<Vec<EthOnEvmEthTxInfo>>(),
        )
    }

    pub fn filter_out_zero_values(&self) -> Result<Self> {
        Ok(Self::new(
            self.iter()
                .filter(|tx_info| match tx_info.native_token_amount != U256::zero() {
                    true => true,
                    false => {
                        info!("✘ Filtering out redeem info due to zero asset amount: {:?}", tx_info);
                        false
                    },
                })
                .cloned()
                .collect::<Vec<EthOnEvmEthTxInfo>>(),
        ))
    }

    fn is_log_erc20_on_evm_redeem(log: &EthLog, dictionary: &EthEvmTokenDictionary) -> Result<bool> {
        debug!(
            "✔ Checking log contains topic: {}",
            hex::encode(ERC_777_REDEEM_EVENT_TOPIC_WITH_USER_DATA.as_bytes())
        );
        let token_is_supported = dictionary.is_evm_token_supported(&log.address);
        let log_contains_topic = log.contains_topic(&ERC_777_REDEEM_EVENT_TOPIC_WITH_USER_DATA);
        debug!("✔ Log is supported: {}", token_is_supported);
        debug!("✔ Log has correct topic: {}", log_contains_topic);
        Ok(token_is_supported && log_contains_topic)
    }

    pub fn is_log_supported_erc20_on_evm_redeem(log: &EthLog, dictionary: &EthEvmTokenDictionary) -> Result<bool> {
        match Self::is_log_erc20_on_evm_redeem(log, dictionary)? {
            false => Ok(false),
            true => Ok(dictionary.is_evm_token_supported(&log.address)),
        }
    }

    fn get_supported_erc20_on_evm_logs_from_receipt(
        receipt: &EthReceipt,
        dictionary: &EthEvmTokenDictionary,
    ) -> EthLogs {
        EthLogs::new(
            receipt
                .logs
                .iter()
                .filter(|log| matches!(Self::is_log_supported_erc20_on_evm_redeem(log, dictionary), Ok(true)))
                .cloned()
                .collect(),
        )
    }

    fn receipt_contains_supported_erc20_on_evm_redeem(
        receipt: &EthReceipt,
        dictionary: &EthEvmTokenDictionary,
    ) -> bool {
        Self::get_supported_erc20_on_evm_logs_from_receipt(receipt, dictionary).len() > 0
    }

    fn from_eth_receipt(
        receipt: &EthReceipt,
        dictionary: &EthEvmTokenDictionary,
        origin_chain_id: &EthChainId,
    ) -> Result<Self> {
        info!("✔ Getting `EthOnEvmEthTxInfos` from receipt...");
        Ok(Self::new(
            Self::get_supported_erc20_on_evm_logs_from_receipt(receipt, dictionary)
                .iter()
                .map(|log| {
                    let event_params = Erc777RedeemEvent::from_eth_log(log)?;
                    let tx_info = EthOnEvmEthTxInfo {
                        evm_token_address: log.address,
                        token_sender: event_params.redeemer,
                        origin_chain_id: origin_chain_id.clone(),
                        user_data: event_params.user_data.clone(),
                        originating_tx_hash: receipt.transaction_hash,
                        eth_token_address: dictionary.get_eth_address_from_evm_address(&log.address)?,
                        destination_address: safely_convert_hex_to_eth_address(
                            &event_params.underlying_asset_recipient,
                        )?,
                        native_token_amount: dictionary
                            .convert_evm_amount_to_eth_amount(&log.address, event_params.value)?,
                    };
                    info!("✔ Parsed tx info: {:?}", tx_info);
                    Ok(tx_info)
                })
                .collect::<Result<Vec<EthOnEvmEthTxInfo>>>()?,
        ))
    }

    fn filter_eth_submission_material_for_supported_redeems(
        submission_material: &EvmSubmissionMaterial,
        dictionary: &EthEvmTokenDictionary,
    ) -> Result<EvmSubmissionMaterial> {
        info!("✔ Filtering submission material receipts for those pertaining to `ERC20-on-EVM` redeems...");
        info!(
            "✔ Num receipts before filtering: {}",
            submission_material.receipts.len()
        );
        let filtered_receipts = EthReceipts::new(
            submission_material
                .receipts
                .iter()
                .filter(|receipt| {
                    EthOnEvmEthTxInfos::receipt_contains_supported_erc20_on_evm_redeem(receipt, dictionary)
                })
                .cloned()
                .collect(),
        );
        info!("✔ Num receipts after filtering: {}", filtered_receipts.len());
        Ok(EvmSubmissionMaterial::new(
            submission_material.get_block()?,
            filtered_receipts,
            None,
            None,
        ))
    }

    pub fn from_submission_material(
        submission_material: &EvmSubmissionMaterial,
        dictionary: &EthEvmTokenDictionary,
        origin_chain_id: &EthChainId,
    ) -> Result<Self> {
        info!("✔ Getting `EthOnEvmEthTxInfos` from submission material...");
        Ok(Self::new(
            submission_material
                .get_receipts()
                .iter()
                .map(|receipt| Self::from_eth_receipt(receipt, dictionary, origin_chain_id))
                .collect::<Result<Vec<EthOnEvmEthTxInfos>>>()?
                .into_iter()
                .flatten()
                .collect(),
        ))
    }

    pub fn to_eth_signed_txs(
        &self,
        start_nonce: u64,
        chain_id: &EthChainId,
        gas_price: u64,
        evm_private_key: &EthPrivateKey,
        vault_address: &EthAddress,
    ) -> Result<EvmTransactions> {
        info!("✔ Signing `ERC20-on-EVM` ETH transactions...");
        Ok(EvmTransactions::new(
            self.iter()
                .enumerate()
                .map(|(i, tx_info)| {
                    EthOnEvmEthTxInfo::to_eth_signed_tx(
                        tx_info,
                        start_nonce + i as u64,
                        chain_id,
                        gas_price,
                        evm_private_key,
                        vault_address,
                    )
                })
                .collect::<Result<Vec<EvmTransaction>>>()?,
        ))
    }
}

pub fn maybe_parse_tx_info_from_canon_block_and_add_to_state<D: DatabaseInterface>(
    state: EvmState<D>,
) -> Result<EvmState<D>> {
    info!("✔ Maybe parsing `EthOnEvmEthTxInfos`...");
    get_evm_canon_block_from_db(&state.db).and_then(|submission_material| {
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
                EthEvmTokenDictionary::get_from_db(&state.db)
                    .and_then(|account_names| {
                        EthOnEvmEthTxInfos::from_submission_material(
                            &submission_material,
                            &account_names,
                            &get_evm_chain_id_from_db(&state.db)?,
                        )
                    })
                    .and_then(|tx_infos| state.add_erc20_on_evm_eth_tx_infos(tx_infos))
            },
        }
    })
}

pub fn filter_out_zero_value_eth_tx_infos_from_state<D: DatabaseInterface>(state: EvmState<D>) -> Result<EvmState<D>> {
    info!("✔ Maybe filtering out zero value `EthOnEvmEthTxInfos`...");
    debug!(
        "✔ Num `EthOnEvmEthTxInfos` before: {}",
        state.erc20_on_evm_eth_signed_txs.len()
    );
    state
        .erc20_on_evm_eth_tx_infos
        .filter_out_zero_values()
        .and_then(|filtered_tx_infos| {
            debug!("✔ Num `EthOnEvmEthTxInfos` after: {}", filtered_tx_infos.len());
            state.replace_erc20_on_evm_eth_tx_infos(filtered_tx_infos)
        })
}

pub fn filter_submission_material_for_redeem_events_in_state<D: DatabaseInterface>(
    state: EvmState<D>,
) -> Result<EvmState<D>> {
    info!("✔ Filtering receipts for those containing `ERC20-on-EVM` redeem events...");
    state
        .get_eth_submission_material()?
        .get_receipts_containing_log_from_addresses_and_with_topics(
            &state.get_eth_evm_token_dictionary()?.to_evm_addresses(),
            &[*ERC_777_REDEEM_EVENT_TOPIC_WITH_USER_DATA],
        )
        .and_then(|filtered_submission_material| {
            EthOnEvmEthTxInfos::filter_eth_submission_material_for_supported_redeems(
                &filtered_submission_material,
                state.get_eth_evm_token_dictionary()?,
            )
        })
        .and_then(|filtered_submission_material| state.update_eth_submission_material(filtered_submission_material))
}

pub fn maybe_sign_eth_txs_and_add_to_evm_state<D: DatabaseInterface>(state: EvmState<D>) -> Result<EvmState<D>> {
    if state.erc20_on_evm_eth_tx_infos.is_empty() {
        info!("✔ No tx infos in state ∴ no ETH transactions to sign!");
        Ok(state)
    } else {
        state
            .erc20_on_evm_eth_tx_infos
            .to_eth_signed_txs(
                get_eth_account_nonce_from_db(&state.db)?,
                &get_eth_chain_id_from_db(&state.db)?,
                get_eth_gas_price_from_db(&state.db)?,
                &get_eth_private_key_from_db(&state.db)?,
                &get_erc20_on_evm_smart_contract_address_from_db(&state.db)?,
            )
            .and_then(|signed_txs| {
                #[cfg(feature = "debug")]
                {
                    debug!("✔ Signed transactions: {:?}", signed_txs);
                }
                state.add_erc20_on_evm_eth_signed_txs(signed_txs)
            })
    }
}

pub fn maybe_divert_txs_to_safe_address_if_destination_is_eth_token_address<D: DatabaseInterface>(
    state: EvmState<D>,
) -> Result<EvmState<D>> {
    if state.erc20_on_evm_eth_tx_infos.is_empty() {
        Ok(state)
    } else {
        info!("✔ Maybe diverting ETH txs to safe address if destination address is the token contract address...");
        let new_infos = state
            .erc20_on_evm_eth_tx_infos
            .divert_to_safe_address_if_destination_is_token_contract_address();
        state.replace_erc20_on_evm_eth_tx_infos(new_infos)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::eth::eth_traits::EthTxInfoCompatible,
        erc20_on_evm::test_utils::{
            get_evm_submission_material_n,
            get_sample_eth_evm_token_dictionary,
            get_sample_eth_private_key,
            get_sample_vault_address,
        },
    };

    fn get_sample_tx_infos() -> EthOnEvmEthTxInfos {
        let dictionary = get_sample_eth_evm_token_dictionary();
        let material = get_evm_submission_material_n(1);
        let origin_chain_id = EthChainId::BscMainnet;
        EthOnEvmEthTxInfos::from_submission_material(&material, &dictionary, &origin_chain_id).unwrap()
    }

    fn get_sample_tx_info() -> EthOnEvmEthTxInfo {
        get_sample_tx_infos()[0].clone()
    }

    #[test]
    fn should_filter_submission_info_for_supported_redeems() {
        let dictionary = get_sample_eth_evm_token_dictionary();
        let material = get_evm_submission_material_n(1);
        let result =
            EthOnEvmEthTxInfos::filter_eth_submission_material_for_supported_redeems(&material, &dictionary).unwrap();
        let expected_num_receipts = 1;
        assert_eq!(result.receipts.len(), expected_num_receipts);
    }

    // TODO Get a sample with actual user data & test that too.
    #[test]
    fn should_get_erc20_on_evm_eth_tx_info_from_submission_material() {
        let dictionary = get_sample_eth_evm_token_dictionary();
        let origin_chain_id = EthChainId::BscMainnet;
        let material = get_evm_submission_material_n(1);
        let result = EthOnEvmEthTxInfos::from_submission_material(&material, &dictionary, &origin_chain_id).unwrap();
        let expected_num_results = 1;
        assert_eq!(result.len(), expected_num_results);
        let expected_result = EthOnEvmEthTxInfos::new(vec![EthOnEvmEthTxInfo {
            origin_chain_id,
            user_data: vec![],
            native_token_amount: U256::from_dec_str("100000000000000000").unwrap(),
            token_sender: EthAddress::from_slice(&hex::decode("8127192c2e4703dfb47f087883cc3120fe061cb8").unwrap()),
            evm_token_address: EthAddress::from_slice(
                &hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap(),
            ),
            eth_token_address: EthAddress::from_slice(
                &hex::decode("89ab32156e46f46d02ade3fecbe5fc4243b9aaed").unwrap(),
            ),
            destination_address: EthAddress::from_slice(
                &hex::decode("71a440ee9fa7f99fb9a697e96ec7839b8a1643b8").unwrap(),
            ),
            originating_tx_hash: EthHash::from_slice(
                &hex::decode("52c620012a6e278d56f582eb1dcb9241c9b2d14d7edc5dab15473b579ce2d2ea").unwrap(),
            ),
        }]);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_signatures_from_eth_tx_info() {
        let infos = get_sample_tx_infos();
        let vault_address = get_sample_vault_address();
        let pk = get_sample_eth_private_key();
        let nonce = 0_u64;
        let chain_id = EthChainId::Rinkeby;
        let gas_price = 20_000_000_000_u64;
        let signed_txs = infos
            .to_eth_signed_txs(nonce, &chain_id, gas_price, &pk, &vault_address)
            .unwrap();
        let expected_num_results = 1;
        assert_eq!(signed_txs.len(), expected_num_results);
        let tx_hex = signed_txs[0].eth_tx_hex().unwrap();
        let expected_tx_hex =
"f8c9808504a817c8008303d09094d608367b33c52293201af7fb578916a7c0784bd780b86483c09d4200000000000000000000000071a440ee9fa7f99fb9a697e96ec7839b8a1643b800000000000000000000000089ab32156e46f46d02ade3fecbe5fc4243b9aaed000000000000000000000000000000000000000000000000016345785d8a00002ba0cf271fe2d7dcf4d882fe86ceed811de38dad1e63b37305978892251c1b2ce1ed9ff88c86769d246e1f98bc901d45bf0e02ec5a404f56f7747c4f9a9d02938773"
;
        assert_eq!(tx_hex, expected_tx_hex);
    }

    #[test]
    fn should_calculate_eth_on_evm_eth_tx_info_fee() {
        let fee_basis_points = 25;
        let info = get_sample_tx_info();
        let result = info.calculate_fee(fee_basis_points);
        let expected_result = U256::from_dec_str("250000000000000").unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_subtract_amount_from_eth_on_evm_eth_tx_info() {
        let info = get_sample_tx_info();
        let subtrahend = U256::from(1337);
        let result = info.subtract_amount(subtrahend).unwrap();
        let expected_native_token_amount = U256::from_dec_str("99999999999998663").unwrap();
        assert_eq!(result.native_token_amount, expected_native_token_amount)
    }

    #[test]
    fn should_fail_to_subtract_too_large_amount_from_eth_on_evm_eth_tx_info() {
        let info = get_sample_tx_info();
        let subtrahend = U256::from(info.native_token_amount + 1);
        let result = info.subtract_amount(subtrahend);
        assert!(result.is_err());
    }

    #[test]
    fn should_divert_to_safe_address_if_destination_is_token_address() {
        let destination_address =
            EthAddress::from_slice(&hex::decode("89ab32156e46f46d02ade3fecbe5fc4243b9aaed").unwrap());
        let info = EthOnEvmEthTxInfo {
            user_data: vec![],
            destination_address,
            origin_chain_id: EthChainId::BscMainnet,
            native_token_amount: U256::from_dec_str("100000000000000000").unwrap(),
            token_sender: EthAddress::from_slice(&hex::decode("8127192c2e4703dfb47f087883cc3120fe061cb8").unwrap()),
            evm_token_address: EthAddress::from_slice(
                &hex::decode("daacb0ab6fb34d24e8a67bfa14bf4d95d4c7af92").unwrap(),
            ),
            eth_token_address: EthAddress::from_slice(
                &hex::decode("89ab32156e46f46d02ade3fecbe5fc4243b9aaed").unwrap(),
            ),
            originating_tx_hash: EthHash::from_slice(
                &hex::decode("52c620012a6e278d56f582eb1dcb9241c9b2d14d7edc5dab15473b579ce2d2ea").unwrap(),
            ),
        };
        assert_eq!(info.destination_address, destination_address);
        let result = info.divert_to_safe_address_if_destination_is_token_contract_address();
        assert_eq!(result.destination_address, *SAFE_ETH_ADDRESS);
    }
}
