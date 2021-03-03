use derive_more::{Constructor, Deref};
use eos_primitives::{
    AccountName as EosAccountName,
    Action as EosAction,
    PermissionLevel,
    Transaction as EosTransaction,
};
use ethereum_types::{Address as EthAddress, H256 as EthHash, U256};

use crate::{
    chains::{
        eos::{
            eos_actions::PTokenPegOutAction,
            eos_constants::{EOS_ACCOUNT_PERMISSION_LEVEL, EOS_MAX_EXPIRATION_SECS},
            eos_crypto::{
                eos_private_key::EosPrivateKey,
                eos_transaction::{EosSignedTransaction, EosSignedTransactions},
            },
            eos_database_utils::{get_eos_account_name_from_db, get_eos_chain_id_from_db},
            eos_eth_token_dictionary::EosEthTokenDictionary,
        },
        eth::{
            eth_constants::EOS_ON_ETH_ETH_TX_INFO_EVENT_TOPIC,
            eth_contracts::erc777::Erc777RedeemEvent,
            eth_database_utils::get_eth_canon_block_from_db,
            eth_log::EthLog,
            eth_state::EthState,
            eth_submission_material::EthSubmissionMaterial,
        },
    },
    eos_on_eth::constants::MINIMUM_WEI_AMOUNT,
    traits::DatabaseInterface,
    types::{Byte, Result},
};

const ZERO_ETH_ASSET_STR: &str = "0.0000 EOS";

#[derive(Debug, Clone, PartialEq, Eq, Constructor, Deref)]
pub struct EosOnEthEthTxInfos(pub Vec<EosOnEthEthTxInfo>);

impl EosOnEthEthTxInfos {
    pub fn from_eth_submission_material(
        material: &EthSubmissionMaterial,
        token_dictionary: &EosEthTokenDictionary,
    ) -> Result<Self> {
        Self::from_eth_submission_material_without_filtering(material, token_dictionary).map(|tx_infos| {
            debug!("Num tx infos before filtering: {}", tx_infos.len());
            let filtered = tx_infos.filter_out_those_with_zero_eos_asset_amount(token_dictionary);
            debug!("Num tx infos after filtering: {}", filtered.len());
            filtered
        })
    }

    fn from_eth_submission_material_without_filtering(
        material: &EthSubmissionMaterial,
        token_dictionary: &EosEthTokenDictionary,
    ) -> Result<Self> {
        let topic = &EOS_ON_ETH_ETH_TX_INFO_EVENT_TOPIC[0];
        let eth_contract_addresses = token_dictionary.to_eth_addresses();
        debug!("Addresses from dict: {:?}", eth_contract_addresses);
        debug!("The topic: {}", hex::encode(EOS_ON_ETH_ETH_TX_INFO_EVENT_TOPIC[0]));
        Ok(Self(
            material
                .receipts
                .get_receipts_containing_log_from_addresses_and_with_topics(&eth_contract_addresses, &[*topic])
                .iter()
                .map(|receipt| {
                    receipt
                        .get_logs_from_addresses_with_topic(&eth_contract_addresses, topic)
                        .iter()
                        .map(|log| EosOnEthEthTxInfo::from_eth_log(&log, &receipt.transaction_hash, token_dictionary))
                        .collect::<Result<Vec<EosOnEthEthTxInfo>>>()
                })
                .collect::<Result<Vec<Vec<EosOnEthEthTxInfo>>>>()?
                .concat(),
        ))
    }

    pub fn filter_out_those_with_value_too_low(&self) -> Result<Self> {
        let min_amount = U256::from_dec_str(MINIMUM_WEI_AMOUNT)?;
        Ok(EosOnEthEthTxInfos::new(
            self.iter()
                .filter(|info| {
                    if info.token_amount >= min_amount {
                        true
                    } else {
                        info!("✘ Filtering out tx info ∵ value too low: {:?}", info);
                        false
                    }
                })
                .cloned()
                .collect::<Vec<EosOnEthEthTxInfo>>(),
        ))
    }

    pub fn to_eos_signed_txs(
        &self,
        ref_block_num: u16,
        ref_block_prefix: u32,
        chain_id: &str,
        pk: &EosPrivateKey,
        eos_smart_contract: &EosAccountName,
    ) -> Result<EosSignedTransactions> {
        info!("✔ Signing {} EOS txs from `EosOnEthEthTxInfos`...", self.len());
        Ok(EosSignedTransactions::new(
            self.iter()
                .map(|tx_info| {
                    info!("✔ Signing EOS tx from `EosOnEthEthTxInfo`: {:?}", tx_info);
                    tx_info.to_eos_signed_tx(
                        ref_block_num,
                        ref_block_prefix,
                        &eos_smart_contract,
                        ZERO_ETH_ASSET_STR,
                        chain_id,
                        pk,
                    )
                })
                .collect::<Result<Vec<EosSignedTransaction>>>()?,
        ))
    }

    fn filter_out_those_with_zero_eos_asset_amount(&self, dictionary: &EosEthTokenDictionary) -> Self {
        info!("✔ Filtering out `EosOnEthEthTxInfos` if they have a zero EOS asset amount...");
        Self::new(
            self.iter()
                .filter(|tx_info| {
                    match dictionary.get_zero_eos_asset_amount_via_eth_token_address(&tx_info.eth_token_address) {
                        Err(_) => {
                            info!(
                                "✘ Filtering out tx ∵ cannot determine zero EOS asset amount! {:?}",
                                tx_info
                            );
                            false
                        },
                        Ok(zero_asset_amount) => tx_info.eos_asset_amount != zero_asset_amount,
                    }
                })
                .cloned()
                .collect::<Vec<EosOnEthEthTxInfo>>(),
        )
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Constructor)]
pub struct EosOnEthEthTxInfo {
    pub token_amount: U256,
    pub eos_address: String,
    pub eos_token_address: String,
    pub eos_asset_amount: String,
    pub token_sender: EthAddress,
    pub eth_token_address: EthAddress,
    pub originating_tx_hash: EthHash,
}

impl EosOnEthEthTxInfo {
    pub fn from_eth_log(log: &EthLog, tx_hash: &EthHash, token_dictionary: &EosEthTokenDictionary) -> Result<Self> {
        info!("✔ Parsing `EosOnEthEthTxInfo` from ETH log...");
        Erc777RedeemEvent::from_eth_log(log).and_then(|params| {
            Ok(Self {
                token_amount: params.value,
                originating_tx_hash: *tx_hash,
                token_sender: params.redeemer,
                eth_token_address: log.address,
                eos_address: params.underlying_asset_recipient,
                eos_token_address: token_dictionary.get_eos_account_name_from_eth_token_address(&log.address)?,
                eos_asset_amount: token_dictionary.convert_u256_to_eos_asset_string(&log.address, &params.value)?,
            })
        })
    }

    fn get_eos_ptoken_peg_out_action(
        from: &str,
        actor: &str,
        permission_level: &str,
        token_contract: &str,
        quantity: &str,
        recipient: &str,
        metadata: &[Byte],
    ) -> Result<EosAction> {
        debug!(
            "from: {}\nactor: {}\npermission_level: {}\ntoken_contract: {}\nquantity: {}\nrecipient: {}\nmetadata: '0x{}'",
            from, actor, permission_level, token_contract, quantity, recipient, hex::encode(metadata),
        );
        Ok(EosAction::from_str(
            from,
            "pegout",
            vec![PermissionLevel::from_str(actor, permission_level)?],
            PTokenPegOutAction::from_str(token_contract, quantity, recipient, metadata)?,
        )?)
    }

    pub fn to_eos_signed_tx(
        &self,
        ref_block_num: u16,
        ref_block_prefix: u32,
        eos_smart_contract: &EosAccountName,
        amount: &str,
        chain_id: &str,
        pk: &EosPrivateKey,
    ) -> Result<EosSignedTransaction> {
        info!("✔ Signing eos tx...");
        debug!(
            "smart-contract: {}\namount: {}\nchain ID: {}",
            &eos_smart_contract, &amount, &chain_id
        );
        Self::get_eos_ptoken_peg_out_action(
            &eos_smart_contract.to_string(),
            &eos_smart_contract.to_string(),
            EOS_ACCOUNT_PERMISSION_LEVEL,
            &self.eos_token_address,
            &self.eos_asset_amount,
            &self.eos_address,
            &[], // NOTE: Empty metadata for now.
        )
        .map(|action| EosTransaction::new(EOS_MAX_EXPIRATION_SECS, ref_block_num, ref_block_prefix, vec![action]))
        .and_then(|ref unsigned_tx| {
            EosSignedTransaction::from_unsigned_tx(&eos_smart_contract.to_string(), amount, chain_id, pk, unsigned_tx)
        })
    }
}

pub fn maybe_parse_eth_tx_info_from_canon_block_and_add_to_state<D: DatabaseInterface>(
    state: EthState<D>,
) -> Result<EthState<D>> {
    info!("✔ Maybe parsing `eos-on-eth` tx infos...");
    get_eth_canon_block_from_db(&state.db).and_then(|material| match material.receipts.is_empty() {
        true => {
            info!("✔ No receipts in canon block ∴ no info to parse!");
            Ok(state)
        },
        false => {
            info!(
                "✔ {} receipts in canon block ∴ parsing ETH tx info...",
                material.receipts.len()
            );
            EosOnEthEthTxInfos::from_eth_submission_material(&material, state.get_eos_eth_token_dictionary()?)
                .and_then(|tx_infos| state.add_eos_on_eth_eth_tx_infos(tx_infos))
        },
    })
}

pub fn maybe_filter_out_eth_tx_info_with_value_too_low_in_state<D: DatabaseInterface>(
    state: EthState<D>,
) -> Result<EthState<D>> {
    info!("✔ Maybe filtering `EosOnEthEthTxInfos`...");
    debug!("✔ Num tx infos before: {}", state.eos_on_eth_eth_tx_infos.len());
    state
        .eos_on_eth_eth_tx_infos
        .filter_out_those_with_value_too_low()
        .and_then(|filtered_infos| {
            debug!("✔ Num tx infos after: {}", filtered_infos.len());
            state.replace_eos_on_eth_eth_tx_infos(filtered_infos)
        })
}

pub fn maybe_sign_eos_txs_and_add_to_eth_state<D: DatabaseInterface>(state: EthState<D>) -> Result<EthState<D>> {
    info!("✔ Maybe signing `EosOnEthEthTxInfos`...");
    let submission_material = state.get_eth_submission_material()?;
    state
        .eos_on_eth_eth_tx_infos
        .to_eos_signed_txs(
            submission_material.get_eos_ref_block_num()?,
            submission_material.get_eos_ref_block_prefix()?,
            &get_eos_chain_id_from_db(&state.db)?,
            &EosPrivateKey::get_from_db(&state.db)?,
            &get_eos_account_name_from_db(&state.db)?,
        )
        .and_then(|signed_txs| state.add_eos_transactions(signed_txs))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::{
        chains::eos::eos_eth_token_dictionary::EosEthTokenDictionaryEntry,
        eos_on_eth::test_utils::{get_eth_submission_material_n, get_sample_eos_eth_token_dictionary},
    };

    #[test]
    fn should_get_tx_info_from_eth_submission_material() {
        let material = get_eth_submission_material_n(1).unwrap();
        let dictionary = get_sample_eos_eth_token_dictionary();
        let tx_infos = EosOnEthEthTxInfos::from_eth_submission_material(&material, &dictionary).unwrap();
        let result = tx_infos[0].clone();
        let expected_token_amount = U256::from_dec_str("100000000000000").unwrap();
        let expected_eos_address = "whateverxxxx";
        let expected_eos_token_address = "eosio.token".to_string();
        let expected_eos_asset_amount = "0.0001 EOS".to_string();
        let expected_token_sender =
            EthAddress::from_slice(&hex::decode("fedfe2616eb3661cb8fed2782f5f0cc91d59dcac").unwrap());
        let expected_eth_token_address =
            EthAddress::from_slice(&hex::decode("711c50b31ee0b9e8ed4d434819ac20b4fbbb5532").unwrap());
        let expected_originating_tx_hash = EthHash::from_slice(
            &hex::decode("9b9b2b88bdd495c132704154003d2deb65bd34ce6f8836ed6efdf0ba9def2b3e").unwrap(),
        );
        assert_eq!(result.token_amount, expected_token_amount);
        assert_eq!(result.eos_address, expected_eos_address);
        assert_eq!(result.eos_token_address, expected_eos_token_address);
        assert_eq!(result.eos_asset_amount, expected_eos_asset_amount);
        assert_eq!(result.token_sender, expected_token_sender);
        assert_eq!(result.eth_token_address, expected_eth_token_address);
        assert_eq!(result.originating_tx_hash, expected_originating_tx_hash);
    }

    #[test]
    fn should_get_eos_signed_txs_from_tx_info() {
        let material = get_eth_submission_material_n(1).unwrap();
        let dictionary = get_sample_eos_eth_token_dictionary();
        let tx_infos = EosOnEthEthTxInfos::from_eth_submission_material(&material, &dictionary).unwrap();
        let ref_block_num = 1;
        let ref_block_prefix = 1;
        let chain_id = "aca376f206b8fc25a6ed44dbdc66547c36c6c33e3a119ffbeaef943642f0e906";
        let pk = EosPrivateKey::from_slice(
            &hex::decode("17b116e5e55af3b9985ff6c6e0320578176b83ca55570a66683d3b36d9deca64").unwrap(),
        )
        .unwrap();
        let eos_smart_contract = EosAccountName::from_str("11ppntoneos").unwrap();
        let result = tx_infos
            .to_eos_signed_txs(ref_block_num, ref_block_prefix, chain_id, &pk, &eos_smart_contract)
            .unwrap()[0]
            .transaction
            .clone();
        let expected_result = "010001000000000000000100305593e6596b0800000000644d99aa0100305593e6596b0800000000a8ed32322100a6823403ea3055010000000000000004454f5300000000d07bef576d954de30000";
        let result_with_no_timestamp = &result[8..];
        assert_eq!(result_with_no_timestamp, expected_result);
    }

    #[test]
    fn should_filter_out_zero_eth_amounts() {
        let dictionary = EosEthTokenDictionary::new(vec![EosEthTokenDictionaryEntry::from_str(
            "{\"eth_token_decimals\":18,\"eos_token_decimals\":4,\"eth_symbol\":\"TOK\",\"eos_symbol\":\"EOS\",\"eth_address\":\"9a74c1e17b31745199b229b5c05b61081465b329\",\"eos_address\":\"eosio.token\"}"
        ).unwrap()]);
        let submission_material = get_eth_submission_material_n(2).unwrap();
        let expected_result_before = 1;
        let expected_result_after = 0;
        let result_before =
            EosOnEthEthTxInfos::from_eth_submission_material_without_filtering(&submission_material, &dictionary)
                .unwrap();
        assert_eq!(result_before.len(), expected_result_before);
        assert_eq!(result_before[0].eos_asset_amount, "0.0000 EOS");
        let result_after = result_before.filter_out_those_with_zero_eos_asset_amount(&dictionary);
        assert_eq!(result_after.len(), expected_result_after);
    }
}
