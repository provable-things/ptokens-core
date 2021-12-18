use std::str::from_utf8;

use derive_more::{Constructor, Deref};
use eos_chain::{
    symbol::symbol_to_string as eos_symbol_to_string,
    AccountName as EosAccountName,
    Checksum256,
    Name as EosName,
    Symbol as EosSymbol,
};
use ethereum_types::{Address as EthAddress, U256};
use serde::{Deserialize, Serialize};

use crate::{
    chains::{
        eos::{
            eos_action_proofs::EosActionProof,
            eos_database_utils::get_eos_account_name_from_db,
            eos_global_sequences::{GlobalSequence, GlobalSequences, ProcessedGlobalSequences},
            eos_state::EosState,
        },
        eth::{
            eth_chain_id::EthChainId,
            eth_constants::ZERO_ETH_VALUE,
            eth_contracts::erc777::{encode_erc777_mint_with_no_data_fxn, ERC777_MINT_WITH_NO_DATA_GAS_LIMIT},
            eth_crypto::{
                eth_private_key::EthPrivateKey,
                eth_transaction::{EthTransaction, EthTransactions},
            },
            eth_database_utils::{
                get_eth_account_nonce_from_db,
                get_eth_chain_id_from_db,
                get_eth_gas_price_from_db,
                get_eth_private_key_from_db,
            },
        },
    },
    constants::SAFE_ETH_ADDRESS,
    dictionaries::eos_eth::EosEthTokenDictionary,
    eos_on_eth::constants::MINIMUM_WEI_AMOUNT,
    traits::DatabaseInterface,
    types::Result,
    utils::{convert_bytes_to_u64, strip_hex_prefix},
};

const REQUIRED_ACTION_NAME: &str = "pegin";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Constructor)]
pub struct EosOnEthEosTxInfo {
    pub amount: U256,
    pub from: EosAccountName,
    pub recipient: EthAddress,
    pub originating_tx_id: Checksum256,
    pub global_sequence: GlobalSequence,
    pub eth_token_address: EthAddress,
    pub eos_token_address: String,
}

impl EosOnEthEosTxInfo {
    fn get_token_sender_from_proof(proof: &EosActionProof) -> Result<EosAccountName> {
        let end_index = 7;
        proof
            .check_proof_action_data_length(
                end_index,
                "Not enough data to parse `EosOnEthEosTxInfo` sender from proof!",
            )
            .and_then(|_| {
                let result = EosAccountName::new(convert_bytes_to_u64(&proof.action.data[..=end_index])?);
                debug!("✔ Token sender parsed from action proof: {}", result);
                Ok(result)
            })
    }

    fn get_token_account_name_from_proof(proof: &EosActionProof) -> Result<EosAccountName> {
        let end_index = 15;
        let start_index = 8;
        proof
            .check_proof_action_data_length(
                end_index,
                "Not enough data to parse `EosOnEthEosTxInfo` account from proof!",
            )
            .and_then(|_| {
                let result = EosAccountName::new(convert_bytes_to_u64(&proof.action.data[start_index..=end_index])?);
                debug!("✔ Token account name parsed from action proof: {}", result);
                Ok(result)
            })
    }

    fn get_action_name_from_proof(proof: &EosActionProof) -> Result<EosName> {
        let end_index = 15;
        let start_index = 8;
        let serialized_action = proof.get_serialized_action()?;
        if serialized_action.len() < end_index + 1 {
            Err("Not enough data to parse `EosOnEthEosTxInfo` action name from proof!".into())
        } else {
            let result = EosName::new(convert_bytes_to_u64(
                &proof.get_serialized_action()?[start_index..=end_index],
            )?);
            debug!("✔ Action name parsed from action proof: {}", result);
            Ok(result)
        }
    }

    fn get_action_sender_account_name_from_proof(proof: &EosActionProof) -> Result<EosAccountName> {
        let end_index = 7;
        let serialized_action = proof.get_serialized_action()?;
        if serialized_action.len() < end_index + 1 {
            Err("Not enough data to parse `EosOnEthEosTxInfo` action sender from proof!".into())
        } else {
            let result = EosAccountName::new(convert_bytes_to_u64(&serialized_action[..=end_index])?);
            debug!("✔ Action sender account name parsed from action proof: {}", result);
            Ok(result)
        }
    }

    fn get_eos_symbol_from_proof(proof: &EosActionProof) -> Result<EosSymbol> {
        let start_index = 24;
        let end_index = 31;
        proof
            .check_proof_action_data_length(
                end_index,
                "Not enough data to parse `EosOnEthEosTxInfo` symbol from proof!",
            )
            .and_then(|_| {
                let result = EosSymbol::new(convert_bytes_to_u64(&proof.action.data[start_index..=end_index])?);
                debug!("✔ Eos symbol parsed from action proof: {}", result);
                Ok(result)
            })
    }

    fn get_token_symbol_from_proof(proof: &EosActionProof) -> Result<String> {
        let result = eos_symbol_to_string(Self::get_eos_symbol_from_proof(proof)?.as_u64());
        debug!("✔ Token symbol parsed from action proof: {}", result);
        Ok(result)
    }

    fn get_eos_amount_from_proof(proof: &EosActionProof) -> Result<u64> {
        let start_index = 16;
        let end_index = 23;
        proof
            .check_proof_action_data_length(
                end_index,
                "Not enough data to parse `EosOnEthEosTxInfo` amount from proof!",
            )
            .and_then(|_| convert_bytes_to_u64(&proof.action.data[start_index..=end_index].to_vec()))
    }

    fn get_eth_address_from_proof(proof: &EosActionProof) -> Result<EthAddress> {
        let start_index = 33;
        let end_index = 74;
        proof
            .check_proof_action_data_length(
                end_index,
                "Not enough data to parse `EosOnEthEosTxInfo` ETH address from proof!",
            )
            .and_then(|_| {
                let result = EthAddress::from_slice(&hex::decode(strip_hex_prefix(from_utf8(
                    &proof.action.data[start_index..=end_index],
                )?))?);
                debug!("✔ ETH address parsed from action proof: {}", result);
                Ok(result)
            })
    }

    fn get_eth_address_from_proof_or_revert_to_safe_eth_address(proof: &EosActionProof) -> Result<EthAddress> {
        match Self::get_eth_address_from_proof(proof) {
            Ok(eth_address) => Ok(eth_address),
            Err(_) => {
                info!(
                    "✘ Error getting ETH addess from proof! Default to `SAFE_ETH_ADDRESS`: {}",
                    SAFE_ETH_ADDRESS.to_string()
                );
                Ok(*SAFE_ETH_ADDRESS)
            },
        }
    }

    fn check_proof_is_from_contract(proof: &EosActionProof, contract: &EosAccountName) -> Result<()> {
        Self::get_action_sender_account_name_from_proof(proof).and_then(|ref action_sender| {
            if action_sender != contract {
                return Err(format!(
                    "Proof does not appear to be for an action from the EOS smart-contract: {}!",
                    contract
                )
                .into());
            }
            Ok(())
        })
    }

    fn get_asset_num_decimals_from_proof(proof: &EosActionProof) -> Result<usize> {
        Self::get_eos_symbol_from_proof(proof).and_then(|symbol| {
            let symbol_string = symbol.to_string();
            let pieces = symbol_string.split(',').collect::<Vec<&str>>();
            if pieces.is_empty() {
                Err("Error getting number of decimals from `EosSymbol`!".into())
            } else {
                Ok(pieces[0].parse::<usize>()?)
            }
        })
    }

    fn check_proof_is_for_action(proof: &EosActionProof, required_action_name: &str) -> Result<()> {
        Self::get_action_name_from_proof(proof).and_then(|action_name| {
            if action_name.to_string() != required_action_name {
                return Err(format!("Proof does not appear to be for a '{}' action!", REQUIRED_ACTION_NAME).into());
            }
            Ok(())
        })
    }

    pub fn from_eos_action_proof(
        proof: &EosActionProof,
        token_dictionary: &EosEthTokenDictionary,
        eos_smart_contract: &EosAccountName,
    ) -> Result<Self> {
        Self::check_proof_is_from_contract(proof, eos_smart_contract)
            .and_then(|_| Self::check_proof_is_for_action(proof, REQUIRED_ACTION_NAME))
            .and_then(|_| {
                info!("✔ Converting action proof to `eos-on-eth` eos tx info...");
                let token_address = Self::get_token_account_name_from_proof(proof)?;
                let dictionary_entry = token_dictionary.get_entry_via_eos_address_symbol_and_decimals(
                    &token_address,
                    &Self::get_token_symbol_from_proof(proof)?,
                    Self::get_asset_num_decimals_from_proof(proof)?,
                )?;
                let eos_asset = dictionary_entry.convert_u64_to_eos_asset(Self::get_eos_amount_from_proof(proof)?);
                let eth_amount = dictionary_entry.convert_eos_asset_to_eth_amount(&eos_asset)?;
                Ok(Self {
                    amount: eth_amount,
                    originating_tx_id: proof.tx_id,
                    global_sequence: proof.get_global_sequence(),
                    from: Self::get_token_sender_from_proof(proof)?,
                    recipient: Self::get_eth_address_from_proof_or_revert_to_safe_eth_address(proof)?,
                    eth_token_address: token_dictionary.get_eth_address_via_eos_address(&token_address)?,
                    eos_token_address: dictionary_entry.eos_address,
                })
            })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Deref, Constructor)]
pub struct EosOnEthEosTxInfos(pub Vec<EosOnEthEosTxInfo>);

impl EosOnEthEosTxInfos {
    pub fn from_eos_action_proofs(
        action_proofs: &[EosActionProof],
        token_dictionary: &EosEthTokenDictionary,
        eos_smart_contract: &EosAccountName,
    ) -> Result<Self> {
        Ok(EosOnEthEosTxInfos::new(
            action_proofs
                .iter()
                .map(|proof| EosOnEthEosTxInfo::from_eos_action_proof(proof, token_dictionary, eos_smart_contract))
                .collect::<Result<Vec<EosOnEthEosTxInfo>>>()?,
        ))
    }

    pub fn filter_out_already_processed_txs(&self, processed_tx_ids: &ProcessedGlobalSequences) -> Result<Self> {
        Ok(EosOnEthEosTxInfos::new(
            self.iter()
                .filter(|info| !processed_tx_ids.contains(&info.global_sequence))
                .cloned()
                .collect::<Vec<EosOnEthEosTxInfo>>(),
        ))
    }

    pub fn get_global_sequences(&self) -> GlobalSequences {
        GlobalSequences::new(
            self.iter()
                .map(|infos| infos.global_sequence)
                .collect::<Vec<GlobalSequence>>(),
        )
    }

    pub fn filter_out_those_with_value_too_low(&self) -> Result<Self> {
        let min_amount = U256::from_dec_str(MINIMUM_WEI_AMOUNT)?;
        Ok(EosOnEthEosTxInfos::new(
            self.iter()
                .filter(|info| {
                    if info.amount >= min_amount {
                        true
                    } else {
                        info!("✘ Filtering out tx info ∵ value too low: {:?}", info);
                        false
                    }
                })
                .cloned()
                .collect::<Vec<EosOnEthEosTxInfo>>(),
        ))
    }

    pub fn to_eth_signed_txs(
        &self,
        eth_account_nonce: u64,
        chain_id: &EthChainId,
        gas_price: u64,
        eth_private_key: &EthPrivateKey,
    ) -> Result<EthTransactions> {
        info!("✔ Getting ETH signed transactions from `erc20-on-eos` redeem infos...");
        Ok(EthTransactions::new(
            self.iter()
                .enumerate()
                .map(|(i, tx_info)| {
                    info!(
                        "✔ Signing ETH tx for amount: {}, to address: {}",
                        tx_info.amount, tx_info.recipient
                    );
                    EthTransaction::new_unsigned(
                        encode_erc777_mint_with_no_data_fxn(&tx_info.recipient, &tx_info.amount)?,
                        eth_account_nonce + i as u64,
                        ZERO_ETH_VALUE,
                        tx_info.eth_token_address,
                        chain_id,
                        ERC777_MINT_WITH_NO_DATA_GAS_LIMIT,
                        gas_price,
                    )
                    .sign(eth_private_key)
                })
                .collect::<Result<Vec<EthTransaction>>>()?,
        ))
    }
}

pub fn maybe_parse_eos_on_eth_eos_tx_infos_and_put_in_state<D: DatabaseInterface>(
    state: EosState<D>,
) -> Result<EosState<D>> {
    info!("✔ Parsing redeem params from actions data...");
    EosOnEthEosTxInfos::from_eos_action_proofs(
        &state.action_proofs,
        state.get_eos_eth_token_dictionary()?,
        &get_eos_account_name_from_db(&state.db)?,
    )
    .and_then(|tx_infos| {
        info!("✔ Parsed {} sets of redeem info!", tx_infos.len());
        state.add_eos_on_eth_eos_tx_info(tx_infos)
    })
}

pub fn maybe_filter_out_already_processed_tx_ids_from_state<D: DatabaseInterface>(
    state: EosState<D>,
) -> Result<EosState<D>> {
    info!("✔ Filtering out already processed tx IDs...");
    debug!("Num tx infos before: {}", &state.eos_on_eth_eos_tx_infos.len());
    state
        .eos_on_eth_eos_tx_infos
        .filter_out_already_processed_txs(&state.processed_tx_ids)
        .and_then(|filtered| {
            debug!("Num tx infos after: {}", filtered.len());
            state.add_eos_on_eth_eos_tx_info(filtered)
        })
}

pub fn maybe_filter_out_value_too_low_txs_from_state<D: DatabaseInterface>(state: EosState<D>) -> Result<EosState<D>> {
    info!("✔ Filtering out value too low txs from state...");
    debug!("Num tx infos before: {}", &state.eos_on_eth_eos_tx_infos.len());
    state
        .eos_on_eth_eos_tx_infos
        .filter_out_those_with_value_too_low()
        .and_then(|filtered| {
            debug!("Num tx infos after: {}", &filtered.len());
            state.replace_eos_on_eth_eos_tx_infos(filtered)
        })
}

pub fn maybe_sign_normal_eth_txs_and_add_to_state<D: DatabaseInterface>(state: EosState<D>) -> Result<EosState<D>> {
    if state.eos_on_eth_eos_tx_infos.len() == 0 {
        info!("✔ No EOS tx info in state ∴ no ETH transactions to sign!");
        Ok(state)
    } else {
        state
            .eos_on_eth_eos_tx_infos
            .to_eth_signed_txs(
                get_eth_account_nonce_from_db(&state.db)?,
                &get_eth_chain_id_from_db(&state.db)?,
                get_eth_gas_price_from_db(&state.db)?,
                &get_eth_private_key_from_db(&state.db)?,
            )
            .and_then(|signed_txs| {
                #[cfg(feature = "debug")]
                {
                    debug!("✔ Signed transactions: {:?}", signed_txs);
                }
                state.add_eth_signed_txs(signed_txs)
            })
    }
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::{
        chains::eos::{eos_test_utils::get_sample_eos_submission_material_n, eos_utils::convert_hex_to_checksum256},
        eos_on_eth::test_utils::{get_eos_submission_material_n, get_sample_eos_eth_token_dictionary},
    };

    fn get_sample_proof() -> EosActionProof {
        get_eos_submission_material_n(1).unwrap().action_proofs[0].clone()
    }

    #[test]
    fn should_get_token_sender_from_proof() {
        let proof = get_sample_proof();
        let result = EosOnEthEosTxInfo::get_token_sender_from_proof(&proof).unwrap();
        let expected_result = EosAccountName::from_str("oraclizetest").unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_token_account_name_from_proof() {
        let proof = get_sample_proof();
        let result = EosOnEthEosTxInfo::get_token_account_name_from_proof(&proof).unwrap();
        let expected_result = EosAccountName::from_str("eosio.token").unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_action_name_from_proof() {
        let proof = get_sample_proof();
        let result = EosOnEthEosTxInfo::get_action_name_from_proof(&proof).unwrap();
        let expected_result = EosName::from_str("pegin").unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_action_sender_account_name_from_proof() {
        let proof = get_sample_proof();
        let result = EosOnEthEosTxInfo::get_action_sender_account_name_from_proof(&proof).unwrap();
        let expected_result = EosAccountName::from_str("t11ppntoneos").unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_eos_symbol_from_proof() {
        let proof = get_sample_proof();
        let result = EosOnEthEosTxInfo::get_eos_symbol_from_proof(&proof).unwrap();
        let expected_result = EosSymbol::from_str("4,EOS").unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_token_symbol_from_proof() {
        let proof = get_sample_proof();
        let result = EosOnEthEosTxInfo::get_token_symbol_from_proof(&proof).unwrap();
        let expected_result = "EOS".to_string();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_eos_amount_from_proof() {
        let proof = get_sample_proof();
        let result = EosOnEthEosTxInfo::get_eos_amount_from_proof(&proof).unwrap();
        let expected_result = 1 as u64;
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_eth_address_from_proof() {
        let proof = get_sample_proof();
        let result = EosOnEthEosTxInfo::get_eth_address_from_proof(&proof).unwrap();
        let expected_result = EthAddress::from_slice(&hex::decode("5fDAEf0a0B11774dB68C38aB36957De8646aF1B5").unwrap());
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_eos_on_eth_eth_tx_info_from_action_proof() {
        let proof = get_sample_proof();
        let smart_contract_name = EosAccountName::from_str("t11ppntoneos").unwrap();
        let dictionary = get_sample_eos_eth_token_dictionary();
        let result = EosOnEthEosTxInfo::from_eos_action_proof(&proof, &dictionary, &smart_contract_name).unwrap();
        let expected_amount = U256::from_dec_str("100000000000000").unwrap();
        let expected_from = EosAccountName::from_str("oraclizetest").unwrap();
        let expected_recipient =
            EthAddress::from_slice(&hex::decode("5fDAEf0a0B11774dB68C38aB36957De8646aF1B5").unwrap());
        let expected_originating_tx_id =
            convert_hex_to_checksum256("cb2e6fbd5c82fb50b3c2e0658a887aa359f9f6b398457448322d86968a28e794").unwrap();
        let expected_global_sequence = 323917921677;
        let expected_eth_token_address =
            EthAddress::from_slice(&hex::decode("711c50b31ee0b9e8ed4d434819ac20b4fbbb5532").unwrap());
        assert_eq!(result.amount, expected_amount);
        assert_eq!(result.from, expected_from);
        assert_eq!(result.recipient, expected_recipient);
        assert_eq!(result.global_sequence, expected_global_sequence);
        assert_eq!(result.originating_tx_id, expected_originating_tx_id);
        assert_eq!(result.eth_token_address, expected_eth_token_address);
    }

    #[test]
    fn should_get_correct_signed_tx() {
        // NOTE Real tx: https://rinkeby.etherscan.io/tx/0x2181a9009da8e2418d67b95501e6c37347f9cce65ea97f9bf3737d5efaf9be89
        let expected_result = "f8aa808504a817c8008302bf2094711c50b31ee0b9e8ed4d434819ac20b4fbbb553280b84440c10f190000000000000000000000005fdaef0a0b11774db68c38ab36957de8646af1b500000000000000000000000000000000000000000000000000005af3107a40002ca0162392250af5a68aec146384043e109b00ff8d13a8565dcf286ea3e68cd2d097a067842749990070b15a7d4bf989dd6ddb264132fe77e83c9285c949e77a60d826";
        let proof = get_sample_proof();
        let smart_contract_name = EosAccountName::from_str("t11ppntoneos").unwrap();
        let dictionary = get_sample_eos_eth_token_dictionary();
        let pk = EthPrivateKey::from_slice(
            &hex::decode("e3925cf65ad0baa57cc67eae8fbea03eeeb8464f7ad17b34b28d24f531de71cb").unwrap(),
        )
        .unwrap();
        let tx_infos = EosOnEthEosTxInfos::from_eos_action_proofs(&[proof], &dictionary, &smart_contract_name).unwrap();
        let chain_id = EthChainId::Rinkeby;
        let gas_price = 20_000_000_000;
        let nonce = 0;
        let signed_txs = tx_infos.to_eth_signed_txs(nonce, &chain_id, gas_price, &pk).unwrap();
        let result = signed_txs[0].serialize_hex();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_asset_num_decimals_from_proof() {
        let proof = get_sample_proof();
        let expected_result = 4;
        let result = EosOnEthEosTxInfo::get_asset_num_decimals_from_proof(&proof).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_not_panic_due_to_out_of_range_error() {
        // NOTE This sample has a badly formed ETH address in it which caused a panic. This test
        // asserts that this is no longer the case.
        let proof = get_sample_eos_submission_material_n(11).action_proofs[0].clone();
        let dictionary_str = "[{\"eth_token_decimals\":18,\"eos_token_decimals\":4,\"eth_symbol\":\"pSEEDS\",\"eos_symbol\":\"SEEDS\",\"eth_address\":\"6db338e6ed75f67cd5a4ef8bdf59163b32d4bd46\",\"eos_address\":\"token.seeds\"},{\"eth_token_decimals\":18,\"eos_token_decimals\":4,\"eth_symbol\":\"TLOS\",\"eos_symbol\":\"TLOS\",\"eth_address\":\"7825e833d495f3d1c28872415a4aee339d26ac88\",\"eos_address\":\"eosio.token\"}]";
        let dictionary = EosEthTokenDictionary::from_str(dictionary_str).unwrap();
        let eos_smart_contract = EosAccountName::from_str("xeth.ptokens").unwrap();
        let result = EosOnEthEosTxInfo::from_eos_action_proof(&proof, &dictionary, &eos_smart_contract).unwrap();
        let expected_recipient = *SAFE_ETH_ADDRESS;
        assert_eq!(result.recipient, expected_recipient);
    }
}
