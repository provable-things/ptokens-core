use std::str::from_utf8;

use derive_more::{Constructor, Deref};
use eos_primitives::{AccountName as EosAccountName, Checksum256};
use ethereum_types::{Address as EthAddress, U256};

use crate::{
    chains::eos::{
        eos_action_proofs::EosActionProof,
        eos_eth_token_dictionary::{EosEthTokenDictionary, EosEthTokenDictionaryEntry},
        eos_global_sequences::{GlobalSequence, GlobalSequences, ProcessedGlobalSequences},
        eos_state::EosState,
    },
    constants::SAFE_ETH_ADDRESS,
    traits::DatabaseInterface,
    types::Result,
    utils::{convert_bytes_to_u64, strip_hex_prefix},
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Deref, Constructor)]
pub struct Erc20OnEosRedeemInfos(pub Vec<Erc20OnEosRedeemInfo>);

impl Erc20OnEosRedeemInfos {
    pub fn get_global_sequences(&self) -> GlobalSequences {
        GlobalSequences::new(
            self.iter()
                .map(|infos| infos.global_sequence)
                .collect::<Vec<GlobalSequence>>(),
        )
    }

    pub fn from_action_proofs(
        action_proofs: &[EosActionProof],
        dictionary: &EosEthTokenDictionary,
    ) -> Result<Erc20OnEosRedeemInfos> {
        Ok(Erc20OnEosRedeemInfos::new(
            action_proofs
                .iter()
                .map(|ref action_proof| Erc20OnEosRedeemInfo::from_action_proof(action_proof, dictionary))
                .collect::<Result<Vec<Erc20OnEosRedeemInfo>>>()?,
        ))
    }

    pub fn filter_out_already_processed_txs(&self, processed_tx_ids: &ProcessedGlobalSequences) -> Result<Self> {
        Ok(Erc20OnEosRedeemInfos::new(
            self.iter()
                .filter(|info| !processed_tx_ids.contains(&info.global_sequence))
                .cloned()
                .collect::<Vec<Erc20OnEosRedeemInfo>>(),
        ))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize, Constructor)]
pub struct Erc20OnEosRedeemInfo {
    pub amount: U256,
    pub from: EosAccountName,
    pub recipient: EthAddress,
    pub eth_token_address: EthAddress,
    pub originating_tx_id: Checksum256,
    pub global_sequence: GlobalSequence,
    pub eos_token_address: String,
    pub eos_tx_amount: String,
}

impl Erc20OnEosRedeemInfo {
    fn get_memo_string_from_proof(proof: &EosActionProof) -> Result<String> {
        proof
            .check_proof_action_data_length(25, "Not enough data to parse `Erc20OnEosRedeemInfo` memo from proof!")
            .and_then(|_| Ok(from_utf8(&proof.action.data[25..])?.to_string()))
    }

    fn get_erc20_on_eos_eth_redeem_address(proof: &EosActionProof) -> Result<EthAddress> {
        Ok(EthAddress::from_slice(&hex::decode(&strip_hex_prefix(
            &Self::get_memo_string_from_proof(&proof)?,
        ))?))
    }

    fn get_redeem_address_from_proof_or_default_to_safe_address(proof: &EosActionProof) -> Result<EthAddress> {
        match Self::get_erc20_on_eos_eth_redeem_address(proof) {
            Ok(address) => Ok(address),
            Err(_) => {
                info!(
                    "✘ Could not parse ETH address from action memo: {}",
                    Self::get_memo_string_from_proof(proof)?
                );
                info!("✔ Defaulting to safe ETH address: 0x{}", hex::encode(*SAFE_ETH_ADDRESS));
                Ok(*SAFE_ETH_ADDRESS)
            },
        }
    }

    fn get_redeem_amount_from_proof(
        proof: &EosActionProof,
        dictionary_entry: &EosEthTokenDictionaryEntry,
    ) -> Result<U256> {
        proof
            .check_proof_action_data_length(15, "Not enough data to parse `Erc20OnEosRedeemInfo` amount from proof!")
            .and_then(|_| {
                Ok(dictionary_entry
                    .convert_u64_to_eos_asset(convert_bytes_to_u64(&proof.action.data[8..=15].to_vec())?))
            })
            .and_then(|eos_asset| dictionary_entry.convert_eos_asset_to_eth_amount(&eos_asset))
    }

    pub fn from_action_proof(proof: &EosActionProof, dictionary: &EosEthTokenDictionary) -> Result<Self> {
        dictionary
            .get_entry_via_eos_address(&proof.get_action_eos_account())
            .and_then(|entry| {
                let amount = Self::get_redeem_amount_from_proof(proof, &entry)?;
                let eos_tx_amount = entry.convert_u256_to_eos_asset_string(&amount)?;
                info!("✔ Converting action proof to `erc20-on-eos` redeem info...");
                Ok(Self {
                    amount,
                    eos_tx_amount,
                    originating_tx_id: proof.tx_id,
                    eth_token_address: entry.eth_address,
                    from: proof.get_action_sender()?,
                    eos_token_address: entry.eos_address,
                    global_sequence: proof.action_receipt.global_sequence,
                    recipient: Self::get_redeem_address_from_proof_or_default_to_safe_address(proof)?,
                })
            })
    }
}

pub fn maybe_parse_redeem_infos_and_put_in_state<D: DatabaseInterface>(state: EosState<D>) -> Result<EosState<D>> {
    info!("✔ Parsing redeem params from actions data...");
    Erc20OnEosRedeemInfos::from_action_proofs(&state.action_proofs, state.get_eos_eth_token_dictionary()?).and_then(
        |redeem_infos| {
            info!("✔ Parsed {} sets of redeem info!", redeem_infos.len());
            state.add_erc20_on_eos_redeem_infos(redeem_infos)
        },
    )
}

pub fn maybe_filter_out_already_processed_tx_ids_from_state<D: DatabaseInterface>(
    state: EosState<D>,
) -> Result<EosState<D>> {
    info!("✔ Filtering out already processed tx IDs...");
    state
        .erc20_on_eos_redeem_infos
        .filter_out_already_processed_txs(&state.processed_tx_ids)
        .and_then(|filtered| state.add_erc20_on_eos_redeem_infos(filtered))
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use super::*;
    use crate::chains::eos::{
        eos_test_utils::get_sample_eos_submission_material_n,
        eos_utils::convert_hex_to_checksum256,
    };

    fn get_sample_action_proof_for_erc20_redeem() -> EosActionProof {
        get_sample_eos_submission_material_n(10).action_proofs[0].clone()
    }

    #[test]
    fn should_get_erc20_on_eos_eth_redeem_amount() {
        let dictionary_entry = EosEthTokenDictionaryEntry::new(
            18,
            9,
            "PETH".to_string(),
            "SAM".to_string(),
            "testpethxxxx".to_string(),
            EthAddress::from_slice(&hex::decode("32eF9e9a622736399DB5Ee78A68B258dadBB4353").unwrap()),
        );
        let proof = get_sample_action_proof_for_erc20_redeem();
        let result = Erc20OnEosRedeemInfo::get_redeem_amount_from_proof(&proof, &dictionary_entry).unwrap();
        let expected_result = U256::from_dec_str("1337000000000").unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_erc20_on_eos_eth_redeem_address() {
        let expected_result = EthAddress::from_slice(&hex::decode("fEDFe2616EB3661CB8FEd2782F5F0cC91D59DCaC").unwrap());
        let proof = get_sample_action_proof_for_erc20_redeem();
        let result = Erc20OnEosRedeemInfo::get_redeem_address_from_proof_or_default_to_safe_address(&proof).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_proof_to_erc20_on_eos_redeem_info() {
        let eos_account_name = "testpethxxxx".to_string();
        let expected_result = Erc20OnEosRedeemInfo::new(
            U256::from_dec_str("1337000000000").unwrap(),
            EosAccountName::from_str("t11ptokens11").unwrap(),
            EthAddress::from_slice(&hex::decode("fEDFe2616EB3661CB8FEd2782F5F0cC91D59DCaC").unwrap()),
            EthAddress::from_slice(&hex::decode("32eF9e9a622736399DB5Ee78A68B258dadBB4353").unwrap()),
            convert_hex_to_checksum256("ed991197c5d571f39b4605f91bf1374dd69237070d44b46d4550527c245a01b9").unwrap(),
            250255005734,
            eos_account_name.clone(),
            "0.000001337 PETH".to_string(),
        );
        let dictionary = EosEthTokenDictionary::new(vec![EosEthTokenDictionaryEntry::new(
            18,
            9,
            "PETH".to_string(),
            "SAM".to_string(),
            eos_account_name,
            EthAddress::from_slice(&hex::decode("32eF9e9a622736399DB5Ee78A68B258dadBB4353").unwrap()),
        )]);
        let proof = get_sample_action_proof_for_erc20_redeem();
        let result = Erc20OnEosRedeemInfo::from_action_proof(&proof, &dictionary).unwrap();
        assert_eq!(result, expected_result);
    }
}
