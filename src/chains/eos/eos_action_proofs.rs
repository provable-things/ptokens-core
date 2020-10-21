use std::str::{
    FromStr,
    from_utf8,
};
use ethereum_types::{
    U256,
    Address as EthAddress,
};
use eos_primitives::{
    Checksum256,
    Action as EosAction,
    Symbol as EosSymbol,
    AccountName as EosAccountName,
    ActionReceipt as EosActionReceipt,
    ActionName,
    AccountName,
    PermissionLevel,
    PermissionLevels,
};
use crate::{
    constants::SAFE_ETH_ADDRESS,
    btc_on_eos::eos::redeem_info::BtcOnEosRedeemInfo,
    erc20_on_eos::eos::redeem_info::Erc20OnEosRedeemInfo,
    types::{
        Bytes,
        Result,
    },
    utils::{
        convert_bytes_to_u64,
        maybe_strip_hex_prefix,
    },
    chains::eos::{
        eos_types:: MerkleProof,
        eos_utils::convert_hex_to_checksum256,
        parse_eos_action_receipts::parse_eos_action_receipt_json,
        eos_erc20_dictionary::{
            EosErc20Dictionary,
            EosErc20DictionaryEntry,
        },
    },
};

pub type EosActionProofs = Vec<EosActionProof>;
pub type EosActionProofJsons = Vec<EosActionProofJson>;
pub type AuthSequenceJsons = Vec<AuthSequenceJson>;
pub type AuthorizationJsons = Vec<AuthorizationJson>;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct EosActionProof {
    pub action: EosAction,
    pub tx_id: Checksum256,
    pub action_proof: MerkleProof,
    pub action_receipt: EosActionReceipt,
}

impl EosActionProof {
    #[allow(dead_code)] // TODO Use when checking for correct symbol!
    fn get_eos_symbol(&self) -> Result<EosSymbol> {
        Ok(EosSymbol::new(convert_bytes_to_u64(&self.action.data[16..24].to_vec())?))
    }

    fn get_btc_on_eos_eos_amount(&self) -> Result<u64> {
        convert_bytes_to_u64(&self.action.data[8..16].to_vec())
    }

    fn get_erc20_on_eos_eth_redeem_amount(&self, dictionary_entry: &EosErc20DictionaryEntry) -> Result<U256> {
        dictionary_entry
            .convert_u64_to_eos_asset(convert_bytes_to_u64(&self.action.data[8..16].to_vec())?)
            .and_then(|eos_asset| dictionary_entry.convert_eos_asset_to_eth_amount(&eos_asset))
    }

    fn get_redeem_action_sender(&self) -> Result<EosAccountName> {
        let account_name = EosAccountName::new(convert_bytes_to_u64(&self.action.data[..8].to_vec())?);
        debug!("✔ Account name parsed from redeem action: {}", account_name);
        Ok(account_name)
    }

    fn get_btc_on_eos_btc_redeem_address(&self) -> Result<String> {
        Ok(from_utf8(&self.action.data[25..])?.to_string())
    }

    fn get_memo_string(&self) -> Result<String> {
        Ok(from_utf8(&self.action.data[25..])?.to_string())
    }

    fn get_erc20_on_eos_eth_redeem_address(&self) -> Result<EthAddress> {
        Ok(EthAddress::from_slice(&hex::decode(&maybe_strip_hex_prefix(&self.get_memo_string()?)?)?))
    }

    // TODO get sample with bad ETH address and test this!
    fn get_erc20_on_eos_eth_redeem_address_or_default_to_safe_address(&self) -> Result<EthAddress> {
        match self.get_erc20_on_eos_eth_redeem_address() {
            Ok(address) => Ok(address),
            Err(_) => {
                info!("✘ Could not parse ETH address from action memo: {}", self.get_memo_string()?);
                info!("✔ Defaulting to safe ETH address: 0x{}", hex::encode(*SAFE_ETH_ADDRESS));
                Ok(*SAFE_ETH_ADDRESS)
            }
        }
    }

    pub fn from_json(json: &EosActionProofJson) -> Result<Self> {
        Ok(EosActionProof {
            action: json.action_json.to_action()?,
            action_proof: json.action_proof.clone(),
            tx_id: convert_hex_to_checksum256(&json.tx_id)?,
            action_receipt: parse_eos_action_receipt_json(&json.action_receipt_json)?,
        })
    }

    pub fn to_btc_on_eos_redeem_info(&self) -> Result<BtcOnEosRedeemInfo> {
        info!("✔ Converting action proof to `btc-on-eos` redeem info...");
        Ok(BtcOnEosRedeemInfo {
            originating_tx_id: self.tx_id,
            from: self.get_redeem_action_sender()?,
            amount: self.get_btc_on_eos_eos_amount()?,
            recipient: self.get_btc_on_eos_btc_redeem_address()?,
            global_sequence: self.action_receipt.global_sequence,
        })
    }

    pub fn to_erc20_on_eos_redeem_info(&self, dictionary: &EosErc20Dictionary) -> Result<Erc20OnEosRedeemInfo> {
        dictionary
            .get_entry_via_eos_address(&self.action.account.to_string())
            .and_then(|entry| {
                info!("✔ Converting action proof to `erc20-on-eos` redeem info...");
                Ok(Erc20OnEosRedeemInfo {
                    originating_tx_id: self.tx_id,
                    eth_token_address: entry.eth_address,
                    from: self.get_redeem_action_sender()?,
                    eos_token_address: entry.eos_address.clone(),
                    global_sequence: self.action_receipt.global_sequence,
                    amount: self.get_erc20_on_eos_eth_redeem_amount(&entry)?,
                    recipient: self.get_erc20_on_eos_eth_redeem_address_or_default_to_safe_address()?,
                })
            })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EosActionProofJson {
    pub tx_id: String,
    pub block_id: String,
    pub action_index: usize,
    pub action_digest: String,
    pub action_proof: MerkleProof,
    pub serialized_action: String,
    pub action_json: EosActionJson,
    pub action_receipt_digest: String,
    pub serialized_action_receipt: String,
    pub action_receipt_json: EosActionReceiptJson,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EosActionReceiptJson {
    pub receiver: String,
    pub act_digest: String,
    pub global_sequence: u64,
    pub recv_sequence:  u64,
    pub auth_sequence: AuthSequenceJsons,
    pub code_sequence: usize,
    pub abi_sequence: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthSequenceJson(pub String, pub u64);


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EosActionJson {
    pub name: String,
    pub account: String,
    pub hex_data: Option<String>,
    pub authorization: AuthorizationJsons,
}

impl EosActionJson {
    fn parse_authorization_json(authorization_json: &AuthorizationJson) -> Result<PermissionLevel> {
        Ok(PermissionLevel::from_str(authorization_json.actor.clone(), authorization_json.permission.clone())?)
    }

    fn parse_authorization_jsons(authorization_jsons: &[AuthorizationJson]) -> Result<PermissionLevels> {
        authorization_jsons.iter().map(Self::parse_authorization_json).collect()
    }

    fn deserialize_action_data(maybe_hex_data: &Option<String>) -> Result<Bytes> {
        match maybe_hex_data {
            Some(string) => Ok(hex::decode(string)?),
            None => Err("✘ Failed to decode hex_data field of action!".into())
        }
    }

    pub fn to_action(&self) -> Result<EosAction> {
        Ok(EosAction {
            name: ActionName::from_str(&self.name)?,
            account: AccountName::from_str(&self.account)?,
            data: Self::deserialize_action_data(&self.hex_data)?,
            authorization: Self::parse_authorization_jsons(&self.authorization)?,
        })
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AuthorizationJson {
    pub actor: String,
    pub permission: String,
}


#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use crate::btc_on_eos::eos::eos_test_utils::get_sample_eos_submission_material_n;

    #[test]
    fn should_get_sender() {
        let expected_result = EosAccountName::from_str("provtestable")
            .unwrap();
        let result = get_sample_eos_submission_material_n(1)
            .action_proofs[0]
            .get_redeem_action_sender()
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_symbol() {
        let expected_result = EosSymbol::from_str("8,PFFF")
            .unwrap();
        let result = get_sample_eos_submission_material_n(1)
            .action_proofs[0]
            .get_eos_symbol()
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_amount() {
        let expected_result: u64 = 5111;
        let result = get_sample_eos_submission_material_n(1)
            .action_proofs[0]
            .get_btc_on_eos_eos_amount()
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_btc_on_eos_btc_redeem_address_serialized_action() {
        let expected_result = "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM"
            .to_string();
        let result = get_sample_eos_submission_material_n(1)
            .action_proofs[0]
            .get_btc_on_eos_btc_redeem_address()
            .unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_btc_on_eos_redeem_infos_from_action_proof_2() {
        let expected_result = BtcOnEosRedeemInfo {
            global_sequence: 577606126,
            amount: 1,
            recipient: "mr6ioeUxNMoavbr2VjaSbPAovzzgDT7Su9".to_string(),
            from: EosAccountName::from_str("provabletest").unwrap(),
            originating_tx_id: convert_hex_to_checksum256(
                &"34dff748d2bbb9504057d4be24c69b8ac38b2905f7e911dd0e9ed3bf369bae03".to_string()
            ).unwrap(),
        };
        let action_proof = get_sample_eos_submission_material_n(2).action_proofs[0].clone();
        let result = action_proof.to_btc_on_eos_redeem_info().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_btc_on_eos_redeem_infos_from_action_proof_3() {
        let expected_result = BtcOnEosRedeemInfo {
            global_sequence: 583774614,
            amount: 5666,
            recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
            from: EosAccountName::from_str("provabletest").unwrap(),
            originating_tx_id: convert_hex_to_checksum256(
                &"51f0dbbaf6989e9b980d0fa18bd70ddfc543851ff65140623d2cababce2ceb8c".to_string()
            ).unwrap(),
        };
        let action_proof = get_sample_eos_submission_material_n(3).action_proofs[0].clone();
        let result = action_proof.to_btc_on_eos_redeem_info().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_btc_on_eos_redeem_infos_from_action_proof_4() {
        let expected_result = BtcOnEosRedeemInfo {
            global_sequence: 579818529,
            amount: 5555,
            recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
            from: EosAccountName::from_str("provtestable").unwrap(),
            originating_tx_id: convert_hex_to_checksum256(
                &"8eaafcb796002a12e0f48ebc0f832bacca72a8b370e00967c65619a2c1814a04".to_string()
            ).unwrap(),
        };
        let action_proof = get_sample_eos_submission_material_n(4).action_proofs[0].clone();
        let result = action_proof.to_btc_on_eos_redeem_info().unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_btc_on_eos_redeem_infos_from_action_proof_5() {
        let expected_result = BtcOnEosRedeemInfo {
            global_sequence: 579838915,
            amount: 5111,
            recipient: "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
            from: EosAccountName::from_str("provtestable").unwrap(),
            originating_tx_id: convert_hex_to_checksum256(
                &"aebe7cd1a4687485bc5db87bfb1bdfb44bd1b7f9c080e5cb178a411fd99d2fd5".to_string()
            ).unwrap(),
        };
        let action_proof = get_sample_eos_submission_material_n(1).action_proofs[0].clone();
        let result = action_proof.to_btc_on_eos_redeem_info().unwrap();
        assert_eq!(result, expected_result);
    }

    fn get_sample_action_proof_for_erc20_redeem() -> EosActionProof {
        get_sample_eos_submission_material_n(10).action_proofs[0].clone()
    }

    #[test]
    fn should_get_erc20_on_eos_eth_redeem_amount() {
        let dictionary_entry = EosErc20DictionaryEntry::new(
            18,
            9,
            "PETH".to_string(),
            "SAM".to_string(),
            "testpethxxxx".to_string(),
            EthAddress::from_slice(&hex::decode("32eF9e9a622736399DB5Ee78A68B258dadBB4353").unwrap()),
        );
        let proof = get_sample_action_proof_for_erc20_redeem();
        let result = proof.get_erc20_on_eos_eth_redeem_amount(&dictionary_entry).unwrap();
        let expected_result = U256::from_dec_str("1337000000000").unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_erc20_on_eos_eth_redeem_address() {
        let expected_result =  EthAddress::from_slice(
            &hex::decode("fEDFe2616EB3661CB8FEd2782F5F0cC91D59DCaC").unwrap()
        );
        let proof = get_sample_action_proof_for_erc20_redeem();
        let result = proof.get_erc20_on_eos_eth_redeem_address().unwrap();
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
        );
        let dictionary = EosErc20Dictionary::new(vec![EosErc20DictionaryEntry::new(
            18,
            9,
            "PETH".to_string(),
            "SAM".to_string(),
            eos_account_name,
            EthAddress::from_slice(&hex::decode("32eF9e9a622736399DB5Ee78A68B258dadBB4353").unwrap()),
        )]);
        let proof = get_sample_action_proof_for_erc20_redeem();
        let result = proof.to_erc20_on_eos_redeem_info(&dictionary).unwrap();
        assert_eq!(result, expected_result);
    }
}
