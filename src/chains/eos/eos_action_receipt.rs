use std::str::FromStr;

use bitcoin_hashes::{sha256, Hash};
use eos_primitives::{AccountName as EosAccountName, Checksum256, NumBytes, Read, SerializeData, Write};

use crate::{
    chains::eos::{
        eos_action_proofs::{AuthSequenceJson, EosActionReceiptJson},
        eos_utils::convert_hex_to_checksum256,
    },
    types::Bytes,
};

pub type AuthSequences = Vec<AuthSequence>;

#[derive(Clone, Debug, Deserialize, Serialize, Read, Write, NumBytes, Default, PartialEq, Eq, PartialOrd, Ord)]
#[eosio_core_root_path = "eos_primitives"]
pub struct AuthSequence(EosAccountName, u64);

impl SerializeData for AuthSequence {}

impl AuthSequence {
    pub fn new(recipient: &str, number: u64) -> crate::Result<Self> {
        Ok(AuthSequence(EosAccountName::from_str(recipient)?, number))
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, Read, Write, NumBytes, Default, PartialEq, Eq, PartialOrd, Ord)]
#[eosio_core_root_path = "eos_primitives"]
pub struct EosActionReceipt {
    pub recipient: EosAccountName,
    pub act_digest: Checksum256,
    pub global_sequence: u64,
    pub recv_sequence: u64,
    pub auth_sequence: AuthSequences,
    pub code_sequence: usize,
    pub abi_sequence: usize,
}

impl SerializeData for EosActionReceipt {}

impl EosActionReceipt {
    #[cfg(test)]
    pub fn new(
        recipient: &str,
        act_digest_string: &str,
        recv_sequence: u64,
        abi_sequence: usize,
        global_sequence: u64,
        code_sequence: usize,
        auth_sequences: AuthSequences,
    ) -> crate::Result<Self> {
        Ok(Self {
            abi_sequence,
            code_sequence,
            recv_sequence,
            global_sequence,
            auth_sequence: auth_sequences,
            recipient: EosAccountName::from_str(recipient)?,
            act_digest: convert_hex_to_checksum256(act_digest_string)?,
        })
    }

    pub fn serialize(&self) -> Bytes {
        self.to_serialize_data()
    }

    pub fn to_digest(&self) -> Bytes {
        sha256::Hash::hash(&self.serialize()).to_vec()
    }

    fn parse_auth_sequence_jsons(auth_sequence_jsons: &[AuthSequenceJson]) -> crate::Result<AuthSequences> {
        auth_sequence_jsons.iter().map(Self::parse_auth_sequence_json).collect()
    }

    fn parse_auth_sequence_json(auth_sequence_json: &AuthSequenceJson) -> crate::Result<AuthSequence> {
        AuthSequence::new(&auth_sequence_json.0, auth_sequence_json.1)
    }

    pub fn from_json(json: &EosActionReceiptJson) -> crate::Result<EosActionReceipt> {
        Ok(EosActionReceipt {
            abi_sequence: json.abi_sequence,
            code_sequence: json.code_sequence,
            recv_sequence: json.recv_sequence,
            global_sequence: json.global_sequence,
            recipient: EosAccountName::from_str(&json.receiver)?,
            act_digest: convert_hex_to_checksum256(&json.act_digest)?,
            auth_sequence: Self::parse_auth_sequence_jsons(&json.auth_sequence)?,
        })
    }
}
