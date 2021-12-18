#![allow(non_snake_case)]
use std::str::FromStr;

use derive_more::Constructor;
use eos_chain::{AccountName as EosAccountName, Asset as EosAsset, NumBytes, Read, SerializeData, Write};

use crate::types::Bytes;

#[derive(Clone, Debug, Read, Write, NumBytes, PartialEq, Default, SerializeData)]
#[eosio_core_root_path = "eos_chain"]
pub struct PTokenMintActionWithoutMetadata {
    pub to: EosAccountName,
    pub quantity: EosAsset,
    pub memo: String,
}

impl PTokenMintActionWithoutMetadata {
    pub fn new(to: EosAccountName, quantity: EosAsset, memo: &str) -> Self {
        PTokenMintActionWithoutMetadata {
            to,
            quantity,
            memo: memo.into(),
        }
    }

    pub fn from_str(to: &str, quantity: &str, memo: &str) -> crate::Result<Self> {
        Ok(Self::new(
            EosAccountName::from_str(to)?,
            EosAsset::from_str(quantity)?,
            memo,
        ))
    }
}

#[derive(Clone, Debug, Read, Write, NumBytes, PartialEq, Default, SerializeData, Constructor)]
#[eosio_core_root_path = "eos_chain"]
pub struct PTokenMintActionWithMetadata {
    pub to: EosAccountName,
    pub quantity: EosAsset,
    pub memo: String,
    pub metadata: Bytes,
}

#[derive(Clone, Debug, Read, Write, NumBytes, Default, SerializeData)]
#[eosio_core_root_path = "eos_chain"]
pub struct PTokenPegOutAction {
    pub tokenContract: EosAccountName,
    pub quantity: EosAsset,
    pub recipient: EosAccountName,
    pub metadata: Bytes,
}

impl PTokenPegOutAction {
    pub fn from_str(token_contract: &str, quantity: &str, recipient: &str, metadata: &[u8]) -> crate::Result<Self> {
        Ok(Self {
            metadata: metadata.to_vec(),
            quantity: EosAsset::from_str(quantity)?,
            recipient: EosAccountName::from_str(recipient)?,
            tokenContract: EosAccountName::from_str(token_contract)?,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_create_ptoken_mint_action_from_str() {
        let result = PTokenMintActionWithoutMetadata::from_str("whateverxxx", "1.000 EOS", "a memo");
        assert!(result.is_ok());
    }

    #[test]
    fn should_crate_ptoken_peg_out_action_from_str() {
        let result =
            PTokenPegOutAction::from_str("whateverxxx", "1.000 EOS", "whateveryyyy", &vec![0x1, 0x3, 0x3, 0x7]);
        assert!(result.is_ok());
    }
}
