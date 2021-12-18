use std::str::FromStr;

use derive_more::{Constructor, Deref};
use eos_chain::{
    AccountName as EosAccountName,
    Action as EosAction,
    Asset as EosAsset,
    PermissionLevel,
    SerializeData,
    Transaction as EosTransaction,
};
use serde::{Deserialize, Serialize};

use crate::{
    chains::eos::{
        eos_actions::{PTokenMintActionWithMetadata, PTokenMintActionWithoutMetadata},
        eos_chain_id::EosChainId,
        eos_constants::{EOS_ACCOUNT_PERMISSION_LEVEL, MEMO},
        eos_crypto::eos_private_key::EosPrivateKey,
    },
    types::{Byte, Bytes, Result},
};

#[derive(Debug, Clone, Eq, PartialEq, Deref, Constructor)]
pub struct EosSignedTransactions(pub Vec<EosSignedTransaction>);

#[derive(Clone, Debug, Eq, PartialEq, Constructor, Deserialize, Serialize)]
pub struct EosSignedTransaction {
    pub amount: String,
    pub recipient: String,
    pub signature: String,
    pub transaction: String,
}

impl EosSignedTransaction {
    fn get_signing_data_from_unsigned_tx(unsigned_tx: &EosTransaction, chain_id: &EosChainId) -> Result<Bytes> {
        Ok([chain_id.to_bytes(), unsigned_tx.to_serialize_data()?, vec![0u8; 32]].concat())
    }

    pub fn from_unsigned_tx(
        to: &str,
        amount: &str,
        chain_id: &EosChainId,
        eos_private_key: &EosPrivateKey,
        unsigned_tx: &EosTransaction,
    ) -> Result<EosSignedTransaction> {
        Ok(Self::new(
            amount.to_string(),
            to.to_string(),
            eos_private_key
                .sign_message_bytes(&Self::get_signing_data_from_unsigned_tx(unsigned_tx, chain_id)?)?
                .to_string(),
            hex::encode(&unsigned_tx.to_serialize_data()?[..]),
        ))
    }
}

fn get_eos_ptoken_mint_action_without_metadata(
    to: &str,
    from: &str,
    memo: &str,
    actor: &str,
    amount: &str,
    permission_level: &str,
) -> Result<EosAction> {
    Ok(EosAction::from_str(
        from,
        "issue",
        vec![PermissionLevel::from_str(actor, permission_level)?],
        PTokenMintActionWithoutMetadata::from_str(to, amount, memo)?,
    )?)
}

fn get_eos_ptoken_mint_action_with_metadata(
    to: &str,
    from: &str,
    memo: &str,
    actor: &str,
    amount: &str,
    permission_level: &str,
    metadata: &[Byte],
) -> Result<EosAction> {
    Ok(EosAction::from_str(
        from,
        "issuewdata",
        vec![PermissionLevel::from_str(actor, permission_level)?],
        PTokenMintActionWithMetadata::new(
            EosAccountName::from_str(to)?,
            EosAsset::from_str(amount)?,
            memo.to_string(),
            metadata.to_vec(),
        ),
    )?)
}

pub fn get_signed_eos_ptoken_issue_tx(
    ref_block_num: u16,
    ref_block_prefix: u32,
    to: &str,
    amount: &str,
    chain_id: &EosChainId,
    private_key: &EosPrivateKey,
    account_name: &str,
    timestamp: u32,
    metadata: Option<Bytes>,
) -> Result<EosSignedTransaction> {
    info!("✔ Signing eos tx for {} to {}...", &amount, &to);
    let action = match metadata {
        None => {
            info!("✔ Using pToken mint action WITHOUT metadata...");
            get_eos_ptoken_mint_action_without_metadata(
                to,
                account_name,
                MEMO,
                account_name,
                amount,
                EOS_ACCOUNT_PERMISSION_LEVEL,
            )?
        },
        Some(ref bytes) => {
            info!("✔ Using pToken mint action WITH metadata...");
            get_eos_ptoken_mint_action_with_metadata(
                to,
                account_name,
                MEMO,
                account_name,
                amount,
                EOS_ACCOUNT_PERMISSION_LEVEL,
                bytes,
            )?
        },
    };
    EosSignedTransaction::from_unsigned_tx(
        to,
        amount,
        chain_id,
        private_key,
        &EosTransaction::new(timestamp, ref_block_num, ref_block_prefix, vec![action]),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::eos::{
            eos_constants::{EOS_ACCOUNT_PERMISSION_LEVEL, EOS_MAX_EXPIRATION_SECS},
            eos_test_utils::EOS_JUNGLE_CHAIN_ID,
        },
        utils::get_unix_timestamp_as_u32,
    };

    fn get_unsigned_eos_tx(
        seconds_from_now: u32,
        ref_block_num: u16,
        ref_block_prefix: u32,
        actions: Vec<EosAction>,
    ) -> EosTransaction {
        EosTransaction::new(seconds_from_now, ref_block_num, ref_block_prefix, actions)
    }

    #[allow(clippy::too_many_arguments)]
    fn get_unsigned_eos_ptoken_issue_tx(
        to: &str,
        from: &str,
        memo: &str,
        actor: &str,
        amount: &str,
        ref_block_num: u16,
        ref_block_prefix: u32,
        seconds_from_now: u32,
        permission_level: &str,
    ) -> Result<EosTransaction> {
        Ok(get_unsigned_eos_tx(
            seconds_from_now,
            ref_block_num,
            ref_block_prefix,
            vec![get_eos_ptoken_mint_action_without_metadata(
                to,
                from,
                memo,
                actor,
                amount,
                permission_level,
            )?],
        ))
    }

    #[test]
    fn should_get_signed_eos_ptoken_issue_tx_via_unsigned() {
        let to = "provtestable";
        let amount = "1.00000042 PFFF";
        let ref_block_num = 44391;
        let ref_block_prefix = 1355491504;
        let unsigned_tx = get_unsigned_eos_ptoken_issue_tx(
            to,
            "ptokensbtc1a",
            "BTC -> pBTC complete!",
            "ptokensbtc1a",
            amount,
            ref_block_num,
            ref_block_prefix,
            EOS_MAX_EXPIRATION_SECS,
            EOS_ACCOUNT_PERMISSION_LEVEL,
        )
        .unwrap();
        let pk = EosPrivateKey::from_slice(
            &hex::decode("0bc331469a2c834b26ff3af7a72e3faab3ee806c368e7a8008f57904237c6057").unwrap(),
        )
        .unwrap();
        let result = EosSignedTransaction::from_unsigned_tx(to, amount, &EOS_JUNGLE_CHAIN_ID, &pk, &unsigned_tx)
            .unwrap()
            .transaction;
        // NOTE: First 4 bytes are the timestamp (8 hex chars...)
        // NOTE: Signature not deterministic ∴ we don't test it.
        let expected_result = "67adb028cb5000000000016002ca074f0569ae0000000000a53176016002ca074f0569ae00000000a8ed32322ea0e23119abbce9ad2ae1f50500000000085046464600000015425443202d3e207042544320636f6d706c6574652100".to_string();
        let result_without_timestamp = &result[8..];
        assert_eq!(result_without_timestamp, expected_result);
    }

    #[test]
    fn should_get_signed_eos_ptoken_issue_tx() {
        let to = "provtestable";
        let amount = "1.00000042 PFFF";
        let account_name = "ptokensbtc1a";
        let ref_block_num = 44391;
        let ref_block_prefix = 1355491504;
        let pk = EosPrivateKey::from_slice(
            &hex::decode("0bc331469a2c834b26ff3af7a72e3faab3ee806c368e7a8008f57904237c6057").unwrap(),
        )
        .unwrap();
        let timestamp = get_unix_timestamp_as_u32().unwrap() + EOS_MAX_EXPIRATION_SECS;
        let metadata = None;
        let result = get_signed_eos_ptoken_issue_tx(
            ref_block_num,
            ref_block_prefix,
            to,
            amount,
            &EOS_JUNGLE_CHAIN_ID,
            &pk,
            account_name,
            timestamp,
            metadata,
        )
        .unwrap()
        .transaction;
        // NOTE: First 4 bytes are the timestamp (8 hex chars...)
        // NOTE: Signature not deterministic ∴ we don't test it.
        let expected_result = "67adb028cb5000000000016002ca074f0569ae0000000000a53176016002ca074f0569ae00000000a8ed323219a0e23119abbce9ad2ae1f5050000000008504646460000000000".to_string();
        let result_without_timestamp = &result[8..];
        assert_eq!(result_without_timestamp, expected_result);
    }
}
