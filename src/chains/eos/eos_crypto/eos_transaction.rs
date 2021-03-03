use derive_more::{Constructor, Deref};
use eos_primitives::{Action as EosAction, PermissionLevel, SerializeData, Transaction as EosTransaction};

use crate::{
    chains::eos::{
        eos_actions::PTokenMintAction,
        eos_constants::{EOS_ACCOUNT_PERMISSION_LEVEL, EOS_MAX_EXPIRATION_SECS, MEMO},
        eos_crypto::eos_private_key::EosPrivateKey,
    },
    types::{Bytes, Result},
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
    fn get_signing_data_from_unsigned_tx(unsigned_tx: &EosTransaction, chain_id: &str) -> Result<Bytes> {
        Ok([hex::decode(chain_id)?, unsigned_tx.to_serialize_data(), vec![0u8; 32]].concat())
    }

    pub fn from_unsigned_tx(
        to: &str,
        amount: &str,
        chain_id: &str,
        eos_private_key: &EosPrivateKey,
        unsigned_tx: &EosTransaction,
    ) -> Result<EosSignedTransaction> {
        Ok(Self::new(
            amount.to_string(),
            to.to_string(),
            eos_private_key
                .sign_message_bytes(&Self::get_signing_data_from_unsigned_tx(unsigned_tx, chain_id)?)?
                .to_string(),
            hex::encode(&unsigned_tx.to_serialize_data()[..]),
        ))
    }
}

fn get_eos_ptoken_issue_action(
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
        PTokenMintAction::from_str(to, amount, memo)?,
    )?)
}

pub fn get_signed_eos_ptoken_issue_tx(
    ref_block_num: u16,
    ref_block_prefix: u32,
    to: &str,
    amount: &str,
    chain_id: &str,
    private_key: &EosPrivateKey,
    account_name: &str,
) -> Result<EosSignedTransaction> {
    info!("✔ Signing eos tx for {} to {}...", &amount, &to);
    get_eos_ptoken_issue_action(
        to,
        account_name,
        MEMO,
        account_name,
        amount,
        EOS_ACCOUNT_PERMISSION_LEVEL,
    )
    .map(|action| EosTransaction::new(EOS_MAX_EXPIRATION_SECS, ref_block_num, ref_block_prefix, vec![action]))
    .and_then(|ref unsigned_tx| EosSignedTransaction::from_unsigned_tx(to, amount, chain_id, private_key, unsigned_tx))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::eos::{
        eos_constants::{EOS_ACCOUNT_PERMISSION_LEVEL, EOS_MAX_EXPIRATION_SECS},
        eos_test_utils::EOS_JUNGLE_CHAIN_ID,
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
            vec![get_eos_ptoken_issue_action(
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
        let result = EosSignedTransaction::from_unsigned_tx(to, amount, EOS_JUNGLE_CHAIN_ID, &pk, &unsigned_tx)
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
        let result = get_signed_eos_ptoken_issue_tx(
            ref_block_num,
            ref_block_prefix,
            to,
            amount,
            EOS_JUNGLE_CHAIN_ID,
            &pk,
            account_name,
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
