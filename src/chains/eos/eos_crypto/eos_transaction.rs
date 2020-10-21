use eos_primitives::{
    SerializeData,
    PermissionLevel,
    ActionPTokenMint,
    Action as EosAction,
    Transaction as EosTransaction,
};
use crate::{
    types::Result,
    chains::eos::{
        eos_types::EosSignedTransaction,
        eos_constants::PBTC_MINT_FXN_NAME,
        eos_crypto::eos_private_key::EosPrivateKey,
    },
};

fn get_peos_permission_level(
    actor: &str,
    permission_level: &str,
) -> Result<PermissionLevel> {
    Ok(PermissionLevel::from_str(actor, permission_level)?)
}

fn get_peos_transfer_action(
    to: &str,
    _from: &str,
    memo: &str,
    amount: &str,
) -> Result<ActionPTokenMint> {
    Ok(ActionPTokenMint::from_str(to, amount, memo)?)
}

fn get_eos_minting_action(
    to: &str,
    from: &str,
    memo: &str,
    actor: &str,
    amount: &str,
    permission_level: &str,
) -> Result<EosAction> {
    Ok(
        EosAction::from_str(
            from,
            PBTC_MINT_FXN_NAME,
            vec![get_peos_permission_level(actor, permission_level)?],
            get_peos_transfer_action(to, from, memo, amount)?,
        )?
    )
}

#[allow(clippy::too_many_arguments)]
pub fn get_unsigned_eos_minting_tx(
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
    Ok(
        EosTransaction::new(
            seconds_from_now,
            ref_block_num,
            ref_block_prefix,
            vec![
                get_eos_minting_action(
                    to,
                    from,
                    memo,
                    actor,
                    amount,
                    permission_level,
                )?
            ]
        )
    )
}

pub fn sign_peos_transaction(
    to: &str,
    amount: &str,
    chain_id: &str,
    eos_private_key: &EosPrivateKey,
    unsigned_transaction: &EosTransaction,
) -> Result<EosSignedTransaction> {
    Ok(
        EosSignedTransaction::new(
            format!(
                "{}",
                eos_private_key
                    .sign_message_bytes(
                        &unsigned_transaction.get_signing_data(chain_id)?
                    )?
            ),
            hex::encode(
                &unsigned_transaction.to_serialize_data()[..]
            ),
            to.to_string(),
            amount.to_string(),
        )
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        btc_on_eos::eos::eos_test_utils::EOS_JUNGLE_CHAIN_ID,
        chains::eos::eos_constants::{
            EOS_MAX_EXPIRATION_SECS,
            PEOS_ACCOUNT_PERMISSION_LEVEL,
        },
    };

    #[test]
    fn should_sign_minting_tx_correctly() {
        let to = "provtestable";
        let amount = "1.00000042 PFFF";
        let ref_block_num = 44391;
        let ref_block_prefix = 1355491504;
        let unsigned_transaction = get_unsigned_eos_minting_tx(
            to,
            "ptokensbtc1a",
            "BTC -> pBTC complete!",
            "ptokensbtc1a",
            amount,
            ref_block_num,
            ref_block_prefix,
            EOS_MAX_EXPIRATION_SECS,
            PEOS_ACCOUNT_PERMISSION_LEVEL,
        ).unwrap();
        let pk = EosPrivateKey::from_slice(
            &hex::decode(
            "0bc331469a2c834b26ff3af7a72e3faab3ee806c368e7a8008f57904237c6057"
            ).unwrap()
        ).unwrap();
        let result = sign_peos_transaction(
            to,
            amount,
            EOS_JUNGLE_CHAIN_ID,
            &pk,
            &unsigned_transaction,
        )
            .unwrap()
            .transaction;
        // NOTE: First 4 bytes are the timestamp (8 hex chars...)
        // NOTE: Signature not deterministic ∴ we don't test it.
        let expected_result = "67adb028cb5000000000016002ca074f0569ae0000000000a53176016002ca074f0569ae00000000a8ed32322ea0e23119abbce9ad2ae1f50500000000085046464600000015425443202d3e207042544320636f6d706c6574652100".to_string();
        let result_without_timestamp = &result[8..];
        assert_eq!(result_without_timestamp, expected_result);
    }
}
