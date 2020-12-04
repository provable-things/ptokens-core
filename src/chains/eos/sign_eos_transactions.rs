use crate::{
    chains::{
        eos::{
            eos_constants::{EOS_MAX_EXPIRATION_SECS, MEMO, PEOS_ACCOUNT_PERMISSION_LEVEL},
            eos_crypto::{
                eos_private_key::EosPrivateKey,
                eos_transaction::{get_unsigned_eos_minting_tx, sign_peos_transaction},
            },
            eos_database_utils::get_eos_chain_id_from_db,
            eos_types::{EosSignedTransaction, EosSignedTransactions},
        },
        eth::eth_state::EthState,
    },
    erc20_on_eos::eth::peg_in_info::Erc20OnEosPegInInfos,
    traits::DatabaseInterface,
    types::Result,
};

fn get_signed_tx(
    ref_block_num: u16,
    ref_block_prefix: u32,
    to: &str,
    amount: &str,
    chain_id: &str,
    private_key: &EosPrivateKey,
    account_name: &str,
) -> Result<EosSignedTransaction> {
    info!("✔ Signing eos minting tx for {} to {}...", &amount, &to);
    get_unsigned_eos_minting_tx(
        to,
        account_name,
        MEMO,
        account_name,
        amount,
        ref_block_num,
        ref_block_prefix,
        EOS_MAX_EXPIRATION_SECS,
        PEOS_ACCOUNT_PERMISSION_LEVEL,
    )
    .and_then(|unsigned_tx| sign_peos_transaction(to, amount, chain_id, private_key, &unsigned_tx))
}

pub fn get_signed_txs_from_erc20_on_eos_peg_in_infos(
    ref_block_num: u16,
    ref_block_prefix: u32,
    chain_id: &str,
    private_key: &EosPrivateKey,
    peg_in_infos: &Erc20OnEosPegInInfos,
) -> Result<EosSignedTransactions> {
    info!(
        "✔ Signing {} EOS txs from `erc20-on-eos` peg in infos...",
        peg_in_infos.len()
    );
    peg_in_infos
        .iter()
        .map(|peg_in_info| {
            info!("✔ Signing EOS tx from `erc20-on-eos` peg in info: {:?}", peg_in_info);
            get_signed_tx(
                ref_block_num,
                ref_block_prefix,
                &peg_in_info.eos_address,
                &peg_in_info.eos_asset_amount,
                chain_id,
                private_key,
                &peg_in_info.eos_token_address,
            )
        })
        .collect()
}

pub fn maybe_sign_eos_txs_and_add_to_eth_state<D>(state: EthState<D>) -> Result<EthState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Maybe signing `erc20-on-eos` peg in txs...");
    let submission_material = state.get_eth_submission_material()?;
    get_signed_txs_from_erc20_on_eos_peg_in_infos(
        submission_material.get_eos_ref_block_num()?,
        submission_material.get_eos_ref_block_prefix()?,
        &get_eos_chain_id_from_db(&state.db)?,
        &EosPrivateKey::get_from_db(&state.db)?,
        &state.erc20_on_eos_peg_in_infos,
    )
    .and_then(|signed_txs| state.add_eos_transactions(signed_txs))
}
