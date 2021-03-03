use crate::{
    chains::{
        eos::{
            eos_crypto::{
                eos_private_key::EosPrivateKey,
                eos_transaction::{get_signed_eos_ptoken_issue_tx, EosSignedTransaction, EosSignedTransactions},
            },
            eos_database_utils::get_eos_chain_id_from_db,
        },
        eth::eth_state::EthState,
    },
    erc20_on_eos::eth::peg_in_info::Erc20OnEosPegInInfos,
    traits::DatabaseInterface,
    types::Result,
};

pub fn get_signed_eos_ptoken_issue_txs_from_erc20_on_eos_peg_in_infos(
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
    Ok(EosSignedTransactions::new(
        peg_in_infos
            .iter()
            .map(|peg_in_info| {
                info!("✔ Signing EOS tx from `erc20-on-eos` peg in info: {:?}", peg_in_info);
                get_signed_eos_ptoken_issue_tx(
                    ref_block_num,
                    ref_block_prefix,
                    &peg_in_info.eos_address,
                    &peg_in_info.eos_asset_amount,
                    chain_id,
                    private_key,
                    &peg_in_info.eos_token_address,
                )
            })
            .collect::<Result<Vec<EosSignedTransaction>>>()?,
    ))
}

pub fn maybe_sign_eos_txs_and_add_to_eth_state<D: DatabaseInterface>(state: EthState<D>) -> Result<EthState<D>> {
    info!("✔ Maybe signing `erc20-on-eos` peg in txs...");
    let submission_material = state.get_eth_submission_material()?;
    get_signed_eos_ptoken_issue_txs_from_erc20_on_eos_peg_in_infos(
        submission_material.get_eos_ref_block_num()?,
        submission_material.get_eos_ref_block_prefix()?,
        &get_eos_chain_id_from_db(&state.db)?,
        &EosPrivateKey::get_from_db(&state.db)?,
        &state.erc20_on_eos_peg_in_infos,
    )
    .and_then(|signed_txs| state.add_eos_transactions(signed_txs))
}
