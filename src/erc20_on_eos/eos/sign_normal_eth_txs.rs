use ethereum_types::Address as EthAddress;
use crate::{
    types::Result,
    traits::DatabaseInterface,
    erc20_on_eos::eos::redeem_info::Erc20OnEosRedeemInfos,
    chains::{
        eos::eos_state::EosState,
        eth::{
            eth_types::EthTransactions,
            eth_constants::ZERO_ETH_VALUE,
            eth_crypto::{
                eth_private_key::EthPrivateKey,
                eth_transaction::EthTransaction,
            },
            eth_database_utils::{
                get_eth_chain_id_from_db,
                get_eth_gas_price_from_db,
                get_eth_private_key_from_db,
                get_eth_account_nonce_from_db,
                get_erc20_on_eos_smart_contract_address_from_db,
            },
            eth_contracts::perc20::{
                PERC20_PEGOUT_GAS_LIMIT,
                encode_perc20_peg_out_fxn_data,
            },
        },
    },
};

pub fn get_eth_signed_txs(
    redeem_infos: &Erc20OnEosRedeemInfos,
    erc20_on_eos_smart_contract_address: &EthAddress,
    eth_account_nonce: u64,
    chain_id: u8,
    gas_price: u64,
    eth_private_key: EthPrivateKey,
) -> Result<EthTransactions> {
    info!("✔ Getting ETH signed transactions from `erc20-on-eos` redeem infos...");
    redeem_infos
        .iter()
        .enumerate()
        .map(|(i, redeem_info)| {
            info!("✔ Signing ETH tx for amount: {}, to address: {}", redeem_info.amount, redeem_info.recipient);
            EthTransaction::new_unsigned(
                encode_perc20_peg_out_fxn_data(
                    redeem_info.recipient,
                    redeem_info.eth_token_address,
                    redeem_info.amount
                )?,
                eth_account_nonce + i as u64,
                ZERO_ETH_VALUE,
                *erc20_on_eos_smart_contract_address,
                chain_id,
                PERC20_PEGOUT_GAS_LIMIT,
                gas_price,
            )
                .sign(eth_private_key.clone())
        })
        .collect::<Result<EthTransactions>>()
}

pub fn maybe_sign_normal_eth_txs_and_add_to_state<D: DatabaseInterface>(state: EosState<D>) -> Result<EosState<D>> {
    if state.erc20_on_eos_redeem_infos.len() == 0 {
        info!("✔ No redeem infos in state ∴ no ETH transactions to sign!");
        Ok(state)
    } else {
        get_eth_signed_txs(
            &state.erc20_on_eos_redeem_infos,
            &get_erc20_on_eos_smart_contract_address_from_db(&state.db)?,
            get_eth_account_nonce_from_db(&state.db)?,
            get_eth_chain_id_from_db(&state.db)?,
            get_eth_gas_price_from_db(&state.db)?,
            get_eth_private_key_from_db(&state.db)?,
        )
            .and_then(|signed_txs| {
                #[cfg(feature="debug")] { debug!("✔ Signed transactions: {:?}", signed_txs); }
                state.add_erc20_on_eos_signed_txs(signed_txs)
            })
    }
}
