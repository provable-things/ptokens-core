use bitcoin::{blockdata::transaction::Transaction as BtcTransaction, network::constants::Network as BtcNetwork};

use crate::{
    btc_on_eth::eth::redeem_info::BtcOnEthRedeemInfos,
    chains::{
        btc::{
            btc_database_utils::{
                get_btc_address_from_db,
                get_btc_fee_from_db,
                get_btc_network_from_db,
                get_btc_private_key_from_db,
            },
            btc_transaction::create_signed_raw_btc_tx_for_n_input_n_outputs,
            utxo_manager::utxo_utils::get_enough_utxos_to_cover_total,
        },
        eth::eth_state::EthState,
    },
    traits::DatabaseInterface,
    types::Result,
};

fn create_btc_tx_from_redeem_infos<D: DatabaseInterface>(
    db: &D,
    sats_per_byte: u64,
    btc_network: BtcNetwork,
    redeem_infos: &BtcOnEthRedeemInfos,
) -> Result<BtcTransaction> {
    info!("✔ Getting correct amount of UTXOs...");
    debug!("✔ Network: {}", btc_network);
    debug!("✔ Satoshis per byte: {}", sats_per_byte);
    let utxos_and_values =
        get_enough_utxos_to_cover_total(db, redeem_infos.sum(), redeem_infos.len(), sats_per_byte, vec![].into())?;
    debug!("✔ Retrieved {} UTXOs!", utxos_and_values.len());
    info!("✔ Creating BTC transaction...");
    create_signed_raw_btc_tx_for_n_input_n_outputs(
        sats_per_byte,
        redeem_infos.to_btc_addresses_and_amounts()?,
        &get_btc_address_from_db(db)?[..],
        get_btc_private_key_from_db(db)?,
        utxos_and_values,
    )
}

pub fn maybe_create_btc_txs_and_add_to_state<D: DatabaseInterface>(state: EthState<D>) -> Result<EthState<D>> {
    info!("✔ Maybe creating BTC transaction(s) from redeem params...");
    match &state.btc_on_eth_redeem_infos.len() {
        0 => {
            info!("✔ No redeem params in state ∴ not creating BTC txs!");
            Ok(state)
        },
        _ => {
            info!("✔ Burn event params in state ∴ creating BTC txs...");
            create_btc_tx_from_redeem_infos(
                &state.db,
                get_btc_fee_from_db(&state.db)?,
                get_btc_network_from_db(&state.db)?,
                &state.btc_on_eth_redeem_infos,
            )
            .and_then(|signed_tx| {
                #[cfg(feature = "debug")]
                {
                    debug!("✔ Signed transaction: {:?}", signed_tx);
                }
                state.add_btc_transactions(vec![signed_tx])
            })
        },
    }
}
