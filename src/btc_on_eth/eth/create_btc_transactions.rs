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
            btc_utils::calculate_btc_tx_fee,
            utxo_manager::{utxo_database_utils::get_first_utxo_and_value, utxo_types::BtcUtxosAndValues},
        },
        eth::eth_state::EthState,
    },
    traits::DatabaseInterface,
    types::Result,
};
use bitcoin::{blockdata::transaction::Transaction as BtcTransaction, network::constants::Network as BtcNetwork};

fn get_enough_utxos_to_cover_total<D>(
    db: &D,
    required_btc_amount: u64,
    num_outputs: usize,
    sats_per_byte: u64,
    inputs: BtcUtxosAndValues,
) -> Result<BtcUtxosAndValues>
where
    D: DatabaseInterface,
{
    info!("✔ Getting UTXO from db...");
    get_first_utxo_and_value(db).and_then(|utxo_and_value| {
        debug!("✔ Retrieved UTXO of value: {}", utxo_and_value.value);
        let fee = calculate_btc_tx_fee(inputs.len() + 1, num_outputs, sats_per_byte);
        let total_cost = fee + required_btc_amount;
        let updated_inputs = {
            let mut v = inputs.clone();
            v.push(utxo_and_value); // FIXME - can we make more efficient?
            v
        };
        let total_utxo_value = updated_inputs
            .iter()
            .fold(0, |acc, utxo_and_value| acc + utxo_and_value.value);
        debug!(
            "✔ Calculated fee for {} input(s) & {} output(s): {} Sats",
            updated_inputs.len(),
            num_outputs,
            fee
        );
        debug!("✔ Fee + required BTC value of tx: {} Satoshis", total_cost);
        debug!("✔ Current total UTXO value: {} Satoshis", total_utxo_value);
        match total_cost > total_utxo_value {
            true => {
                trace!("✔ UTXOs do not cover fee + amount, need another!");
                get_enough_utxos_to_cover_total(db, required_btc_amount, num_outputs, sats_per_byte, updated_inputs)
            },
            false => {
                trace!("✔ UTXO(s) covers fee and required btc amount!");
                Ok(updated_inputs)
            },
        }
    })
}

fn create_btc_tx_from_redeem_infos<D>(
    db: &D,
    sats_per_byte: u64,
    btc_network: BtcNetwork,
    redeem_infos: &BtcOnEthRedeemInfos,
) -> Result<BtcTransaction>
where
    D: DatabaseInterface,
{
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
