use bitcoin::network::constants::Network as BtcNetwork;

use crate::{
    chains::btc::{
        btc_database_utils::{
            put_btc_account_nonce_in_db,
            put_btc_canon_to_tip_length_in_db,
            put_btc_difficulty_in_db,
            put_btc_fee_in_db,
            put_btc_network_in_db,
            put_btc_tail_block_hash_in_db,
        },
        btc_state::BtcState,
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn put_btc_tail_block_hash_in_db_and_return_state<D>(state: BtcState<D>) -> Result<BtcState<D>>
where
    D: DatabaseInterface,
{
    trace!("✔ Putting BTC tail block hash in db...");
    put_btc_tail_block_hash_in_db(&state.db, &state.get_btc_block_and_id()?.id).and(Ok(state))
}

pub fn put_btc_account_nonce_in_db_and_return_state<D: DatabaseInterface>(state: BtcState<D>) -> Result<BtcState<D>> {
    trace!("✔ Putting BTC account nonce of 0 in db...");
    put_btc_account_nonce_in_db(&state.db, 0).and(Ok(state))
}

pub fn put_canon_to_tip_length_in_db_and_return_state<D>(
    canon_to_tip_length: u64,
    state: BtcState<D>,
) -> Result<BtcState<D>>
where
    D: DatabaseInterface,
{
    put_btc_canon_to_tip_length_in_db(&state.db, canon_to_tip_length).and(Ok(state))
}

pub fn get_btc_network_from_arg(network_arg: &str) -> BtcNetwork {
    match network_arg {
        "Testnet" => {
            trace!("✔ Using 'TESTNET' for bitcoin network!");
            BtcNetwork::Testnet
        },
        _ => {
            trace!("✔ Using 'BITCOIN' for bitcoin network!");
            BtcNetwork::Bitcoin
        },
    }
}

pub fn put_difficulty_threshold_in_db<D>(difficulty: u64, state: BtcState<D>) -> Result<BtcState<D>>
where
    D: DatabaseInterface,
{
    put_btc_difficulty_in_db(&state.db, difficulty).and(Ok(state))
}

pub fn put_btc_network_in_db_and_return_state<D: DatabaseInterface>(
    network: &str,
    state: BtcState<D>,
) -> Result<BtcState<D>>
where
    D: DatabaseInterface,
{
    put_btc_network_in_db(&state.db, get_btc_network_from_arg(network)).and(Ok(state))
}

pub fn put_btc_fee_in_db_and_return_state<D: DatabaseInterface>(fee: u64, state: BtcState<D>) -> Result<BtcState<D>> {
    put_btc_fee_in_db(&state.db, fee).and(Ok(state))
}
