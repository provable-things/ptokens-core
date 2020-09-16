use bitcoin::network::constants::Network as BtcNetwork;
use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::btc::{
        btc_state::BtcState,
        btc_database_utils::{
            put_btc_fee_in_db,
            put_btc_network_in_db,
            put_btc_difficulty_in_db,
            put_btc_account_nonce_in_db,
            put_btc_tail_block_hash_in_db,
            put_btc_canon_to_tip_length_in_db,
        },
    },
};

pub fn put_btc_tail_block_hash_in_db_and_return_state<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    trace!("✔ Putting BTC tail block hash in db...");
    put_btc_tail_block_hash_in_db(
        &state.db,
        &state.get_btc_block_and_id()?.id
    )
        .map(|_| state)
}

pub fn put_btc_account_nonce_in_db_and_return_state<D>(
    state: BtcState<D>,
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    trace!("✔ Putting BTC account nonce of 0 in db...");
    put_btc_account_nonce_in_db(&state.db, 0)
        .map(|_| state)
}

pub fn put_canon_to_tip_length_in_db_and_return_state<D>(
    canon_to_tip_length: u64,
    state: BtcState<D>,
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    put_btc_canon_to_tip_length_in_db(&state.db, canon_to_tip_length)
        .map(|_| state)
}

pub fn get_btc_network_from_arg(network_arg: &str) -> BtcNetwork {
    match &network_arg[..] {
        "Testnet" => {
            trace!("✔ Using 'TESTNET' for bitcoin network!");
            BtcNetwork::Testnet
        }
        _ => {
            trace!("✔ Using 'BITCOIN' for bitcoin network!");
            BtcNetwork::Bitcoin
        }
    }
}

pub fn put_difficulty_threshold_in_db<D>(
    difficulty: u64,
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    put_btc_difficulty_in_db(&state.db, difficulty)
        .map(|_| state)
}

pub fn put_btc_network_in_db_and_return_state<D>(
    network: &str,
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    put_btc_network_in_db(&state.db, get_btc_network_from_arg(network))
        .map(|_| state)
}

pub fn put_btc_fee_in_db_and_return_state<D>(
    fee: u64,
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    put_btc_fee_in_db(&state.db, fee)
        .map(|_| state)
}
