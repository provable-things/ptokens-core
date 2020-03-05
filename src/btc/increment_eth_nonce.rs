use crate::{
    types::Result,
    btc::btc_state::BtcState,
    traits::DatabaseInterface,
    eth::eth_database_utils::increment_eth_account_nonce_in_db,
};

pub fn maybe_increment_eth_nonce_in_db<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    match state.get_eth_signed_txs() {
        Err(_) => {
            info!("✔ Not incrementing ETH account nonce - no signatures made!");
            Ok(state)
        }
        Ok(signed_txs) => {
            info!("✔ Incrementing ETH account nonce by {}", signed_txs.len());
            increment_eth_account_nonce_in_db(
                &state.db,
                &(signed_txs.len() as u64),
            )
                .and_then(|_| Ok(state))
        }
    }
}
