use crate::{chains::btc::btc_state::BtcState, traits::DatabaseInterface, types::Result};

pub fn set_any_sender_flag_in_state<D: DatabaseInterface>(state: BtcState<D>) -> Result<BtcState<D>> {
    info!("✔ Setting `AnySender` flag in BTC state...");
    let any_sender = state.get_btc_submission_json()?.any_sender;
    state.add_any_sender_flag(any_sender)
}
