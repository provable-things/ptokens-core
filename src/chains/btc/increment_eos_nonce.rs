use crate::{
    chains::{
        btc::btc_state::BtcState,
        eos::eos_database_utils::{get_eos_account_nonce_from_db, put_eos_account_nonce_in_db},
    },
    traits::DatabaseInterface,
    types::Result,
};

fn increment_eos_nonce<D: DatabaseInterface>(db: &D, current_nonce: u64, num_signatures: u64) -> Result<()> {
    debug!("✔ Incrementing EOS  nonce from {} to {}", current_nonce, num_signatures);
    put_eos_account_nonce_in_db(db, current_nonce + num_signatures)
}

pub fn maybe_increment_eos_nonce<D: DatabaseInterface>(state: BtcState<D>) -> Result<BtcState<D>> {
    let num_txs = &state.signed_txs.len();
    match num_txs {
        0 => {
            info!("✔ No EOS signatures in state ∴ not incrementing nonce");
            Ok(state)
        },
        _ => increment_eos_nonce(&state.db, get_eos_account_nonce_from_db(&state.db)?, *num_txs as u64).and(Ok(state)),
    }
}
