use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eos::btc::btc_state::BtcState,
    chains::eos::eos_database_utils::{
        put_eos_account_nonce_in_db,
        get_eos_account_nonce_from_db,
    },
};

fn increment_signature_nonce<D>(
    db: &D,
    current_nonce: u64,
    num_signatures: u64,
) -> Result<()>
    where D: DatabaseInterface
{
    debug!(
        "✔ Incrementing signature nonce from {} to {}",
        current_nonce,
        num_signatures
    );
    put_eos_account_nonce_in_db(db, current_nonce + num_signatures)
}

pub fn maybe_increment_signature_nonce<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    let num_txs = &state.signed_txs.len();
    match num_txs {
        0 => {
            info!("✔ No signatures in state ∴ not incrementing nonce");
            Ok(state)
        }
        _ => {
            increment_signature_nonce(
                &state.db,
                get_eos_account_nonce_from_db(&state.db)?,
                *num_txs as u64
            )
                .map(|_| state)
        }
    }
}
