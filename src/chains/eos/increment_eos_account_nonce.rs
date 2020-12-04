use crate::{chains::eos::eos_database_utils::put_eos_account_nonce_in_db, traits::DatabaseInterface, types::Result};

pub fn increment_eos_account_nonce<D>(db: &D, current_nonce: u64, num_signatures: u64) -> Result<()>
where
    D: DatabaseInterface,
{
    let new_nonce = num_signatures + current_nonce;
    info!(
        "✔ Incrementing eos account nonce by {} from {} to {}",
        num_signatures, current_nonce, new_nonce
    );
    put_eos_account_nonce_in_db(db, new_nonce)
}
