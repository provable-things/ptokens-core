use crate::{chains::evm::eth_database_utils::put_eth_account_nonce_in_db, traits::DatabaseInterface, types::Result};

pub fn increment_evm_account_nonce<D: DatabaseInterface>(
    db: &D,
    current_nonce: u64,
    num_signatures: u64,
) -> Result<()> {
    let new_nonce = num_signatures + current_nonce;
    info!(
        "✔ Incrementing EVM account nonce by {} from {} to {}",
        num_signatures, current_nonce, new_nonce
    );
    put_eth_account_nonce_in_db(db, new_nonce)
}
