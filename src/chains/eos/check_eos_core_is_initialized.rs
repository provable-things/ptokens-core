use crate::{chains::eos::eos_crypto::eos_private_key::EosPrivateKey, traits::DatabaseInterface};

pub fn is_eos_core_initialized<D>(db: &D) -> bool
where
    D: DatabaseInterface,
{
    trace!("✔ Checking if EOS core has been initialized...");
    match EosPrivateKey::get_from_db(db) {
        Ok(_) => {
            trace!("✔ EOS core *HAS* been initialized!");
            true
        },
        _ => {
            trace!("✔ EOS core has *NOT* been initialized!");
            false
        },
    }
}
