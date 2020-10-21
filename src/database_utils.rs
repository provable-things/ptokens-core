use crate::{
    traits::DatabaseInterface,
    types::{Byte, Result},
};

pub fn put_string_in_db<D>(db: &D, key: &[Byte], string: &str) -> Result<()> where D: DatabaseInterface {
    debug!("✔ Putting `string` of {} in db under key {}", string, hex::encode(key));
    db.put(key.to_vec(), string.as_bytes().to_vec(), None)
}

pub fn get_string_from_db<D>(db: &D, key: &[Byte]) -> Result<String> where D: DatabaseInterface {
    debug!("✔ Getting `string` from db under key: {}", hex::encode(key));
    db.get(key.to_vec(), None).map(|bytes| bytes.iter().map(|byte| *byte as char).collect::<String>())
}

pub fn put_u64_in_db<D>(db: &D, key: &[Byte], u_64: u64) -> Result<()> where D: DatabaseInterface {
    trace!("✔ Putting `u64` of {} in db...", u_64);
    db.put(key.to_vec(), u_64.to_le_bytes().to_vec(), None)
}

pub fn get_u64_from_db<D>(db: &D, key: &[Byte]) -> Result<u64> where D: DatabaseInterface {
    trace!("✔ Getting `u64` from db...");
    db.get(key.to_vec(), None)
        .and_then(|bytes|
            match bytes.len() <= 8 {
                true => {
                    let mut array = [0; 8];
                    let bytes = &bytes[..array.len()];
                    array.copy_from_slice(bytes);
                    Ok(u64::from_le_bytes(array))
                },
                false => Err("✘ Too many bytes to convert to u64!".into())
            }
        )
}
