use bitcoin_hashes::{sha256, Hash};
use eos_primitives::{Action as EosAction, Checksum256, SerializeData};

use crate::{
    chains::eos::eos_constants::EOS_SCHEDULE_DB_PREFIX,
    types::{Byte, Bytes, Result},
};

pub fn convert_hex_to_checksum256<T: AsRef<[u8]>>(hex: T) -> Result<Checksum256> {
    convert_bytes_to_checksum256(&hex::decode(hex)?)
}

pub fn convert_bytes_to_checksum256(bytes: &[Byte]) -> Result<Checksum256> {
    match bytes.len() {
        32 => {
            let mut arr = [0; 32];
            arr.copy_from_slice(bytes);
            Ok(Checksum256::from(arr))
        },
        _ => Err(format!("✘ Wrong number of bytes. Expected 32, got {}", bytes.len()).into()),
    }
}

pub fn get_eos_schedule_db_key(version: u32) -> Bytes {
    format!("{}{}", EOS_SCHEDULE_DB_PREFIX, version).as_bytes().to_vec()
}

pub fn remove_symbol_from_eos_asset(eos_asset: &str) -> &str {
    eos_asset.split_whitespace().collect::<Vec<&str>>()[0]
}

pub fn get_digest_from_eos_action(action: &EosAction) -> Bytes {
    sha256::Hash::hash(&action.to_serialize_data()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_remove_symbol_from_eos_asset() {
        let amount = "1.23456789";
        let asset = format!("{} SAM", amount);
        let result = remove_symbol_from_eos_asset(&asset);
        assert_eq!(result, amount);
    }
}
