use ethereum_types::H256;
use tiny_keccak::keccak256;
use secp256k1::{
    Message,
    key::SecretKey,
};
use rand::{
    RngCore,
    thread_rng,
};
use bitcoin_hashes::{
    sha256,
    Hash as HashTrait
};
use crate::{
    types::{
        Bytes,
        Result,
        Sha256HashedMessage,
    },
};
pub fn keccak_hash_bytes(bytes: Bytes) -> H256 {
    H256::from(keccak256(&bytes[..]))
}

pub fn sha256_hash_message_bytes(
    message_bytes: &Bytes
) -> Result<Sha256HashedMessage> {
    Ok(Message::from_slice(&sha256::Hash::hash(message_bytes))?)
}

fn get_x_random_bytes(num_bytes: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; num_bytes];
    thread_rng().fill_bytes(&mut bytes);
    bytes
}

fn get_32_random_bytes_arr() -> [u8; 32] {
    let mut arr = [0; 32];
    arr.copy_from_slice(&get_x_random_bytes(32));
    arr
}

pub fn generate_random_private_key() -> Result<SecretKey> {
    Ok(SecretKey::from_slice(&get_32_random_bytes_arr())?)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::utils::convert_hex_to_h256;

    #[test]
    fn should_keccak_hash_bytes() {
        let bytes = vec![0xc0, 0xff, 0xee];
        let result = keccak_hash_bytes(bytes);
        let expected_result_hex =
            "7924f890e12acdf516d6278e342cd34550e3bafe0a3dec1b9c2c3e991733711a"
            .to_string();
        let expected_result = convert_hex_to_h256(expected_result_hex)
            .unwrap();
        assert!(result == expected_result);
    }

    #[test]
    fn should_generate_32_random_bytes() {
        let result = get_32_random_bytes_arr();
        assert!(result.len() == 32);
    }

    #[test]
    fn should_generate_x_random_bytes() {
        let x: usize = 100;
        let result = get_x_random_bytes(x);
        assert!(result.len() == x);
    }

    #[test]
    fn should_generate_random_private_key() {
        generate_random_private_key()
            .unwrap();
    }
}
