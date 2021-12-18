use ethereum_types::H256 as KeccakHash;
use rand::{thread_rng, RngCore};
use secp256k1::key::SecretKey;
use tiny_keccak::{Hasher, Keccak};

use crate::types::{Byte, Result};

pub fn keccak_hash_bytes(bytes: &[Byte]) -> KeccakHash {
    let mut keccak = Keccak::v256();
    let mut hashed = [0u8; 32];
    keccak.update(bytes);
    keccak.finalize(&mut hashed);
    KeccakHash::from(hashed)
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

    #[test]
    fn should_generate_32_random_bytes() {
        let result = get_32_random_bytes_arr();
        assert_eq!(result.len(), 32);
    }

    #[test]
    fn should_generate_x_random_bytes() {
        let x: usize = 100;
        let result = get_x_random_bytes(x);
        assert_eq!(result.len(), x);
    }

    #[test]
    fn should_generate_random_private_key() {
        generate_random_private_key().unwrap();
    }

    #[test]
    fn should_keccak_hash_bytes() {
        let bytes = vec![0xc0, 0xff, 0xee];
        let result = keccak_hash_bytes(&bytes);
        let expected_result = KeccakHash::from_slice(
            &hex::decode("7924f890e12acdf516d6278e342cd34550e3bafe0a3dec1b9c2c3e991733711a").unwrap(),
        );
        assert_eq!(result, expected_result);
    }
}
