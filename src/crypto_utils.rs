use crate::types::Result;
use secp256k1::key::SecretKey;
use rand::{
    RngCore,
    thread_rng,
};

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
        generate_random_private_key()
            .unwrap();
    }
}
