use std::fmt;

use ethereum_types::H256;
use secp256k1::{
    key::{PublicKey, SecretKey, ONE_KEY},
    Message,
    Secp256k1,
};

use crate::{
    chains::eth::{
        eth_constants::{ETH_MESSAGE_PREFIX, PREFIXED_MESSAGE_HASH_LEN},
        eth_crypto::eth_public_key::EthPublicKey,
        eth_crypto_utils::set_eth_signature_recovery_param,
        eth_traits::EthSigningCapabilities,
        eth_types::EthSignature,
    },
    constants::PRIVATE_KEY_DATA_SENSITIVITY_LEVEL,
    crypto_utils::{generate_random_private_key, keccak_hash_bytes},
    traits::DatabaseInterface,
    types::{Byte, Result},
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthPrivateKey(SecretKey);

impl EthPrivateKey {
    pub fn from_slice(slice: &[Byte]) -> Result<Self> {
        Ok(Self(SecretKey::from_slice(slice)?))
    }

    pub fn generate_random() -> Result<Self> {
        Ok(Self(generate_random_private_key()?))
    }

    pub fn to_public_key(&self) -> EthPublicKey {
        EthPublicKey {
            compressed: true,
            public_key: PublicKey::from_secret_key(&Secp256k1::new(), &self.0),
        }
    }

    pub fn write_to_database<D>(&self, db: &D, key: &[Byte]) -> Result<()>
    where
        D: DatabaseInterface,
    {
        db.put(key.to_vec(), self.0[..].to_vec(), PRIVATE_KEY_DATA_SENSITIVITY_LEVEL)
    }
}

impl EthSigningCapabilities for EthPrivateKey {
    fn sign_hash(&self, hash: H256) -> Result<EthSignature> {
        let msg = match Message::from_slice(hash.as_bytes()) {
            Ok(msg) => msg,
            Err(err) => return Err(err.into()),
        };
        let sig = Secp256k1::sign_recoverable(&Secp256k1::new(), &msg, &self.0);
        let (rec_id, data) = sig.serialize_compact();
        let mut data_arr = [0; 65];
        data_arr[0..64].copy_from_slice(&data[0..64]);
        data_arr[64] = rec_id.to_i32() as u8;
        Ok(data_arr)
    }

    fn sign_message_bytes(&self, message: &[Byte]) -> Result<EthSignature> {
        self.sign_hash(keccak_hash_bytes(message))
    }

    fn sign_eth_prefixed_msg_bytes(&self, message: &[Byte]) -> Result<EthSignature> {
        let message_hash = keccak_hash_bytes(message);
        let message_bytes = [
            ETH_MESSAGE_PREFIX,
            PREFIXED_MESSAGE_HASH_LEN.as_ref(),
            message_hash.as_bytes(),
        ]
        .concat();
        let mut signature = self.sign_message_bytes(&message_bytes)?;
        set_eth_signature_recovery_param(&mut signature);
        Ok(signature)
    }
}

impl fmt::Display for EthPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "✘ Cannot print ETH private key!")
    }
}

impl Drop for EthPrivateKey {
    fn drop(&mut self) {
        unsafe { ::std::ptr::write_volatile(&mut self.0, ONE_KEY) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::eth::eth_test_utils::{get_sample_eth_private_key, get_sample_eth_private_key_slice};

    #[test]
    fn should_create_random_eth_private_key() {
        if let Err(e) = EthPrivateKey::generate_random() {
            panic!("Error generating random eth private key: {}", e);
        }
    }

    #[test]
    fn should_create_eth_private_key_from_slice() {
        if let Err(e) = EthPrivateKey::from_slice(&get_sample_eth_private_key_slice()) {
            panic!("Error generating eth private key from slice: {}", e);
        }
    }

    #[test]
    fn should_sign_message_bytes() {
        let key = get_sample_eth_private_key();
        let message_bytes = vec![0xc0, 0xff, 0xee];
        if let Err(e) = key.sign_message_bytes(&message_bytes) {
            panic!("Error signing message bytes: {}", e);
        }
    }

    #[test]
    fn should_sign_message_hash() {
        let key = get_sample_eth_private_key();
        let message_bytes = vec![0xc0, 0xff, 0xee];
        let message_hash = keccak_hash_bytes(&message_bytes);
        if let Err(e) = key.sign_hash(message_hash) {
            panic!("Error signing message hash: {}", e);
        }
    }

    #[test]
    fn should_sign_eth_prefixed_msg_bytes() {
        let key = get_sample_eth_private_key();
        let message = "Arbitrary message";
        if let Err(e) = key.sign_eth_prefixed_msg_bytes(message.as_bytes()) {
            panic!("Error signing eth prefixed message bytes: {}", e);
        }
    }

    #[test]
    fn should_sign_eth_prefixed_msg_bytes_recoverable_with_solidity() {
        let eth_private_key = EthPrivateKey::from_slice(&[
            132, 23, 52, 203, 67, 154, 240, 53, 117, 195, 124, 41, 179, 50, 97, 159, 61, 169, 234, 47, 186, 237, 88,
            161, 200, 177, 24, 142, 207, 242, 168, 221,
        ])
        .unwrap();
        let message_bytes = vec![
            0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 83, 194, 4, 141, 173, 79, 207, 171, 68, 195, 239, 61, 22, 232, 130,
            181, 23, 141, 244, 43, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0, 0, 5, 57, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
            0,
        ];

        let expected_result = "9bc417b0f16a9d9f5d216d8bceb74da26cf2ab1fd4f98db4ca86d9ef54f2580671f22b8801d7cdb63bf2036d91d5a620de08fb8f07d7368052ed1f6307b0f7271b";
        let result = hex::encode(
            eth_private_key
                .sign_eth_prefixed_msg_bytes(&message_bytes)
                .unwrap()
                .to_vec(),
        );

        assert_eq!(expected_result, result);
    }

    #[test]
    fn should_get_public_key_from_private() {
        let expected_result = hex::decode(
            "04d95149f2ea3a078523d28fb8fb0d589f8a8c8e90d9688a9bdcbcd97f43e157a74ec521b7fd317e4a02bd81ed5822d6ff93ea78d529cd2a7c2d196ec992d00754"
        ).unwrap();
        let private_key = get_sample_eth_private_key();
        let result = private_key.to_public_key().to_bytes();
        assert_eq!(result, expected_result);
    }
}
