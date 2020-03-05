use std::fmt;
use ethereum_types::H256;
use secp256k1::{
    Message,
    Secp256k1,
    key::{
        SecretKey,
        PublicKey,
    },
};
use crate::{
    traits::DatabaseInterface,
    constants::PRIVATE_KEY_DATA_SENSITIVITY_LEVEL,
    eth::{
       eth_types::EthSignature,
       eth_crypto::eth_public_key::EthPublicKey,
    },
    types::{
        Bytes,
        Result,
    },
    crypto_utils::{
        keccak_hash_bytes,
        generate_random_private_key,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EthPrivateKey(SecretKey);

impl EthPrivateKey {
    pub fn from_slice(slice: [u8; 32]) -> Result<Self> {
        Ok(Self(SecretKey::from_slice(&slice)?))
    }

    pub fn generate_random() -> Result<Self> {
        Ok(Self(generate_random_private_key()?))
    }

    pub fn sign_hash(&self, hash: H256) -> Result<EthSignature> {
        let msg = match Message::from_slice(hash.as_bytes()) {
            Ok(msg) => msg,
            Err(err) => return Err(err.into()),
        };
        let sig = Secp256k1::sign_recoverable(
            &Secp256k1::new(),
            &msg,
            &self.0
        );
        let (rec_id, data) = sig.serialize_compact();
        let mut data_arr = [0; 65];
        data_arr[0..64].copy_from_slice(&data[0..64]);
        data_arr[64] = rec_id.to_i32() as u8;
        Ok(data_arr)
    }

    pub fn sign_message_bytes(&self, message: Bytes) -> Result<EthSignature> {
        self.sign_hash(keccak_hash_bytes(message))
    }

    pub fn to_public_key(&self) -> EthPublicKey {
        EthPublicKey {
            compressed: true,
            public_key: PublicKey::from_secret_key(
                &Secp256k1::new(),
                &self.0
            )
        }
    }

    pub fn write_to_database<D>(
        &self,
        db: &D,
        key: &Bytes,
    ) -> Result<()>
        where D: DatabaseInterface
    {
        db.put(
            key.to_vec(),
            self.0[..].to_vec(),
            PRIVATE_KEY_DATA_SENSITIVITY_LEVEL,
        )
    }
}

impl fmt::Display for EthPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "✘ Cannot print ETH private key!")
    }
}

impl Drop for EthPrivateKey {
    fn drop(&mut self) {
        unsafe {
            ::std::ptr::write_volatile(
                &mut self.0,
                generate_random_private_key()
                    .expect("Failed to get ETH private key!"),
            )
        };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::eth::eth_test_utils::{
        get_sample_eth_private_key,
        get_sample_eth_private_key_slice,
    };

    #[test]
    fn should_create_random_eth_private_key() {
        if let Err(e) = EthPrivateKey::generate_random() {
            panic!("Error generating random eth private key: {}", e);
        }
    }

    #[test]
    fn should_create_eth_private_key_from_slice() {
        if let Err(e) = EthPrivateKey::from_slice(
            get_sample_eth_private_key_slice()
        ) {
            panic!("Error generating eth private key from slice: {}", e);
        }
    }

    #[test]
    fn should_sign_message_bytes() {
        let key = get_sample_eth_private_key();
        let message_bytes = vec![0xc0, 0xff, 0xee];
        if let Err(e) = key.sign_message_bytes(message_bytes) {
            panic!("Error signing message bytes: {}", e);
        }
    }

    #[test]
    fn should_sign_message_hash() {
        let key = get_sample_eth_private_key();
        let message_bytes = vec![0xc0, 0xff, 0xee];
        let message_hash = keccak_hash_bytes(message_bytes);
        if let Err(e) = key.sign_hash(message_hash) {
            panic!("Error signing message hash: {}", e);
        }
    }

    #[test]
    fn should_get_public_key_from_private() {
        let expected_result = hex::decode(
            "04d95149f2ea3a078523d28fb8fb0d589f8a8c8e90d9688a9bdcbcd97f43e157a74ec521b7fd317e4a02bd81ed5822d6ff93ea78d529cd2a7c2d196ec992d00754"
        ).unwrap();
        let private_key = get_sample_eth_private_key();
        let result = private_key
            .to_public_key()
            .to_bytes();
        assert_eq!(result, expected_result);
    }
}
