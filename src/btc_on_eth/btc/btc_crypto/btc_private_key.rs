use std::fmt;
use bitcoin::{
    util::{
        key::PrivateKey,
        address::Address as BtcAddress,
    },
    network::constants::Network,
};
use secp256k1::{
    Message,
    Secp256k1,
    Signature,
    key::{
        SecretKey,
        PublicKey,
    },
};
use crate::{
    traits::DatabaseInterface,
    chains::btc::btc_utils::get_btc_one_key,
    crypto_utils::generate_random_private_key,
    constants::PRIVATE_KEY_DATA_SENSITIVITY_LEVEL,
    types::{
        Byte,
        Bytes,
        Result,
    },
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BtcPrivateKey(PrivateKey);

impl BtcPrivateKey {
    pub fn to_p2pkh_btc_address(&self) -> String {
        BtcAddress::p2pkh(&self.0.public_key(&Secp256k1::new()), self.0.network)
            .to_string()
    }

    pub fn from_slice(slice: &[u8], network: Network) -> Result<Self> {
        Ok(
            Self(
                PrivateKey {
                    network,
                    compressed: true,
                    key: SecretKey::from_slice(&slice)?
                }
            )
        )
    }

    pub fn generate_random(network: Network) -> Result<Self> {
        Ok(
            Self(
                PrivateKey {
                    network,
                    compressed: false,
                    key: generate_random_private_key()?
                }
            )
        )
    }

    pub fn sign_hash(&self, hash: Bytes) -> Result<Signature> {
        Ok(
            Secp256k1::new()
                .sign(&Message::from_slice(&hash)?, &self.0.key)
        )
    }

    pub fn sign_hash_and_append_btc_hash_type(
        &self,
        hash: Bytes,
        hash_type: u8,
    ) -> Result<Bytes> {
        self.sign_hash(hash)
            .map(|sig| sig.serialize_der().to_vec())
            .map(|mut sig_vec| {
                sig_vec.push(hash_type);
                sig_vec
            })
    }

    pub fn to_public_key(&self) -> PublicKey {
        PublicKey::from_secret_key(
            &Secp256k1::new(),
            &self.0.key
        )
    }

    pub fn to_public_key_slice(&self) -> [u8; 33] {
        self.to_public_key()
            .serialize()
    }

    pub fn write_to_database<D>(
        &self,
        db: &D,
        key: &[Byte],
    ) -> Result<()>
        where D: DatabaseInterface
    {
        db.put(
            key.to_vec(),
            self.0[..].to_vec(),
            PRIVATE_KEY_DATA_SENSITIVITY_LEVEL,
        )
    }

    #[cfg(test)]
    pub fn from_wif(wif: &str) -> Result<Self> {
        let pk = PrivateKey::from_wif(wif)?;
        Ok(
            Self(
                PrivateKey {
                    key: pk.key,
                    network: pk.network,
                    compressed: pk.compressed
                }
            )
        )
    }
}

impl fmt::Display for BtcPrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "✘ Cannot print BTC private key!")
    }
}

impl Drop for BtcPrivateKey {
    fn drop(&mut self) {
        unsafe { ::std::ptr::write_volatile(&mut self.0, get_btc_one_key()) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin_hashes::{
        Hash,
        sha256d,
    };
    use crate::btc_on_eth::btc::btc_test_utils::{
        SAMPLE_BTC_PUBLIC_KEY,
        SAMPLE_TARGET_BTC_ADDRESS,
        get_sample_btc_private_key,
    };

    fn get_sample_btc_private_key_slice() -> [u8; 32] {
        [
            42, 247, 128, 75, 130, 36, 250, 199,
            18, 109, 88, 243, 110, 14, 135, 154,
            181, 44, 141, 200, 227, 90, 199, 116,
            29, 59, 150, 42, 200, 13, 236, 155
        ]
    }

    #[test]
    fn should_generate_random_private_key() {
        let network = Network::Bitcoin;
        if let Err(e) = BtcPrivateKey::generate_random(network) {
            panic!("Error generating random private btc key: {}", e);
        }
    }

    #[test]
    fn should_generate_key_from_slice() {
        let network = Network::Bitcoin;
        let slice = get_sample_btc_private_key_slice();
        if let Err(e) =  BtcPrivateKey::from_slice(&slice, network) {
            panic!("Error generating private btc key from slice: {}", e);
        }
    }

    #[test]
    fn should_get_private_key_from_wif() {
        let wif = "5JYkZjmN7PVMjJUfJWfRFwtuXTGB439XV6faajeHPAM9Z2PT2R3";
        let sk = BtcPrivateKey::from_wif(wif)
            .unwrap();
        assert!(!sk.0.compressed);
        assert_eq!(&sk.0.to_wif(), wif);
        assert_eq!(sk.0.network, Network::Bitcoin);
    }

    #[test]
    fn should_sign_hash() {
        let expected_signature = "304502210092a8d56c768e2e3ea74671609ac2f40b7914ee57806df92476e2721b35648eb30220431f2f28d59dcf666f6c435587afb7aac13cc8197bba54ad6629333a95f11a84";
        let btc_private_key = get_sample_btc_private_key();
        let message_to_sign = b"message to sign";
        let hash = sha256d::Hash::hash(message_to_sign)
            .to_vec();
        let result = btc_private_key
            .sign_hash(hash)
            .unwrap();
        assert_eq!(result.to_string(), expected_signature);
    }

    #[test]
    fn should_sign_hash_and_append_hash_type() {
        let expected_result = "304502210092a8d56c768e2e3ea74671609ac2f40b7914ee57806df92476e2721b35648eb30220431f2f28d59dcf666f6c435587afb7aac13cc8197bba54ad6629333a95f11a8401";
        let btc_private_key = get_sample_btc_private_key();
        let message_to_sign = b"message to sign";
        let hash_type: u8 = 1;
        let hash = sha256d::Hash::hash(message_to_sign)
            .to_vec();
        let result = btc_private_key
            .sign_hash_and_append_btc_hash_type(hash, hash_type)
            .unwrap();
        let result_hex = hex::encode(result);
        assert_eq!(result_hex, expected_result);
    }

    #[test]
    fn should_get_public_key_from_private() {
        let btc_private_key = get_sample_btc_private_key();
        let result = btc_private_key
            .to_public_key();
        assert_eq!(result.to_string(), SAMPLE_BTC_PUBLIC_KEY);
    }

    #[test]
    fn should_get_public_key_slice() {
        let expected_result = vec![
            3, 210, 165, 227, 177, 98, 235, 88,
            15, 226, 206, 2, 60, 213, 224, 221,
            219, 182, 40, 105, 35, 172, 222, 119,
            227, 229, 70, 131, 20, 220, 147, 115,
            247
        ];
        let btc_private_key = get_sample_btc_private_key();
        let result = btc_private_key
            .to_public_key_slice();
        assert_eq!(result.to_vec(), expected_result);
    }

    #[test]
    fn should_convert_private_key_to_p2pkh_address() {
        let pk = get_sample_btc_private_key();
        let result = pk.to_p2pkh_btc_address();
        assert_eq!(result, SAMPLE_TARGET_BTC_ADDRESS);
    }
}
