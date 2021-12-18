use std::{fmt, io, str::FromStr};

use bitcoin::util::base58;
use secp256k1::{self, key::PublicKey, Error::InvalidPublicKey, Secp256k1};

use crate::{
    chains::eos::{
        eos_constants::{PUBLIC_KEY_CHECKSUM_SIZE, PUBLIC_KEY_SIZE, PUBLIC_KEY_WITH_CHECKSUM_SIZE},
        eos_crypto::eos_signature::EosSignature,
        eos_hash::ripemd160,
    },
    errors::AppError,
    types::{Byte, Bytes, Result},
};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct EosPublicKey {
    pub compressed: bool,
    pub public_key: PublicKey,
}

impl EosPublicKey {
    pub fn write_into<W: io::Write>(&self, mut writer: W) {
        writer.write_all(&self.public_key.serialize()).ok();
    }

    pub fn to_bytes(self) -> Bytes {
        let mut bytes = Vec::new();
        self.write_into(&mut bytes);
        bytes
    }

    pub fn to_eos_format(self) -> String {
        let h160 = ripemd160(&self.public_key.serialize());
        let mut public_key: [u8; PUBLIC_KEY_WITH_CHECKSUM_SIZE] = [0u8; PUBLIC_KEY_WITH_CHECKSUM_SIZE];
        public_key[..PUBLIC_KEY_SIZE].copy_from_slice(self.to_bytes().as_ref());
        public_key[PUBLIC_KEY_SIZE..].copy_from_slice(&h160.take()[..PUBLIC_KEY_CHECKSUM_SIZE]);
        format!("EOS{}", base58::encode_slice(&public_key))
    }

    pub fn from_bytes(data: &[Byte]) -> Result<EosPublicKey> {
        let compressed: bool = match data.len() {
            33 => true,
            64 => false,
            len => return Err(AppError::Base58Error(base58::Error::InvalidLength(len))),
        };
        Ok(EosPublicKey {
            compressed,
            public_key: PublicKey::from_slice(data)?,
        })
    }

    pub fn recover_from_digest(
        digest: &secp256k1::Message,
        recoverable_signature: &EosSignature,
    ) -> Result<EosPublicKey> {
        Self::from_bytes(&Secp256k1::new().recover(digest, &recoverable_signature.0)?.serialize())
    }
}

impl fmt::Display for EosPublicKey {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.compressed {
            write!(f, "{}", self.to_eos_format())?;
        } else {
            for ch in &self.public_key.serialize()[..] {
                write!(f, "{:02x}", ch)?;
            }
        }
        Ok(())
    }
}

impl FromStr for EosPublicKey {
    type Err = AppError;

    fn from_str(s: &str) -> Result<EosPublicKey> {
        if !s.starts_with("EOS") {
            return Err(AppError::CryptoError(InvalidPublicKey));
        }
        let s_hex = base58::from(&s[3..])?;
        let raw = &s_hex[..PUBLIC_KEY_SIZE];
        let _checksum = &s_hex[PUBLIC_KEY_SIZE..];
        let public_key = secp256k1::key::PublicKey::from_slice(raw)?;
        Ok(EosPublicKey {
            public_key,
            compressed: true,
        })
    }
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use bitcoin::hashes::{sha256, Hash};
    use secp256k1::Message;

    use super::*;
    use crate::{
        chains::eos::{
            eos_crypto::eos_signature::EosSignature,
            eos_test_utils::{
                get_sample_eos_private_key,
                get_sample_eos_public_key,
                get_sample_eos_public_key_bytes,
                get_sample_eos_public_key_str,
                get_sample_eos_signature,
                sha256_hash_message_bytes,
            },
        },
        test_utils::get_sample_message_to_sign_bytes,
    };

    impl EosPublicKey {
        pub fn verify_signature(&self, message_slice: &[u8], signature: &EosSignature) -> Result<()> {
            self.verify_hash(&sha256::Hash::hash(&message_slice), &signature)
        }

        pub fn verify_hash(&self, hash: &[u8], signature: &EosSignature) -> Result<()> {
            match Secp256k1::new().verify(
                &Message::from_slice(&hash)?,
                &signature.0.to_standard(),
                &self.public_key,
            ) {
                Ok(()) => Ok(()),
                Err(err) => Err(err.into()),
            }
        }
    }

    #[test]
    fn should_get_public_key_from_string() {
        let public_key_string = get_sample_eos_public_key_str();
        let result = EosPublicKey::from_str(public_key_string).unwrap().to_string();
        assert_eq!(result, public_key_string);
    }

    #[test]
    fn should_error_getting_public_key_from_invalid_str() {
        let invalid_str = "not-a-valid-public-key";
        match EosPublicKey::from_str(invalid_str) {
            Err(AppError::CryptoError(e)) => assert_eq!(e, InvalidPublicKey),
            Ok(_) => panic!("SHould not have succeeded!"),
            Err(e) => panic!("Wrong error received: {}", e),
        }
    }

    #[test]
    fn should_verify_good_signature() {
        let signature = get_sample_eos_signature();
        let public_key = get_sample_eos_public_key();
        if let Err(e) = public_key.verify_signature(&get_sample_message_to_sign_bytes(), &signature) {
            panic!("Should verify good signature!\n{}", e)
        }
    }

    #[test]
    fn should_fail_to_verify_signature_with_incorrect_message() {
        let wrong_message_bytes = vec![0xc0, 0xff, 0xee];
        assert!(wrong_message_bytes != get_sample_message_to_sign_bytes());
        let public_key = get_sample_eos_public_key();
        let signature = get_sample_eos_signature();
        if let Err(e) = public_key.verify_signature(get_sample_message_to_sign_bytes(), &signature) {
            panic!("Should verify good signature!\n{}", e)
        }
        match public_key.verify_signature(&wrong_message_bytes, &signature) {
            Err(AppError::CryptoError(e)) => assert_eq!(e, secp256k1::Error::IncorrectSignature),
            Ok(_) => panic!("Should not verify wrong message signature!"),
            Err(e) => panic!("Wrong error received: {}", e),
        }
    }

    #[test]
    fn should_fail_to_verify_incorrect_signature() {
        let message = "Provable pEOS Token!";
        let message_bytes = message.as_bytes();
        let public_key = get_sample_eos_public_key();
        let incorrect_signature =
            "SIG_K1_KXBtTkGyMHkMCjNzephUVGwGGjGyrQjRg9fiLhqFAZvVCgNMGN9gvmnawM86zKzVvB5yVKiT4NYnaNGxi77m6CvGfjudnT";
        let signature = EosSignature::from_str(incorrect_signature).unwrap();
        match public_key.verify_signature(message_bytes, &signature) {
            Err(AppError::CryptoError(e)) => assert_eq!(e, secp256k1::Error::IncorrectSignature),
            Ok(_) => panic!("Should not verify bad signature!"),
            Err(e) => panic!("Wrong error received: {}", e),
        }
    }

    #[test]
    fn should_sha256_hash_message_correctly() {
        let message = vec![0xc0, 0xff, 0xee];
        let expected_result_hash = "c47a10dc272b1221f0380a2ae0f7d7fa830b3e378f2f5309bbf13f61ad211913";
        let expected_result_slice = hex::decode(expected_result_hash).unwrap();
        let expected_result = Message::from_slice(&expected_result_slice).unwrap();
        let result = sha256_hash_message_bytes(&message).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_recover_eos_public_key_from_hashed_message_and_signature() {
        let message_bytes = vec![0xc0, 0xff, 0xee];
        let hashed_message = sha256_hash_message_bytes(&message_bytes).unwrap();
        let private_key = get_sample_eos_private_key();
        let public_key = get_sample_eos_public_key();
        let signature = private_key.sign_message_bytes(&message_bytes).unwrap();
        let result = EosPublicKey::recover_from_digest(&hashed_message, &signature).unwrap();
        assert_eq!(result, public_key);
    }

    #[test]
    fn should_convert_public_key_to_bytes_correctly() {
        let expected_result = get_sample_eos_public_key_bytes();
        let public_key = get_sample_eos_public_key();
        let result = public_key.to_bytes();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_public_key_from_bytes_correctly() {
        let result = EosPublicKey::from_bytes(&get_sample_eos_public_key_bytes()).unwrap();
        let expected_result = get_sample_eos_public_key();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_eos_public_key_to_eos_format() {
        let expected_result = get_sample_eos_public_key_str();
        let public_key = get_sample_eos_public_key();
        let result = public_key.to_eos_format();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_perform_bytes_roundtrip_correctly() {
        let key = get_sample_eos_public_key();
        let bytes = key.to_bytes();
        let result = EosPublicKey::from_bytes(&bytes).unwrap();
        assert_eq!(key, result);
    }
}
