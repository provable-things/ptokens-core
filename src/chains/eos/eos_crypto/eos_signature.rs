use std::{
    fmt,
    str::FromStr,
};
use crate::{
    base58,
    types::Result,
    errors::AppError,
    chains::eos::eos_hash::ripemd160,
};
use secp256k1::{
    recovery::{
        RecoveryId,
        RecoverableSignature,
    },
};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct EosSignature(pub RecoverableSignature);

impl From<RecoverableSignature> for EosSignature {
    fn from(recv_sig: RecoverableSignature) -> EosSignature {
        EosSignature(recv_sig)
    }
}

impl FromStr for EosSignature {
    type Err = AppError;

    fn from_str(string: &str) -> Result<EosSignature> {
        if !string.starts_with("SIG_K1_") {
            return Err(AppError::CryptoError(
                secp256k1::Error::InvalidSignature
            ));
        }
        let string_hex = base58::from(&string[7..])?;
        let recid = match RecoveryId::from_i32(
            (string_hex[0] - 4 - 27) as i32
        ) {
            Ok(recid) => recid,
            Err(err) => return Err(err.into()),
        };
        let data = &string_hex[1..65];
        let _checksum = &string_hex[65..];
        let rec_sig = match RecoverableSignature::from_compact(
            &data,
            recid
        ) {
            Err(err) => return Err(err.into()),
            Ok(rec_sig) => rec_sig,
        };
        Ok(EosSignature(rec_sig))
    }
}

impl fmt::Display for EosSignature {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let (recovery_id, sig) = self.0.serialize_compact();
        let mut checksum_data: [u8; 67] = [0u8; 67];
        checksum_data[0] = recovery_id.to_i32() as u8 + 27 + 4;
        checksum_data[1..65].copy_from_slice(&sig[..]);
        checksum_data[65..].copy_from_slice(b"K1");
        let checksum_h160 = ripemd160(&checksum_data);
        let checksum = &checksum_h160[..4];
        let mut sig_slice: [u8; 69] = [0u8; 69];
        sig_slice[..65].copy_from_slice(&checksum_data[..65]);
        sig_slice[65..].copy_from_slice(&checksum[..]);
        write!(f, "SIG_K1_{}", base58::encode_slice(&sig_slice))?;
        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use std::str::FromStr;

    #[test]
    fn should_get_get_signature_from_string_with_prefix() {
        let signature = "SIG_K1_KBJgSuRYtHZcrWThugi4ygFabto756zuQQo8XeEpyRtBXLb9kbJtNW3xDcS14Rc14E8iHqLrdx46nenG5T7R4426Bspyzk";
        if let Err(e) = EosSignature::from_str(signature) {
            panic!("Should not error converting string to signature! {}", e)
        }
    }

    #[test]
    fn should_error_gettin_signature_from_string_without_prefix() {
        let signature = "KomV6FEHKdtZxGDwhwSubEAcJ7VhtUQpEt5P6iDz33ic936aSXx87B2L56C8JLQkqNpp1W8ZXjrKiLHUEB4LCGeXvbtVuR";
        if EosSignature::from_str(signature).is_ok() {
            panic!("Should error converting string w/out prefix to sig!")
        }
    }
}
