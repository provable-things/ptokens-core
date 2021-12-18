use derive_more::{Constructor, Deref};
use eos_chain::{NumBytes, Read, Write};
use serde::{Deserialize, Serialize};

#[derive(
    Read, Write, Deserialize, Serialize, NumBytes, PartialEq, Eq, PartialOrd, Ord, Debug, Clone, Hash, Default,
)]
#[eosio_core_root_path = "eos_chain"]
pub struct EosExtension(pub u16, pub Vec<u8>);

impl EosExtension {
    pub fn from_hex(hex: &str) -> crate::Result<EosExtension> {
        let bytes = hex::decode(hex)?;
        let mut array = [0; 2];
        let u16_bytes = &bytes[..array.len()];
        array.copy_from_slice(u16_bytes);
        let u_16 = u16::from_le_bytes(array);
        Ok(Self(u_16, bytes[2..].to_vec()))
    }
}

impl core::fmt::Display for EosExtension {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "{}, {}", self.0, hex::encode(&self.1))
    }
}

#[derive(Debug, Deref, Constructor)]
pub struct EosExtensions(pub Vec<EosExtension>);

impl EosExtensions {
    pub fn from_hex_strings(hex_strings: &[String]) -> crate::Result<Self> {
        Ok(Self(
            hex_strings
                .iter()
                .map(|hex| EosExtension::from_hex(hex))
                .collect::<crate::Result<Vec<EosExtension>>>()?,
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_convert_hex_string_to_extension() {
        let hex = "01030307";
        let expected_result = EosExtension(769, vec![3u8, 7u8]);
        let result = EosExtension::from_hex(&hex).unwrap();
        assert_eq!(result, expected_result);
    }
}
