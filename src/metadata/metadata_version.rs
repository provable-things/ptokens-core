#[cfg(test)]
use strum::IntoEnumIterator;
use strum_macros::EnumIter;

#[cfg(test)]
use crate::types::Result;
use crate::types::{Byte, Bytes};

#[derive(Clone, Debug, PartialEq, Eq, EnumIter)]
pub enum MetadataVersion {
    V1,
}

impl MetadataVersion {
    pub fn to_byte(&self) -> Byte {
        match self {
            Self::V1 => 0x01,
        }
    }

    pub fn to_bytes(&self) -> Bytes {
        vec![self.to_byte()]
    }

    #[cfg(test)]
    pub fn from_byte(byte: &Byte) -> Result<Self> {
        match byte {
            1u8 => Ok(Self::V1),
            _ => Err(format!("✘ Unrecognized version byte for `MetadataVersion`: {:?}", byte).into()),
        }
    }

    #[cfg(test)]
    pub fn from_bytes(bytes: &[Byte]) -> Result<Self> {
        if bytes.is_empty() {
            Err("Not enough bytes to get `MetadataVersion` from bytes!".into())
        } else {
            Self::from_byte(&bytes[0])
        }
    }

    #[cfg(test)]
    fn get_all() -> Vec<Self> {
        Self::iter().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_make_metadata_version_bytes_roundtrip() {
        MetadataVersion::get_all().iter().for_each(|id| {
            let byte = id.to_byte();
            let result = MetadataVersion::from_byte(&byte).unwrap();
            assert_eq!(&result, id);
        });
    }

    #[test]
    fn should_get_metadata_versiokn_from_bytes() {
        let bytes = vec![0x01, 0xc0, 0xff, 0xee];
        let result = MetadataVersion::from_bytes(&bytes).unwrap();
        assert_eq!(result, MetadataVersion::V1);
    }

    #[test]
    fn should_err_when_getting_version_from_too_few_bytes() {
        let too_few_bytes = vec![];
        let result = MetadataVersion::from_bytes(&too_few_bytes);
        assert!(result.is_err());
    }
}
