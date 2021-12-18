use std::fmt;

use serde::Deserialize;
use strum_macros::EnumIter;

use crate::types::{Byte, Bytes};

#[derive(Clone, Debug, EnumIter, Eq, PartialEq, Deserialize)]
pub enum EthReceiptType {
    Legacy,
    EIP2718,
}

impl EthReceiptType {
    pub fn from_byte(byte: &Byte) -> Self {
        match byte {
            0x00 => Self::Legacy,
            0x02 => Self::EIP2718,
            _ => Self::Legacy,
        }
    }

    pub fn to_byte(&self) -> Byte {
        match self {
            Self::Legacy => 0x00,
            Self::EIP2718 => 0x02,
        }
    }

    pub fn to_bytes(&self) -> Bytes {
        vec![self.to_byte()]
    }

    pub fn is_legacy(&self) -> bool {
        matches!(self, Self::Legacy)
    }
}

impl fmt::Display for EthReceiptType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let s = match self {
            Self::Legacy => "0x0",
            Self::EIP2718 => "0x2",
        };
        write!(f, "{}", s)
    }
}

#[cfg(test)]
mod tests {
    use strum::IntoEnumIterator;

    use super::*;
    use crate::types::Bytes;

    #[test]
    fn should_make_receipt_types_byte_roundtrip() {
        let expected_results = EthReceiptType::iter().collect::<Vec<EthReceiptType>>();
        let bytes = EthReceiptType::iter()
            .map(|receipt_type| receipt_type.to_byte())
            .collect::<Bytes>();
        let results = bytes
            .iter()
            .map(|ref byte| EthReceiptType::from_byte(byte))
            .collect::<Vec<EthReceiptType>>();
        assert_eq!(results, expected_results);
    }

    #[test]
    fn legacy_receipt_type_should_be_legacy() {
        let legacy_receipt_type = EthReceiptType::Legacy;
        let result = legacy_receipt_type.is_legacy();
        assert!(result)
    }

    #[test]
    fn none_legacy_receipt_type_should_not_be_legacy() {
        let legacy_receipt_type = EthReceiptType::EIP2718;
        let result = legacy_receipt_type.is_legacy();
        assert!(!result)
    }
}
