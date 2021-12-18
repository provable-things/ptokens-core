use std::{convert::TryFrom, fmt};

use ethereum_types::H256 as KeccakHash;
use strum_macros::EnumIter;

use crate::{
    crypto_utils::keccak_hash_bytes,
    errors::AppError,
    metadata::{metadata_chain_id::MetadataChainId, metadata_traits::ToMetadataChainId},
    traits::ChainId,
    types::{Byte, Bytes, Result},
    utils::convert_bytes_to_u8,
};

#[derive(Clone, Debug, PartialEq, Eq, EnumIter)]
pub enum EthChainId {
    Mainnet,
    Rinkeby,
    Ropsten,
    BscMainnet,
    XDaiMainnet,
    PolygonMainnet,
    Unknown(u8),
}

impl ChainId for EthChainId {
    fn keccak_hash(&self) -> Result<KeccakHash> {
        Ok(keccak_hash_bytes(&self.to_bytes()?))
    }
}

impl ToMetadataChainId for EthChainId {
    fn to_metadata_chain_id(&self) -> MetadataChainId {
        match self {
            Self::Unknown(_) => MetadataChainId::EthUnknown,
            Self::BscMainnet => MetadataChainId::BscMainnet,
            Self::XDaiMainnet => MetadataChainId::XDaiMainnet,
            Self::Mainnet => MetadataChainId::EthereumMainnet,
            Self::Rinkeby => MetadataChainId::EthereumRinkeby,
            Self::Ropsten => MetadataChainId::EthereumRopsten,
            Self::PolygonMainnet => MetadataChainId::PolygonMainnet,
        }
    }
}

impl EthChainId {
    pub fn unknown() -> Self {
        Self::Unknown(0)
    }

    pub fn from_str(s: &str) -> Result<Self> {
        match &*s.to_lowercase() {
            "mainnet" | "1" => Ok(Self::Mainnet),
            "ropsten" | "3" => Ok(Self::Ropsten),
            "rinkeby" | "4" => Ok(Self::Rinkeby),
            "bsc" | "56" => Ok(Self::BscMainnet),
            "xdai" | "100" => Ok(Self::XDaiMainnet),
            "polygon" | "137" => Ok(Self::PolygonMainnet),
            _ => match s.parse::<u8>() {
                Ok(byte) => Ok(Self::Unknown(byte)),
                Err(_) => Err(format!("✘ Unrecognized ETH network: '{}'!", s).into()),
            },
        }
    }

    pub fn to_bytes(&self) -> Result<Bytes> {
        Ok(self.to_u8().to_le_bytes().to_vec())
    }

    pub fn to_byte(&self) -> Byte {
        match self {
            Self::Mainnet => 1,
            Self::Rinkeby => 4,
            Self::Ropsten => 3,
            Self::BscMainnet => 56,
            Self::XDaiMainnet => 100,
            Self::PolygonMainnet => 137,
            Self::Unknown(byte) => *byte,
        }
    }

    pub fn from_bytes(bytes: &[Byte]) -> Result<Self> {
        info!("✔ Getting `EthChainId` from bytes: {}", hex::encode(bytes));
        let byte = convert_bytes_to_u8(bytes)?;
        match byte {
            1 => Ok(Self::Mainnet),
            3 => Ok(Self::Ropsten),
            4 => Ok(Self::Rinkeby),
            56 => Ok(Self::BscMainnet),
            100 => Ok(Self::XDaiMainnet),
            137 => Ok(Self::PolygonMainnet),
            _ => {
                info!("✔ Using unknown ETH chain ID: 0x{}", hex::encode(bytes));
                Ok(Self::Unknown(byte))
            },
        }
    }

    pub fn to_metadata_chain_id(&self) -> MetadataChainId {
        match self {
            Self::Mainnet => MetadataChainId::EthereumMainnet,
            Self::Rinkeby => MetadataChainId::EthereumRinkeby,
            Self::Ropsten => MetadataChainId::EthereumRopsten,
            Self::BscMainnet => MetadataChainId::BscMainnet,
            Self::XDaiMainnet => MetadataChainId::XDaiMainnet,
            Self::PolygonMainnet => MetadataChainId::PolygonMainnet,
            Self::Unknown(_) => MetadataChainId::EthUnknown,
        }
    }

    pub fn to_u8(&self) -> u8 {
        match self {
            Self::Mainnet => 1,
            Self::Ropsten => 3,
            Self::Rinkeby => 4,
            Self::BscMainnet => 56,
            Self::XDaiMainnet => 100,
            Self::PolygonMainnet => 137,
            Self::Unknown(byte) => *byte,
        }
    }

    #[cfg(test)]
    fn is_unknown(&self) -> bool {
        match self {
            Self::Unknown(_) => true,
            _ => false,
        }
    }

    #[cfg(test)]
    fn get_all() -> Vec<Self> {
        use strum::IntoEnumIterator;
        Self::iter().filter(|chain_id| !chain_id.is_unknown()).collect()
    }
}

impl fmt::Display for EthChainId {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Self::Mainnet => write!(f, "ETH Mainnet: {}", self.to_u8()),
            Self::Rinkeby => write!(f, "Rinekby Testnet: {}", self.to_u8()),
            Self::Ropsten => write!(f, "Ropsten Testnet: {}", self.to_u8()),
            Self::BscMainnet => write!(f, "BSC Mainnet: {}", self.to_u8()),
            Self::XDaiMainnet => write!(f, "xDai Mainnet: {}", self.to_u8()),
            Self::PolygonMainnet => write!(f, "Polygon Mainnet: {}", self.to_u8()),
            Self::Unknown(_) => write!(f, "Unkown ETH chain ID: {}", self.to_u8()),
        }
    }
}

impl TryFrom<u8> for EthChainId {
    type Error = AppError;

    fn try_from(byte: u8) -> Result<Self> {
        Self::from_bytes(&[byte])
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_make_u8_roundtrip_for_all_eth_chain_ids() {
        let ids = EthChainId::get_all();
        let bytes = ids.iter().map(|id| id.to_u8()).collect::<Vec<u8>>();
        let result = bytes
            .iter()
            .map(|byte| EthChainId::try_from(*byte))
            .collect::<Result<Vec<EthChainId>>>()
            .unwrap();
        assert_eq!(result, ids);
    }

    #[test]
    fn should_make_bytes_roundtrip_for_all_eth_chain_ids() {
        let ids = EthChainId::get_all();
        let vec_of_bytes = ids
            .iter()
            .map(|id| id.to_bytes())
            .collect::<Result<Vec<Bytes>>>()
            .unwrap();
        let result = vec_of_bytes
            .iter()
            .map(|ref bytes| EthChainId::from_bytes(bytes))
            .collect::<Result<Vec<EthChainId>>>()
            .unwrap();
        assert_eq!(result, ids);
    }
}
