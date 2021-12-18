pub(crate) mod metadata_chain_id;
pub(crate) mod metadata_origin_address;
pub(crate) mod metadata_protocol_id;
pub(crate) mod metadata_traits;
pub(crate) mod metadata_version;
pub(crate) mod test_utils;

use ethabi::{encode as eth_abi_encode, Token as EthAbiToken};
use ethereum_types::Address as EthAddress;

use crate::{
    chains::eos::eos_metadata::EosMetadata,
    metadata::{
        metadata_chain_id::MetadataChainId,
        metadata_origin_address::MetadataOriginAddress,
        metadata_protocol_id::MetadataProtocolId,
        metadata_version::MetadataVersion,
    },
    types::{Byte, Bytes, Result},
};

/// Metadata V1 Specification per @bertani:
/// [
///     uint8 versionByte,
///     bytes userData,
///     bytes4 originProtocol <bytes1 originProtocolId + bytes3 keccak256(originChainId)[:3]>,
///     origin sender
/// ]
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Metadata {
    pub version: MetadataVersion,
    pub user_data: Bytes,
    pub metadata_chain_id: MetadataChainId,
    pub origin_address: MetadataOriginAddress,
}

impl Metadata {
    pub fn new(user_data: &[Byte], origin_address: &MetadataOriginAddress) -> Self {
        Self::new_v1(user_data, origin_address)
    }

    fn new_v1(user_data: &[Byte], origin_address: &MetadataOriginAddress) -> Self {
        Self {
            version: MetadataVersion::V1,
            user_data: user_data.to_vec(),
            origin_address: origin_address.clone(),
            metadata_chain_id: origin_address.metadata_chain_id,
        }
    }

    fn to_bytes_for_eth(&self) -> Result<Bytes> {
        Ok(eth_abi_encode(&[
            EthAbiToken::FixedBytes(self.version.to_bytes()),
            EthAbiToken::Bytes(self.user_data.clone()),
            EthAbiToken::FixedBytes(self.metadata_chain_id.to_bytes()?),
            match self.origin_address.metadata_chain_id.to_protocol_id() {
                MetadataProtocolId::Ethereum => {
                    EthAbiToken::Address(EthAddress::from_slice(&self.origin_address.to_bytes()?))
                },
                MetadataProtocolId::Eos | MetadataProtocolId::Bitcoin => {
                    EthAbiToken::Bytes(self.origin_address.to_bytes()?)
                },
            },
        ]))
    }

    fn to_bytes_for_eos(&self) -> Result<Bytes> {
        EosMetadata::new(
            self.version.to_byte(),
            self.user_data.clone(),
            self.metadata_chain_id.to_bytes()?,
            format!("0x{}", hex::encode(self.origin_address.to_bytes()?)),
        )
        .to_bytes()
    }

    pub fn to_bytes_for_protocol(&self, destination_protocol: &MetadataProtocolId) -> Result<Bytes> {
        match destination_protocol {
            MetadataProtocolId::Eos => self.to_bytes_for_eos(),
            MetadataProtocolId::Ethereum => self.to_bytes_for_eth(),
            MetadataProtocolId::Bitcoin => Err("Encoding metadata for Bitcoin is not implemented!".into()),
        }
    }

    #[cfg(test)]
    fn get_err_msg(field: &str, protocol: &MetadataProtocolId) -> String {
        format!(
            "Error getting `{}` from bytes for {} metadata!",
            field,
            protocol.to_symbol()
        )
    }

    #[cfg(test)]
    fn from_bytes_from_eth(bytes: &[Byte]) -> Result<Self> {
        use ethabi::{decode as eth_abi_decode, ParamType as EthAbiParamType};
        let protocol = MetadataProtocolId::Ethereum;
        let tokens = eth_abi_decode(
            &[
                EthAbiParamType::FixedBytes(1),
                EthAbiParamType::Bytes,
                EthAbiParamType::FixedBytes(4),
                EthAbiParamType::Address,
            ],
            bytes,
        )?;
        let metadata_chain_id = match tokens[2] {
            EthAbiToken::FixedBytes(ref bytes) => MetadataChainId::from_bytes(bytes),
            _ => Err(Self::get_err_msg("metadata_chain_id", &protocol).into()),
        }?;
        let eth_address = match tokens[3] {
            EthAbiToken::Address(address) => Ok(address),
            _ => Err(Self::get_err_msg("eth_address", &protocol)),
        }?;
        let version = match tokens[0] {
            EthAbiToken::FixedBytes(ref bytes) => MetadataVersion::from_bytes(bytes),
            _ => Err(Self::get_err_msg("version", &protocol).into()),
        }?;
        let user_data = match tokens[1] {
            EthAbiToken::Bytes(ref bytes) => Ok(bytes.clone()),
            _ => Err(Self::get_err_msg("user_data", &protocol)),
        }?;
        let origin_address = MetadataOriginAddress::new_from_eth_address(&eth_address, &metadata_chain_id)?;
        Ok(Self {
            version,
            user_data,
            metadata_chain_id,
            origin_address,
        })
    }

    #[cfg(test)]
    fn from_bytes(bytes: &[Byte], protocol: &MetadataProtocolId) -> Result<Self> {
        match protocol {
            MetadataProtocolId::Ethereum => Self::from_bytes_from_eth(bytes),
            MetadataProtocolId::Bitcoin | MetadataProtocolId::Eos => {
                Err("Decoding metadata for Bitcoin || EOS is not implemented!".into())
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::test_utils::get_sample_eth_metadata;

    #[test]
    fn should_make_eth_metadata_bytes_roundtrip() {
        let metadata = get_sample_eth_metadata();
        let bytes = metadata.to_bytes_for_eth().unwrap();
        let expected_bytes = hex::decode("01000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080005fe7f9000000000000000000000000000000000000000000000000000000000000000000000000000000005a0b54d5dc17e0aadc383d2db43b0a0d3e029c4c0000000000000000000000000000000000000000000000000000000000000003c0ffee0000000000000000000000000000000000000000000000000000000000").unwrap();
        assert_eq!(bytes, expected_bytes);
        let protocol_id = MetadataProtocolId::Ethereum;
        let result = Metadata::from_bytes(&bytes, &protocol_id).unwrap();
        assert_eq!(result, metadata);
    }

    #[test]
    fn should_encode_eth_metadata_for_eos() {
        let metadata = get_sample_eth_metadata();
        let bytes = metadata.to_bytes_for_eos().unwrap();
        let hex_encoded_bytes = hex::encode(&bytes);
        let expected_hex_encode_bytes = "0103c0ffee04005fe7f92a307835613062353464356463313765306161646333383364326462343362306130643365303239633463";
        assert_eq!(hex_encoded_bytes, expected_hex_encode_bytes);
    }
}
