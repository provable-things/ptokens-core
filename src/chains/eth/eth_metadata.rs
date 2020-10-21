use std::{
    fmt,
    str,
    str::FromStr,
};
use crate::{
    types::{
        Byte,
        Bytes,
        Result,
    },
    btc_on_eth::btc::btc_types::MintingParamStruct as BtcOnEthMintingParamStruct,
};
use bitcoin::{
    hashes::sha256d,
    util::address::Address as BtcAddress,
};

#[cfg(test)]
use bitcoin::hashes::Hash;
#[cfg(test)]
use crate::errors::AppError;

#[cfg(test)]
pub const MINIMUM_METADATA_BYTES: usize = 33;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum EthMetadataVersion {
    V1,
}

impl EthMetadataVersion {
    pub fn as_byte(&self) -> Byte {
        match self {
            EthMetadataVersion::V1 => 0x01,
        }
    }

    #[cfg(test)]
    pub fn from_byte(byte: &Byte) -> Result<Self> {
        match byte {
            1u8 => Ok(EthMetadataVersion::V1),
            _ => Err(format!("✘ Unrecognized version byte for `EthMetadataVersion`: {:?}", byte).into())
        }

    }
}

impl fmt::Display for EthMetadataVersion {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EthMetadataVersion::V1 => write!(f, "1"),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EthMetadataFromBtc {
    pub version: EthMetadataVersion,
    pub originating_tx_hash: sha256d::Hash,
    pub originating_tx_address: Option<BtcAddress>,
}

impl EthMetadataFromBtc {
    pub fn from_btc_minting_params(
        version: &EthMetadataVersion,
        minting_param_struct: &BtcOnEthMintingParamStruct
    ) -> Self {
        match version {
            EthMetadataVersion::V1 => {
                EthMetadataFromBtc {
                    version: version.clone(),
                    originating_tx_hash: minting_param_struct.originating_tx_hash,
                    originating_tx_address:
                        Self::get_btc_address_from_str(&minting_param_struct.originating_tx_address),
                }
            }
        }
    }

    fn get_version_byte(&self) -> Byte {
        self.version.as_byte()
    }

    fn get_originating_hash_bytes(&self) -> Result<Bytes> {
        Ok(hex::decode(self.originating_tx_hash.to_string())?)
    }

    fn get_originating_address_bytes(&self) -> Result<Bytes> {
        match &self.originating_tx_address {
            None => Ok(vec![]),
            Some(btc_address) => Ok(btc_address.to_string().as_bytes().to_vec())
        }
    }

    fn get_btc_address_from_str(btc_address_str: &str) -> Option<BtcAddress> {
        match BtcAddress::from_str(&btc_address_str) {
            Ok(btc_address) => Some(btc_address),
            Err(err) => {
                info!("✘ Error creating  BTC address from str in `EthMetadataFromBtc`: {}", err);
                None
            }
        }
    }

    #[cfg(test)]
    fn reverse_endianess_of_bytes(bytes: &[Byte]) -> Bytes {
        // Re the endianess switch: https://bitcointalk.org/index.php?topic=5201170.0
        let mut result = bytes.to_vec();
        result.reverse();
        result
    }

    #[cfg(test)]
    fn get_sha_hash_from_bytes(bytes: &[Byte]) -> Result<sha256d::Hash> {
        match sha256d::Hash::from_slice(&Self::reverse_endianess_of_bytes(bytes)) {
            Ok(hash) => Ok(hash),
            Err(err) => Err(format!(
                "✘ Error extracting hash from bytes in `EthMetadataVersion`: {}",
                err
            ).into())
        }
    }

    pub fn serialize(&self) -> Result<Bytes> {
        match self.version {
            EthMetadataVersion::V1 => {
                Ok(
                    vec![
                        vec![self.get_version_byte()],
                        self.get_originating_hash_bytes()?,
                        self.get_originating_address_bytes()?
                    ].concat()
                )
            }
        }
    }

    #[cfg(test)]
    pub fn from_bytes(bytes: &[Byte]) -> Result<Self> {
        let num_bytes = bytes.len();
        if num_bytes < MINIMUM_METADATA_BYTES {
            return Err(format!(
                "✘ Too few bytes to deserialize `EthMetadataFromBtc`! Got {}, need {}!",
                num_bytes,
                MINIMUM_METADATA_BYTES
            ).into())
        }
        let version = EthMetadataVersion::from_byte(&bytes[0])?;
        match version {
            EthMetadataVersion::V1 => Ok(
                EthMetadataFromBtc {
                    version: EthMetadataVersion::from_byte(&bytes[0])?,
                    originating_tx_hash: Self::get_sha_hash_from_bytes(&bytes[1..33])?,
                    originating_tx_address: match str::from_utf8(&bytes[33..]) {
                        Ok(address_string) => Self::get_btc_address_from_str(address_string),
                        Err(err) => {
                            info!("✘ Failed to convert bytes to utf8 when deserializing `EthMetadataFromBtc`: {}", err);
                            None
                        }
                    }
                }
            )
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::hashes::Hash;
    use ethereum_types::Address as EthAddress;
    use crate::{
        chains::btc::btc_constants::MINIMUM_REQUIRED_SATOSHIS,
        btc_on_eth::utils::convert_satoshis_to_ptoken,
    };

    fn get_sample_minting_param_struct() -> BtcOnEthMintingParamStruct {
        let originating_tx_address = "moBSQbHn7N9BC9pdtAMnA7GBiALzNMQJyE".to_string();
        let eth_address = EthAddress::from_str(&"fEDFe2616EB3661CB8FEd2782F5F0cC91D59DCaC").unwrap();
        let amount = convert_satoshis_to_ptoken(MINIMUM_REQUIRED_SATOSHIS);
        let originating_tx_hash = sha256d::Hash::hash(b"something to hash");
        BtcOnEthMintingParamStruct { amount, eth_address, originating_tx_hash, originating_tx_address }
    }

    fn get_sample_v1_metadata() -> EthMetadataFromBtc {
        EthMetadataFromBtc::from_btc_minting_params(&EthMetadataVersion::V1, &get_sample_minting_param_struct())
    }

    fn get_sample_v1_serialized_metadata() -> Bytes {
        get_sample_v1_metadata().serialize().unwrap()
    }

    #[test]
    fn should_get_metadata_v1_byte() {
        let expected_result = 0x01;
        let metadata_version = EthMetadataVersion::V1;
        let result = metadata_version.as_byte();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_fail_to_get_metadata_version_correctly() {
        let byte = 255u8;
        let expected_error = format!("✘ Unrecognized version byte for `EthMetadataVersion`: {:?}", byte);
        match EthMetadataVersion::from_byte(&byte) {
            Err(AppError::Custom(err)) => assert_eq!(err, expected_error),
            Err(err) => panic!("Wrong error received: {}", err),
            Ok(_) => panic!("Should not have succeeded!"),
        }
    }

    #[test]
    fn should_get_metadata_version_from_byte() {
        let byte = 1u8;
        let expected_result = EthMetadataVersion::V1;
        let result = EthMetadataVersion::from_byte(&byte).unwrap();
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_get_eth_metadata_v1_from_btc_minting_params() {
        let btc_minting_params = get_sample_minting_param_struct();
        let version = EthMetadataVersion::V1;
        let result = EthMetadataFromBtc::from_btc_minting_params(&version, &btc_minting_params);
        assert_eq!(version, result.version);
        assert_eq!(btc_minting_params.originating_tx_hash, result.originating_tx_hash);
        assert!(result.originating_tx_address.is_some());
        assert_eq!(btc_minting_params.originating_tx_address, result.originating_tx_address.unwrap().to_string());
    }

    #[test]
    fn should_serialize_v1_metadata() {
        let expected_result = get_sample_v1_serialized_metadata();
        let metadata = get_sample_v1_metadata();
        let result = metadata.serialize().unwrap();
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_fail_to_deserialize_v1_metadata_if_too_few_bytes() {
        let bytes = vec![0u8, 1u8];
        let expected_error = format!(
            "✘ Too few bytes to deserialize `EthMetadataFromBtc`! Got {}, need {}!",
            bytes.len(),
            MINIMUM_METADATA_BYTES,
        );
        assert!(bytes.len() < MINIMUM_METADATA_BYTES);
        match EthMetadataFromBtc::from_bytes(&bytes) {
            Err(AppError::Custom(err)) => assert_eq!(err, expected_error),
            Err(err) => panic!("Wrong error received: {}", err),
            Ok(_) => panic!("Should not have succeeded!"),
        }
    }

    #[test]
    fn should_deserialize_eth_metadata_v1_correctly() {
        let serialized = get_sample_v1_serialized_metadata();
        let expected_result = get_sample_v1_metadata();
        let result = EthMetadataFromBtc::from_bytes(&serialized).unwrap();
        assert_eq!(result, expected_result);
    }
}
