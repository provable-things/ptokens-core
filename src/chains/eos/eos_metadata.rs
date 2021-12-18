use derive_more::Constructor;
use eos_chain::{NumBytes, Read, SerializeData, Write};

use crate::types::{Byte, Bytes};

#[derive(Clone, Debug, Read, Write, NumBytes, PartialEq, Default, Constructor)]
#[eosio_core_root_path = "eos_chain"]
pub struct EosMetadata {
    pub version: Byte,
    pub user_data: Bytes,
    pub metadata_chain_id: Bytes,
    pub origin_address: String,
}

impl SerializeData for EosMetadata {}

impl EosMetadata {
    pub fn to_bytes(&self) -> crate::types::Result<Bytes> {
        Ok(self.to_serialize_data()?)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::metadata::metadata_chain_id::MetadataChainId;

    #[test]
    fn should_serialize_eos_metadata() {
        let metadata = EosMetadata::new(
            1u8,
            vec![0xde, 0xca, 0xff],
            MetadataChainId::EthereumRopsten.to_bytes().unwrap(),
            "0xfEDFe2616EB3661CB8FEd2782F5F0cC91D59DCaC".to_string(),
        );
        let serialized = metadata.to_bytes().unwrap();
        let result = hex::encode(&serialized);
        let expected_result = "0103decaff040069c3222a307866454446653236313645423336363143423846456432373832463546306343393144353944436143";
        assert_eq!(result, expected_result);
    }
}
