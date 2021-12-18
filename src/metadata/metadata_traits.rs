use crate::{
    metadata::{metadata_chain_id::MetadataChainId, Metadata},
    types::{Bytes, Result},
};

pub trait ToMetadata {
    fn to_metadata(&self) -> Result<Metadata>;
    fn to_metadata_bytes(&self) -> Result<Bytes>;
}

pub trait ToMetadataChainId {
    fn to_metadata_chain_id(&self) -> MetadataChainId;
}
