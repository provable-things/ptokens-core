#![cfg(test)]
use std::str::FromStr;

use bitcoin::util::address::Address as BtcAddress;
use eos_chain::AccountName as EosAddress;
use ethereum_types::Address as EthAddress;

use crate::{
    metadata::{metadata_chain_id::MetadataChainId, metadata_origin_address::MetadataOriginAddress, Metadata},
    types::Bytes,
};

pub fn get_sample_eos_address() -> EosAddress {
    EosAddress::from_str("aneosaddress").unwrap()
}

pub fn get_sample_btc_address() -> BtcAddress {
    BtcAddress::from_str("12dRugNcdxK39288NjcDV4GX7rMsKCGn6B").unwrap()
}

pub fn get_sample_eth_address() -> EthAddress {
    EthAddress::from_slice(&hex::decode("5A0b54D5dc17e0AadC383d2db43B0a0D3E029c4c").unwrap())
}

fn get_sample_user_data() -> Bytes {
    vec![0xc0, 0xff, 0xee]
}

pub fn get_sample_eth_origin_address() -> MetadataOriginAddress {
    MetadataOriginAddress::new_from_eth_address(&get_sample_eth_address(), &MetadataChainId::EthereumMainnet).unwrap()
}

pub fn get_sample_eos_origin_address() -> MetadataOriginAddress {
    MetadataOriginAddress::new_from_eos_address(&get_sample_eos_address(), &MetadataChainId::EosMainnet).unwrap()
}

pub fn get_sample_btc_origin_address() -> MetadataOriginAddress {
    MetadataOriginAddress::new_from_btc_address(&get_sample_btc_address(), &MetadataChainId::BitcoinMainnet).unwrap()
}

pub fn get_sample_eth_metadata() -> Metadata {
    Metadata::new(&get_sample_user_data(), &get_sample_eth_origin_address())
}

pub fn get_sample_eos_metadata() -> Metadata {
    Metadata::new(&get_sample_user_data(), &get_sample_eos_origin_address())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_get_sample_eth_metadata() {
        get_sample_eth_metadata();
    }

    #[test]
    fn should_get_sample_eos_metadata() {
        get_sample_eos_metadata();
    }
}
