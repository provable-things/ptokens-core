use ethereum_types::Address as EthAddress;
use crate::{
    types::Bytes,
    crypto_utils::keccak_hash_bytes,
};

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub struct EthPublicKey {
    pub compressed: bool,
    pub public_key: secp256k1::key::PublicKey,
}

impl EthPublicKey {
    pub fn to_bytes(&self) -> Bytes {
        self.public_key.serialize_uncompressed().to_vec()
    }

    pub fn to_address(&self) -> EthAddress {
        let mut eth_address = EthAddress::zero();
        eth_address.assign_from_slice(
            &keccak_hash_bytes(self.to_bytes()[1..65].to_vec())[12..]
        );
        eth_address
    }
}

#[cfg(test)]
mod tests{
    use crate::eth::eth_test_utils::{
        get_sample_eth_public_key,
        get_sample_eth_address_string,
        get_sample_eth_public_key_bytes,
    };

    #[test]
    fn should_convert_public_key_to_bytes() {
        let public_key = get_sample_eth_public_key();
        let expected_result = get_sample_eth_public_key_bytes();
        let result = public_key.to_bytes();
        assert!(result == expected_result);
    }

    #[test]
    fn should_convert_public_key_to_eth_address() {
        let public_key = get_sample_eth_public_key();
        let result = public_key.to_address();
        assert!(hex::encode(result.as_bytes()) == get_sample_eth_address_string());
    }
}
