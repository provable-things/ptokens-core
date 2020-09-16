use tiny_keccak::keccak256;
use crate::btc_on_eth::{
    eth::eth_types::EthHash,
    utils::convert_h256_to_bytes,
};

pub fn calculate_linker_hash(
    block_hash_to_link_to: EthHash,
    anchor_block_hash: EthHash,
    linker_hash: EthHash
) -> EthHash {
    let mut data = Vec::new();
    convert_h256_to_bytes(block_hash_to_link_to)
        .iter()
        .cloned()
        .map(|byte| data.push(byte))
        .for_each(drop);
    convert_h256_to_bytes(anchor_block_hash)
        .iter()
        .cloned()
        .map(|byte| data.push(byte))
        .for_each(drop);
    convert_h256_to_bytes(linker_hash)
        .iter()
        .cloned()
        .map(|byte| data.push(byte))
        .for_each(drop);
    EthHash::from(keccak256(data.as_slice()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_calculate_linker_hash_correctly() {
        let linker_hash = EthHash::from_slice(
            &hex::decode(
                "0151d767a2bacda0969c93c9e3ea00e1eb08deb4bbd9cfdb7fe8d2d7c6c30062"
            ).unwrap()[..]
        );
        let anchor_block_hash = EthHash::from_slice(
            &hex::decode(
                "74a17673228252a159f8edb348d2e137c0240596b57281e59453d05c7b1adab8"
            ).unwrap()[..]
        );
        let block_hash_to_link_to = EthHash::from_slice(
            &hex::decode(
                "33f5f89485b53d02b7150436f9ddf44b0c43d047ee9d7793db9bae3ce88988bd"
            ).unwrap()[..]
        );
        let expected_result = EthHash::from_slice(
            &hex::decode(
                "ddd1ddca8da92b1fb4dc36dc39ad038d1fd7acaef8a49316b46752a780956f6a"
            ).unwrap()[..]
        );
        let result = calculate_linker_hash(
            block_hash_to_link_to,
            anchor_block_hash,
            linker_hash,
        );
        assert_eq!(result, expected_result);
    }
}
