use tiny_keccak::keccak256;
use crate::{
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
    use crate::utils::convert_hex_to_h256;
    use crate::eth::eth_constants::{
        ETH_LINKER_HASH_KEY,
        ETH_ANCHOR_BLOCK_HASH_KEY,
        ETH_LATEST_BLOCK_HASH_KEY
    };

    #[test]
    fn should_calculate_linker_hash_correctly() {
        let linker_hash = EthHash::from(ETH_LINKER_HASH_KEY);
        let anchor_block_hash = EthHash::from(ETH_ANCHOR_BLOCK_HASH_KEY);
        let block_hash_to_link_to = EthHash::from(ETH_LATEST_BLOCK_HASH_KEY);
        let expected_result_hex = "710f399a2c56bd37f485f3e80212679007cd58c7aea063723979d3104c3d42a5";
        let expected_result = convert_hex_to_h256(
            expected_result_hex.to_string()
        ).unwrap();
        let result = calculate_linker_hash(
            block_hash_to_link_to,
            anchor_block_hash,
            linker_hash,
        );
        assert!(result == expected_result);
    }
}
