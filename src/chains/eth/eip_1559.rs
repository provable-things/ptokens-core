use derive_more::Constructor;
use ethereum_types::U256;

use crate::{chains::eth::eth_chain_id::EthChainId, types::Result};

#[derive(Clone, Constructor)]
pub struct Eip1559 {}

impl Eip1559 {
    pub fn get_activation_block_number(&self, eth_chain_id: &EthChainId) -> Result<U256> {
        match eth_chain_id {
            EthChainId::Mainnet => Ok(U256::from(12_965_000)),
            EthChainId::Ropsten => Ok(U256::from(10_499_401)),
            _ => Err(format!("{} does not have an `EIP1559` activation block number! ", eth_chain_id).into()),
        }
    }

    pub fn is_active(&self, eth_chain_id: &EthChainId, block_number: U256) -> Result<bool> {
        match eth_chain_id {
            EthChainId::Mainnet | EthChainId::Ropsten => {
                Ok(block_number >= self.get_activation_block_number(eth_chain_id)?)
            },
            _ => Ok(false),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_eip_1559_get_activation_block_number() {
        let eip_1559 = Eip1559::new();
        let chain_id = EthChainId::Mainnet;
        let result = eip_1559.get_activation_block_number(&chain_id).unwrap();
        let expected_result = U256::from(12_965_000);
        assert_eq!(result, expected_result);
    }

    #[test]
    fn eip_1559_should_be_active() {
        let block_number = U256::from(13_000_000);
        let eip_1559 = Eip1559::new();
        let chain_id = EthChainId::Mainnet;
        let result = eip_1559.is_active(&chain_id, block_number).unwrap();
        assert!(result);
    }

    #[test]
    fn eip_1559_should_not_be_active() {
        let block_number = U256::from(12_000_000);
        let eip_1559 = Eip1559::new();
        let chain_id = EthChainId::Mainnet;
        eip_1559.is_active(&chain_id, block_number).unwrap();
    }
}
