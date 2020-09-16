use crate::{
    chains::eth::eth_constants::{ETH_MAINNET_CHAIN_ID, ETH_ROPSTEN_CHAIN_ID},
    types::Result,
};
use ethereum_types::Address as EthAddress;

/// An AnySender relay contract address.
/// Should be kept up-to-date with [this](https://github.com/PISAresearch/docs.AnySender#addresses) table.
#[derive(Debug, PartialEq)]
pub enum RelayContract {
    Mainnet,
    Ropsten,
}

impl RelayContract {
    /// Creates new relay contract from Ethereum chain id.
    pub fn from_eth_chain_id(chain_id: u8) -> Result<RelayContract> {
        match chain_id {
            ETH_MAINNET_CHAIN_ID => Ok(RelayContract::Mainnet),
            ETH_ROPSTEN_CHAIN_ID => Ok(RelayContract::Ropsten),
            _ => Err("✘ AnySender is only available on Ropsten and Mainnet!".into()),
        }
    }

    /// Returns the address of the AnySender relay contract
    pub fn address(&self) -> Result<EthAddress> {
        match *self {
            RelayContract::Mainnet | RelayContract::Ropsten => Ok(EthAddress::from_slice(
                &hex::decode("9b4FA5A1D9f6812e2B56B36fBde62736Fa82c2a7").unwrap(),
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_crete_new_relay_contract_from_eth_chain_id() {
        let relay_contract = RelayContract::from_eth_chain_id(1).unwrap();
        assert_eq!(relay_contract, RelayContract::Mainnet);

        let relay_contract = RelayContract::from_eth_chain_id(3).unwrap();
        assert_eq!(relay_contract, RelayContract::Ropsten);

        RelayContract::from_eth_chain_id(42).expect_err("Should fail with unknown chain id.");
    }

    #[test]
    fn should_return_correct_eth_address() {
        // Mainnet
        let relay_contract = RelayContract::from_eth_chain_id(1).unwrap();
        let relay_contract_address = relay_contract.address().unwrap();
        let expected_contract_address = EthAddress::from_slice(
            &hex::decode("9b4FA5A1D9f6812e2B56B36fBde62736Fa82c2a7").unwrap(),
        );

        assert_eq!(relay_contract_address, expected_contract_address);

        // Ropsten
        let relay_contract = RelayContract::from_eth_chain_id(3).unwrap();
        let relay_contract_address = relay_contract.address().unwrap();
        let expected_contract_address = EthAddress::from_slice(
            &hex::decode("9b4FA5A1D9f6812e2B56B36fBde62736Fa82c2a7").unwrap(),
        );

        assert_eq!(relay_contract_address, expected_contract_address);
    }
}
