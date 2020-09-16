use std::fmt;
use crate::types::{Byte, Result};

#[derive(Debug, PartialEq, Eq)]
pub enum EthNetwork {
    Kovan,
    Goerli,
    Mainnet,
    Rinkeby,
    Ropsten,
}

impl EthNetwork {
    pub fn from_chain_id(chain_id: &u8) -> Result<Self> {
        match chain_id {
            1 => Ok(EthNetwork::Mainnet),
            3 => Ok(EthNetwork::Ropsten),
            4 => Ok(EthNetwork::Rinkeby),
            5 => Ok(EthNetwork::Goerli),
            42 => Ok(EthNetwork::Kovan),
            _ => Err(format!("✘ Unrecognised chain id: '{}'!", chain_id).into())
        }
    }

    pub fn to_byte(&self) -> Byte {
        self.to_chain_id()
    }

    pub fn to_chain_id(&self) -> u8 {
        match self {
            EthNetwork::Mainnet => 1,
            EthNetwork::Ropsten => 3,
            EthNetwork::Rinkeby => 4,
            EthNetwork::Goerli => 5,
            EthNetwork::Kovan => 42,
        }
    }

    pub fn from_str(network_str: &str) -> Result<Self> {
        let lowercase_network_str: &str = &network_str.to_lowercase();
        match lowercase_network_str {
            "mainnet" | "1"  => EthNetwork::from_chain_id(&1),
            "ropsten" | "3"  => EthNetwork::from_chain_id(&3),
            "rinkeby" | "4"  => EthNetwork::from_chain_id(&4),
            "goerli"  | "5"  => EthNetwork::from_chain_id(&5),
            "kovan"   | "42" => EthNetwork::from_chain_id(&42),
            _ => Err(format!("✘ Unrecognized ethereum network: '{}'!", network_str).into()),
        }
    }
}

impl fmt::Display for EthNetwork {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            EthNetwork::Mainnet => write!(f, "Mainnet"),
            EthNetwork::Kovan => write!(f, "Kovan Testnet"),
            EthNetwork::Goerli => write!(f, "Goerli Testnet"),
            EthNetwork::Ropsten => write!(f, "Ropsten Testnet"),
            EthNetwork::Rinkeby => write!(f, "Rinkeby Testnet"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_convert_mainnet_str_to_ethereum_chain_id_correctly() {
        let network_str = "Mainnet";
        let expected_result = EthNetwork::Mainnet;
        let result = EthNetwork::from_str(network_str).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_kovan_str_to_ethereum_chain_id_correctly() {
        let network_str = "kOvAN";
        let expected_result = EthNetwork::Kovan;
        let result = EthNetwork::from_str(network_str).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_ropsten_str_to_ethereum_chain_id_correctly() {
        let network_str = "ROPSTEN";
        let expected_result = EthNetwork::Ropsten;
        let result = EthNetwork::from_str(network_str).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_goerli_str_to_ethereum_chain_id_correctly() {
        let network_str = "goerli";
        let expected_result = EthNetwork::Goerli;
        let result = EthNetwork::from_str(network_str).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_rinkeby_str_to_ethereum_chain_id_correctly() {
        let network_str = "rinkeby";
        let expected_result = EthNetwork::Rinkeby;
        let result = EthNetwork::from_str(network_str).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_mainnet_str_int_to_ethereum_chain_id_correctly() {
        let network_str = "1";
        let expected_result = EthNetwork::Mainnet;
        let result = EthNetwork::from_str(network_str).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_kovan_str_int_to_ethereum_chain_id_correctly() {
        let network_str = "42";
        let expected_result = EthNetwork::Kovan;
        let result = EthNetwork::from_str(network_str).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_ropsten_str_int_to_ethereum_chain_id_correctly() {
        let network_str = "3";
        let expected_result = EthNetwork::Ropsten;
        let result = EthNetwork::from_str(network_str).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_goerli_str_int_to_ethereum_chain_id_correctly() {
        let network_str = "5";
        let expected_result = EthNetwork::Goerli;
        let result = EthNetwork::from_str(network_str).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_rinkeby_str_int_to_ethereum_chain_id_correctly() {
        let network_str = "4";
        let expected_result = EthNetwork::Rinkeby;
        let result = EthNetwork::from_str(network_str).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_fail_to_convert_unknown_network_correctly() {
        let network_str = "some other network";
        let expected_err = format!("✘ Program Error!\n✘ Unrecognized ethereum network: '{}'!", network_str);
        let err = EthNetwork::from_str(network_str).unwrap_err().to_string();
        assert_eq!(err, expected_err);
    }

    #[test]
    fn should_convert_mainnet_to_correct_chain_id() {
        let eth_network = EthNetwork::Mainnet;
        let expected_result = 1;
        let result = eth_network.to_chain_id();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_rinekby_to_correct_chain_id() {
        let eth_network = EthNetwork::Rinkeby;
        let expected_result = 4;
        let result = eth_network.to_chain_id();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_ropsten_to_correct_chain_id() {
        let eth_network = EthNetwork::Ropsten;
        let expected_result = 3;
        let result = eth_network.to_chain_id();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_goerli_to_correct_chain_id() {
        let eth_network = EthNetwork::Goerli;
        let expected_result = 5;
        let result = eth_network.to_chain_id();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_convert_kovan_to_correct_chain_id() {
        let eth_network = EthNetwork::Kovan;
        let expected_result = 42;
        let result = eth_network.to_chain_id();
        assert_eq!(result, expected_result);
    }
}
