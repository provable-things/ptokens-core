pub(crate) mod erc777;
pub(crate) mod erc777_proxy;
pub(crate) mod perc20;

use ethabi::{Contract as EthContract, Token};

use crate::types::{Bytes, Result};

pub fn instantiate_contract_from_abi(abi: &str) -> Result<EthContract> {
    Ok(EthContract::load(abi.as_bytes())?)
}

pub fn encode_fxn_call(abi: &str, fxn_name: &str, param_tokens: &[Token]) -> Result<Bytes> {
    Ok(instantiate_contract_from_abi(abi)?
        .function(fxn_name)?
        .encode_input(&param_tokens)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::eth::eth_contracts::erc777_proxy::ERC777_PROXY_ABI;

    #[test]
    fn should_instantiate_pnetwork_contract_from_abi() {
        let result = instantiate_contract_from_abi(ERC777_PROXY_ABI);
        assert!(result.is_ok());
    }
}
