use ethabi::Token;
use ethereum_types::{
    U256,
    Address as EthAddress,
};
use crate::{
    chains::eth::eth_contracts::encode_fxn_call,
    types::{
        Bytes,
        Result,
    },
};

pub const PERC20_PEGOUT_GAS_LIMIT: usize = 180_000;
pub const PERC20_MIGRATE_GAS_LIMIT: usize = 6_000_000;
pub const PERC20_CHANGE_SUPPORTED_TOKEN_GAS_LIMIT: usize = 100_000;

pub const PERC20_ABI: &str = "[{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_tokenRecipient\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_tokenAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_tokenAmount\",\"type\":\"uint256\"}],\"name\":\"pegOut\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"addresspayable\",\"name\":\"_to\",\"type\":\"address\"}],\"name\":\"migrate\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_tokenAddress\",\"type\":\"address\"}],\"name\":\"addSupportedToken\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"SUCCESS\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_tokenAddress\",\"type\":\"address\"}],\"name\":\"removeSupportedToken\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"SUCCESS\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]";

pub fn encode_perc20_peg_out_fxn_data(
    recipient: EthAddress,
    token_contract_address: EthAddress,
    amount: U256,
) -> Result<Bytes> {
    encode_fxn_call(
        PERC20_ABI,
        "pegOut",
        &[Token::Address(recipient), Token::Address(token_contract_address), Token::Uint(amount)]
    )
}

pub fn encode_perc20_migrate_fxn_data(migrate_to: EthAddress) -> Result<Bytes> {
    encode_fxn_call(PERC20_ABI, "migrate", &[Token::Address(migrate_to)])
}

pub fn encode_perc20_add_supported_token_fx_data(token_to_support: EthAddress) -> Result<Bytes> { // TODO test!
    encode_fxn_call(PERC20_ABI, "addSupportedToken", &[Token::Address(token_to_support)])
}

pub fn encode_perc20_remove_supported_token_fx_data(token_to_remove: EthAddress) -> Result<Bytes> { // TODO test!
    encode_fxn_call(PERC20_ABI, "removeSupportedToken", &[Token::Address(token_to_remove)])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_encode_peg_out_fxn_data() {
        let amount = U256::from(1337);
        let recipient_address = EthAddress::from_slice(&hex::decode("edB86cd455ef3ca43f0e227e00469C3bDFA40628").unwrap());
        let token_address = EthAddress::from_slice(&hex::decode("fEDFe2616EB3661CB8FEd2782F5F0cC91D59DCaC").unwrap());
        let expected_result = "83c09d42000000000000000000000000edb86cd455ef3ca43f0e227e00469c3bdfa40628000000000000000000000000fedfe2616eb3661cb8fed2782f5f0cc91d59dcac0000000000000000000000000000000000000000000000000000000000000539";
        let result = hex::encode(encode_perc20_peg_out_fxn_data(recipient_address, token_address, amount).unwrap());
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_encode_migrate_fxn_data() {
        let address = EthAddress::from_slice(&hex::decode("edB86cd455ef3ca43f0e227e00469C3bDFA40628").unwrap());
        let expected_result = "ce5494bb000000000000000000000000edb86cd455ef3ca43f0e227e00469c3bdfa40628";
        let result = hex::encode(encode_perc20_migrate_fxn_data(address).unwrap());
        assert_eq!(result, expected_result)
    }
}
