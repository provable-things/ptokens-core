use ethabi::Token;
use ethereum_types::{
    U256,
    Address as EthAddress,
};
use crate::{
    types::{
        Byte,
        Bytes,
        Result,
    },
    chains::eth::eth_contracts::encode_fxn_call,
};

pub const EMPTY_DATA: Bytes = vec![];
pub const ERC777_CHANGE_PNETWORK_GAS_LIMIT: usize = 30_000;

pub const ERC777_CHANGE_PNETWORK_ABI: &str = "[{\"constant\":false,\"inputs\":[{\"name\":\"newPNetwork\",\"type\":\"address\"}],\"name\":\"changePNetwork\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\",\"signature\":\"0xfd4add66\"}]";

pub const ERC777_MINT_WITH_NO_DATA_ABI: &str = "[{\"constant\":false,\"inputs\":[{\"name\":\"recipient\",\"type\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"mint\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]";

pub const ERC777_MINT_WITH_DATA_ABI: &str = "[{\"constant\":false,\"inputs\":[{\"name\":\"recipient\",\"type\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\"},{\"name\":\"userData\",\"type\":\"bytes\"},{\"name\":\"operatorData\",\"type\":\"bytes\"}],\"name\":\"mint\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]";

pub fn encode_erc777_change_pnetwork_fxn_data(new_ptoken_address: EthAddress) -> Result<Bytes> { // TODO Take a reference!
    encode_fxn_call(ERC777_CHANGE_PNETWORK_ABI, "changePNetwork", &[Token::Address(new_ptoken_address)])
}

fn encode_erc777_mint_with_no_data_fxn(
    recipient: &EthAddress,
    value: &U256,
) -> Result<Bytes> {
    encode_fxn_call(ERC777_MINT_WITH_NO_DATA_ABI, "mint", &[Token::Address(*recipient), Token::Uint(*value)])
}

fn encode_erc777_mint_with_data_fxn(
    recipient: &EthAddress,
    value: &U256,
    user_data: &[Byte],
    operator_data: &[Byte],
) -> Result<Bytes> {
    encode_fxn_call(
        ERC777_MINT_WITH_DATA_ABI,
        "mint",
        &[
            Token::Address(*recipient),
            Token::Uint(*value),
            Token::Bytes(operator_data.to_vec()),
            Token::Bytes(user_data.to_vec()),
        ]
    )
}

fn get_eth_calldata_from_maybe_data(maybe_data: Option<&[Byte]>) -> Bytes {
    maybe_data.unwrap_or(&EMPTY_DATA).to_vec()
}

pub fn encode_erc777_mint_fxn_maybe_with_data(
    recipient: &EthAddress,
    value: &U256,
    user_data: Option<&[Byte]>,
    operator_data: Option<&[Byte]>,
) -> Result<Bytes> {
    match user_data.is_some() | operator_data.is_some() {
        false => encode_erc777_mint_with_no_data_fxn(recipient, value),
        true => encode_erc777_mint_with_data_fxn(
            recipient,
            value,
            &get_eth_calldata_from_maybe_data(user_data),
            &get_eth_calldata_from_maybe_data(operator_data),
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_encode_erc777_change_pnetwork_fxn_data() {
        let expected_result = "fd4add66000000000000000000000000736661736533bcfc9cc35649e6324acefb7d32c1";
        let address = EthAddress::from_slice(&hex::decode("736661736533BcfC9cc35649e6324aceFb7D32c1").unwrap());
        let result = encode_erc777_change_pnetwork_fxn_data(address).unwrap();
        assert_eq!(hex::encode(result), expected_result);
    }

    #[test]
    fn should_encode_erc777_mint_with_no_data_fxn () {
        let expected_result = "40c10f190000000000000000000000001739624f5cd969885a224da84418d12b8570d61a0000000000000000000000000000000000000000000000000000000000000001";
        let recipient = EthAddress::from_slice(&hex::decode("1739624f5cd969885a224da84418d12b8570d61a").unwrap());
        let amount = U256::from_dec_str("1").unwrap();
        let result = encode_erc777_mint_with_no_data_fxn(&recipient, &amount).unwrap();
        assert_eq!(hex::encode(result), expected_result);
    }

    #[test]
    fn should_encode_erc777_mint_with_data_fxn() {
        let expected_result = "dcdc7dd00000000000000000000000001739624f5cd969885a224da84418d12b8570d61a0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000003c0ffee00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003decaff0000000000000000000000000000000000000000000000000000000000";
        let recipient = EthAddress::from_slice(&hex::decode("1739624f5cd969885a224da84418d12b8570d61a").unwrap());
        let amount = U256::from_dec_str("1").unwrap();
        let user_data = vec![0xde, 0xca, 0xff];
        let operator_data = vec![0xc0, 0xff, 0xee];
        let result = encode_erc777_mint_with_data_fxn(&recipient, &amount, &user_data, &operator_data).unwrap();
        assert_eq!(hex::encode(result), expected_result);
    }
}
