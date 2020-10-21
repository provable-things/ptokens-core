use ethabi::{encode, Token};
use ethereum_types::{
    U256,
    Address as EthAddress,
};
use crate::{
    types::{
        Bytes,
        Result,
    },
    traits::DatabaseInterface,
    chains::eth::{
        eth_contracts::encode_fxn_call,
        eth_crypto::eth_private_key::EthPrivateKey,
        eth_crypto::eth_transaction::EthTransaction,
        eth_contracts::erc777::ERC777_CHANGE_PNETWORK_GAS_LIMIT,
        eth_database_utils::{
            get_eth_chain_id_from_db,
            get_eth_gas_price_from_db,
            get_eth_private_key_from_db,
            get_eth_account_nonce_from_db,
            increment_eth_account_nonce_in_db,
            get_erc777_proxy_contract_address_from_db,
        },
    },
};

pub const ERC777_CHANGE_PNETWORK_BY_PROXY_GAS_LIMIT: usize = 33_000;

pub const ERC777_PROXY_ABI: &str = "[{\"constant\":true,\"inputs\":[],\"name\":\"pTokenAddress\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\",\"signature\":\"0x521404d8\"},{\"constant\":true,\"inputs\":[{\"name\":\"\",\"type\":\"bytes32\"}],\"name\":\"processTransactions\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\",\"signature\":\"0xafd5b776\"},{\"constant\":true,\"inputs\":[],\"name\":\"pNetwork\",\"outputs\":[{\"name\":\"\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\",\"signature\":\"0xca16814e\"},{\"inputs\":[{\"name\":\"_pTokenAddress\",\"type\":\"address\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"constructor\",\"signature\":\"constructor\"},{\"constant\":false,\"inputs\":[{\"name\":\"_newPNetwork\",\"type\":\"address\"}],\"name\":\"changePNetwork\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\",\"signature\":\"0xfd4add66\"},{\"constant\":false,\"inputs\":[{\"name\":\"_newPToken\",\"type\":\"address\"}],\"name\":\"changePTokenAddress\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\",\"signature\":\"0x28c14fa8\"},{\"constant\":false,\"inputs\":[{\"name\":\"_recipient\",\"type\":\"address\"},{\"name\":\"_amount\",\"type\":\"uint256\"},{\"name\":\"_nonce\",\"type\":\"uint256\"},{\"name\":\"_signature\",\"type\":\"bytes\"}],\"name\":\"mintByProxy\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\",\"signature\":\"0x7ad6ae47\"},{\"constant\":false,\"inputs\":[{\"name\":\"_newPNetwork\",\"type\":\"address\"}],\"name\":\"changePNetworkByProxy\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\",\"signature\":\"0x6f9d66b0\"}]";

pub fn encode_mint_by_proxy_tx_data(
    eth_private_key: &EthPrivateKey,
    token_recipient: EthAddress,
    token_amount: U256,
    any_sender_nonce: u64,
) -> Result<Bytes> {
    let proxy_signature = eth_private_key
        .sign_eth_prefixed_msg_bytes(&encode(&[
            Token::Address(EthAddress::from_slice(token_recipient.as_bytes())),
            Token::Uint(token_amount),
            Token::Uint(any_sender_nonce.into()),
        ]))?.to_vec();
    let fxn_param_tokens = [
        Token::Address(EthAddress::from_slice(token_recipient.as_bytes())),
        Token::Uint(token_amount),
        Token::Uint(any_sender_nonce.into()),
        Token::Bytes(proxy_signature),
    ];
    encode_fxn_call(ERC777_PROXY_ABI, "mintByProxy", &fxn_param_tokens)
}

pub fn encode_erc777_proxy_change_pnetwork_fxn_data(new_pnetwork_address: EthAddress) -> Result<Bytes> {
    encode_fxn_call(ERC777_PROXY_ABI, "changePNetwork", &[Token::Address(new_pnetwork_address)])
}

pub fn encode_erc777_proxy_change_pnetwork_by_proxy_fxn_data(new_pnetwork_address: EthAddress) -> Result<Bytes> {
    encode_fxn_call(ERC777_PROXY_ABI, "changePNetworkByProxy", &[Token::Address(new_pnetwork_address)])
}


const ZERO_ETH_VALUE: usize = 0;

pub fn get_signed_erc777_proxy_change_pnetwork_tx<D>(
    db: &D,
    new_address: EthAddress,
) -> Result<String>
where
    D: DatabaseInterface,
{
    let nonce_before_incrementing = get_eth_account_nonce_from_db(db)?;
    increment_eth_account_nonce_in_db(db, 1)
        .and(
            Ok(EthTransaction::new_unsigned(
                encode_erc777_proxy_change_pnetwork_fxn_data(new_address)?,
                nonce_before_incrementing,
                ZERO_ETH_VALUE,
                get_erc777_proxy_contract_address_from_db(db)?,
                get_eth_chain_id_from_db(db)?,
                ERC777_CHANGE_PNETWORK_GAS_LIMIT,
                get_eth_gas_price_from_db(db)?,
            )
            .sign(get_eth_private_key_from_db(db)?)?
            .serialize_hex())
        )
}

pub fn get_signed_erc777_proxy_change_pnetwork_by_proxy_tx<D>(
    db: &D,
    new_address: EthAddress,
) -> Result<String>
where
    D: DatabaseInterface,
{
    let nonce_before_incrementing = get_eth_account_nonce_from_db(db)?;
    increment_eth_account_nonce_in_db(db, 1)
        .and(
            Ok(EthTransaction::new_unsigned(
                encode_erc777_proxy_change_pnetwork_by_proxy_fxn_data(new_address)?,
                nonce_before_incrementing,
                ZERO_ETH_VALUE,
                get_erc777_proxy_contract_address_from_db(db)?,
                get_eth_chain_id_from_db(db)?,
                ERC777_CHANGE_PNETWORK_BY_PROXY_GAS_LIMIT,
                get_eth_gas_price_from_db(db)?,
            )
            .sign(get_eth_private_key_from_db(db)?)?
            .serialize_hex())
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc_on_eth::eth::eth_test_utils::{
        get_sample_eth_address,
        get_sample_eth_private_key,
    };

    #[test]
    fn should_encode_mint_by_proxy_tx_data() {
        let any_sender_nonce = 0;
        let token_amount = U256::from(1337);
        let token_recipient = get_sample_eth_address();
        let eth_private_key = get_sample_eth_private_key();
        let result = encode_mint_by_proxy_tx_data(&eth_private_key, token_recipient, token_amount, any_sender_nonce)
            .unwrap();
        let expected_result = "7ad6ae470000000000000000000000001739624f5cd969885a224da84418d12b8570d61a000000000000000000000000000000000000000000000000000000000000053900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000080000000000000000000000000000000000000000000000000000000000000004187465d778f26a5207333f3296c499ed7701f5c9fbd7adcab77117afcfcebbc1669e18b8e1af2577060b8cee764d69ce7af434510b3a256681d976dbec510850b1c00000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(hex::encode(result), expected_result);
    }

    #[test]
    fn should_encode_erc777_proxy_change_pnetwork_fxn_data() {
        let address = get_sample_eth_address();
        let expected_result = "fd4add660000000000000000000000001739624f5cd969885a224da84418d12b8570d61a";
        let result = encode_erc777_proxy_change_pnetwork_fxn_data(address).unwrap();
        assert_eq!(hex::encode(result), expected_result);
    }

    #[test]
    fn should_encode_erc777_proxy_change_pnetwork_by_proxy_fxn_data() {
        let address = get_sample_eth_address();
        let expected_result = "6f9d66b00000000000000000000000001739624f5cd969885a224da84418d12b8570d61a";
        let result = encode_erc777_proxy_change_pnetwork_by_proxy_fxn_data(address).unwrap();
        assert_eq!(hex::encode(result), expected_result);
    }
}
