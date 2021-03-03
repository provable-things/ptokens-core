use derive_more::Constructor;
use ethabi::Token;
use ethereum_types::{Address as EthAddress, H256 as EthHash, U256};

use crate::{
    chains::eth::{
        eth_constants::ETH_WORD_SIZE_IN_BYTES,
        eth_contracts::encode_fxn_call,
        eth_crypto::eth_transaction::EthTransaction,
        eth_database_utils::{
            get_erc777_contract_address_from_db,
            get_eth_account_nonce_from_db,
            get_eth_chain_id_from_db,
            get_eth_gas_price_from_db,
            get_eth_private_key_from_db,
            increment_eth_account_nonce_in_db,
        },
        eth_log::EthLog,
    },
    traits::DatabaseInterface,
    types::{Byte, Bytes, Result},
};

pub const EMPTY_DATA: Bytes = vec![];
pub const ERC777_CHANGE_PNETWORK_GAS_LIMIT: usize = 30_000;
pub const ERC777_MINT_WITH_NO_DATA_GAS_LIMIT: usize = 180_000;

pub const ERC777_CHANGE_PNETWORK_ABI: &str = "[{\"constant\":false,\"inputs\":[{\"name\":\"newPNetwork\",\"type\":\"address\"}],\"name\":\"changePNetwork\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\",\"signature\":\"0xfd4add66\"}]";

pub const ERC777_MINT_WITH_NO_DATA_ABI: &str = "[{\"constant\":false,\"inputs\":[{\"name\":\"recipient\",\"type\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"mint\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]";

pub const ERC777_MINT_WITH_DATA_ABI: &str = "[{\"constant\":false,\"inputs\":[{\"name\":\"recipient\",\"type\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\"},{\"name\":\"userData\",\"type\":\"bytes\"},{\"name\":\"operatorData\",\"type\":\"bytes\"}],\"name\":\"mint\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]";

lazy_static! {
    pub static ref ERC_777_REDEEM_EVENT_TOPIC: EthHash = {
        EthHash::from_slice(
            &hex::decode("78e6c3f67f57c26578f2487b930b70d844bcc8dd8f4d629fb4af81252ab5aa65")
                .expect("✘ Invalid hex in `BTC_ON_ETH_REDEEM_EVENT_TOPIC`"),
        )
    };
}

pub fn encode_erc777_change_pnetwork_fxn_data(new_ptoken_address: EthAddress) -> Result<Bytes> {
    encode_fxn_call(ERC777_CHANGE_PNETWORK_ABI, "changePNetwork", &[Token::Address(
        new_ptoken_address,
    )])
}

pub fn encode_erc777_mint_with_no_data_fxn(recipient: &EthAddress, value: &U256) -> Result<Bytes> {
    encode_fxn_call(ERC777_MINT_WITH_NO_DATA_ABI, "mint", &[
        Token::Address(*recipient),
        Token::Uint(*value),
    ])
}

fn encode_erc777_mint_with_data_fxn(
    recipient: &EthAddress,
    value: &U256,
    user_data: &[Byte],
    operator_data: &[Byte],
) -> Result<Bytes> {
    encode_fxn_call(ERC777_MINT_WITH_DATA_ABI, "mint", &[
        Token::Address(*recipient),
        Token::Uint(*value),
        Token::Bytes(operator_data.to_vec()),
        Token::Bytes(user_data.to_vec()),
    ])
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
        ),
    }
}

pub fn get_signed_erc777_change_pnetwork_tx<D: DatabaseInterface>(db: &D, new_address: EthAddress) -> Result<String> {
    const ZERO_ETH_VALUE: usize = 0;
    let nonce_before_incrementing = get_eth_account_nonce_from_db(db)?;
    increment_eth_account_nonce_in_db(db, 1).and(Ok(EthTransaction::new_unsigned(
        encode_erc777_change_pnetwork_fxn_data(new_address)?,
        nonce_before_incrementing,
        ZERO_ETH_VALUE,
        get_erc777_contract_address_from_db(db)?,
        get_eth_chain_id_from_db(db)?,
        ERC777_CHANGE_PNETWORK_GAS_LIMIT,
        get_eth_gas_price_from_db(db)?,
    )
    .sign(get_eth_private_key_from_db(db)?)?
    .serialize_hex()))
}

#[derive(Debug, Clone, Constructor, Eq, PartialEq)]
pub struct Erc777RedeemEvent {
    pub redeemer: EthAddress,
    pub value: U256,
    pub underlying_asset_recipient: String,
}

impl Erc777RedeemEvent {
    fn get_redeemer_address_from_redeem_log(log: &EthLog) -> Result<EthAddress> {
        if log.topics.len() < 2 {
            Err("Not enough topics to get redeemer address from ERC777 log!".into())
        } else {
            Ok(EthAddress::from_slice(&log.topics[1].as_bytes()[12..]))
        }
    }

    fn get_redeem_amount_from_redeem_log(log: &EthLog) -> Result<U256> {
        if log.data.len() >= ETH_WORD_SIZE_IN_BYTES {
            Ok(U256::from(&log.data[..ETH_WORD_SIZE_IN_BYTES]))
        } else {
            Err("Not enough bytes in log data to get redeem amount!".into())
        }
    }

    fn get_underlying_asset_address_from_redeem_log(log: &EthLog) -> Result<String> {
        let start_index = ETH_WORD_SIZE_IN_BYTES * 3;
        if log.data.len() >= start_index {
            Ok(log.data[start_index..]
                .iter()
                .filter(|byte| *byte != &0u8)
                .map(|byte| *byte as char)
                .collect::<String>())
        } else {
            Err("Not enough bytes in redeem log data to parse underlying asset string!".into())
        }
    }

    fn check_log_is_erc777_redeem_event(log: &EthLog) -> Result<()> {
        match log.topics[0] == *ERC_777_REDEEM_EVENT_TOPIC {
            true => Ok(()),
            false => Err("Log is NOT from an ERC777 redeem event!".into()),
        }
    }

    pub fn from_eth_log(log: &EthLog) -> Result<Self> {
        Erc777RedeemEvent::check_log_is_erc777_redeem_event(log).and_then(|_| {
            Ok(Erc777RedeemEvent {
                value: Erc777RedeemEvent::get_redeem_amount_from_redeem_log(log)?,
                redeemer: Erc777RedeemEvent::get_redeemer_address_from_redeem_log(log)?,
                underlying_asset_recipient: Erc777RedeemEvent::get_underlying_asset_address_from_redeem_log(log)?,
            })
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::eth::eth_test_utils::{get_sample_log_with_erc20_peg_in_event, get_sample_log_with_erc777_redeem},
        errors::AppError,
    };

    #[test]
    fn should_encode_erc777_change_pnetwork_fxn_data() {
        let expected_result = "fd4add66000000000000000000000000736661736533bcfc9cc35649e6324acefb7d32c1";
        let address = EthAddress::from_slice(&hex::decode("736661736533BcfC9cc35649e6324aceFb7D32c1").unwrap());
        let result = encode_erc777_change_pnetwork_fxn_data(address).unwrap();
        assert_eq!(hex::encode(result), expected_result);
    }

    #[test]
    fn should_encode_erc777_mint_with_no_data_fxn() {
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

    #[test]
    fn should_get_redeemer_address_from_redeem_log() {
        let log = get_sample_log_with_erc777_redeem();
        let result = Erc777RedeemEvent::get_redeemer_address_from_redeem_log(&log).unwrap();
        let expected_result = EthAddress::from_slice(&hex::decode("edb86cd455ef3ca43f0e227e00469c3bdfa40628").unwrap());
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_redeem_amount_from_redeem_log() {
        let log = get_sample_log_with_erc777_redeem();
        let result = Erc777RedeemEvent::get_redeem_amount_from_redeem_log(&log).unwrap();
        let expected_result = U256::from_dec_str("6660000000000").unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_underlying_asset_address_from_redeem_log() {
        let log = get_sample_log_with_erc777_redeem();
        let result = Erc777RedeemEvent::get_underlying_asset_address_from_redeem_log(&log).unwrap();
        let expected_result = "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_check_log_is_erc777_redeem_event() {
        let log = get_sample_log_with_erc777_redeem();
        let result = Erc777RedeemEvent::check_log_is_erc777_redeem_event(&log);
        assert!(result.is_ok());
    }

    #[test]
    fn non_erc777_log_should_not_pass_erc777_check() {
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = Erc777RedeemEvent::check_log_is_erc777_redeem_event(&log);
        assert!(result.is_err());
    }

    #[test]
    fn should_get_redeem_event_params_from_log() {
        let log = get_sample_log_with_erc777_redeem();
        let expected_result = Erc777RedeemEvent::new(
            EthAddress::from_slice(&hex::decode("edb86cd455ef3ca43f0e227e00469c3bdfa40628").unwrap()),
            U256::from_dec_str("6660000000000").unwrap(),
            "mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM".to_string(),
        );
        let result = Erc777RedeemEvent::from_eth_log(&log).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_fail_to_get_params_from_non_erc777_redeem_event() {
        let expected_err = "Log is NOT from an ERC777 redeem event!".to_string();
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        match Erc777RedeemEvent::from_eth_log(&log) {
            Ok(_) => panic!("Should not have succeeded!"),
            Err(AppError::Custom(err)) => assert_eq!(err, expected_err),
            Err(_) => panic!("Wrong error received!"),
        }
    }
}
