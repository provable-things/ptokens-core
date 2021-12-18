use derive_more::Constructor;
use ethabi::{decode as eth_abi_decode, ParamType as EthAbiParamType, Token as EthAbiToken};
use ethereum_types::{Address as EthAddress, H256 as EthHash, U256};

use crate::{
    chains::eth::{
        eth_constants::{ETH_ADDRESS_SIZE_IN_BYTES, ETH_WORD_SIZE_IN_BYTES},
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
        eth_traits::EthLogCompatible,
    },
    traits::DatabaseInterface,
    types::{Byte, Bytes, Result},
};

pub const EMPTY_DATA: Bytes = vec![];
pub const ERC777_CHANGE_PNETWORK_GAS_LIMIT: usize = 30_000;
pub const ERC777_MINT_WITH_DATA_GAS_LIMIT: usize = 450_000;
pub const ERC777_MINT_WITH_NO_DATA_GAS_LIMIT: usize = 180_000;

pub const ERC777_CHANGE_PNETWORK_ABI: &str = "[{\"constant\":false,\"inputs\":[{\"name\":\"newPNetwork\",\"type\":\"address\"}],\"name\":\"changePNetwork\",\"outputs\":[],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\",\"signature\":\"0xfd4add66\"}]";

pub const ERC777_MINT_WITH_NO_DATA_ABI: &str = "[{\"constant\":false,\"inputs\":[{\"name\":\"recipient\",\"type\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\"}],\"name\":\"mint\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]";

pub const ERC777_MINT_WITH_DATA_ABI: &str = "[{\"constant\":false,\"inputs\":[{\"name\":\"recipient\",\"type\":\"address\"},{\"name\":\"value\",\"type\":\"uint256\"},{\"name\":\"userData\",\"type\":\"bytes\"},{\"name\":\"operatorData\",\"type\":\"bytes\"}],\"name\":\"mint\",\"outputs\":[{\"name\":\"\",\"type\":\"bool\"}],\"payable\":false,\"stateMutability\":\"nonpayable\",\"type\":\"function\"}]";

pub const ERC_777_REDEEM_EVENT_TOPIC_WITHOUT_USER_DATA_HEX: &str =
    "78e6c3f67f57c26578f2487b930b70d844bcc8dd8f4d629fb4af81252ab5aa65";

lazy_static! {
    pub static ref ERC_777_REDEEM_EVENT_TOPIC_WITHOUT_USER_DATA: EthHash = {
        EthHash::from_slice(
            &hex::decode(ERC_777_REDEEM_EVENT_TOPIC_WITHOUT_USER_DATA_HEX)
                .expect("✘ Invalid hex in `ERC_777_REDEEM_EVENT_TOPIC_WITHOUT_USER_DATA`"),
        )
    };
}

pub const ERC_777_REDEEM_EVENT_TOPIC_WITH_USER_DATA_HEX: &str =
    "4599e9bf0d45c505e011d0e11f473510f083a4fdc45e3f795d58bb5379dbad68";

lazy_static! {
    pub static ref ERC_777_REDEEM_EVENT_TOPIC_WITH_USER_DATA: EthHash = {
        EthHash::from_slice(
            &hex::decode(ERC_777_REDEEM_EVENT_TOPIC_WITH_USER_DATA_HEX)
                .expect("✘ Invalid hex in `ERC_777_REDEEM_EVENT_TOPIC_WITH_USER_DATA`"),
        )
    };
}

pub fn encode_erc777_change_pnetwork_fxn_data(new_ptoken_address: EthAddress) -> Result<Bytes> {
    encode_fxn_call(ERC777_CHANGE_PNETWORK_ABI, "changePNetwork", &[EthAbiToken::Address(
        new_ptoken_address,
    )])
}

pub fn encode_erc777_mint_with_no_data_fxn(recipient: &EthAddress, value: &U256) -> Result<Bytes> {
    encode_fxn_call(ERC777_MINT_WITH_NO_DATA_ABI, "mint", &[
        EthAbiToken::Address(*recipient),
        EthAbiToken::Uint(*value),
    ])
}

fn encode_erc777_mint_with_data_fxn(
    recipient: &EthAddress,
    value: &U256,
    user_data: &[Byte],
    operator_data: &[Byte],
) -> Result<Bytes> {
    encode_fxn_call(ERC777_MINT_WITH_DATA_ABI, "mint", &[
        EthAbiToken::Address(*recipient),
        EthAbiToken::Uint(*value),
        EthAbiToken::Bytes(user_data.to_vec()),
        EthAbiToken::Bytes(operator_data.to_vec()),
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
        &get_eth_chain_id_from_db(db)?,
        ERC777_CHANGE_PNETWORK_GAS_LIMIT,
        get_eth_gas_price_from_db(db)?,
    )
    .sign(&get_eth_private_key_from_db(db)?)?
    .serialize_hex()))
}

#[derive(Debug, Clone, Constructor, Eq, PartialEq)]
pub struct Erc777RedeemEvent {
    pub redeemer: EthAddress,
    pub value: U256,
    pub underlying_asset_recipient: String,
    pub user_data: Bytes,
}

impl Erc777RedeemEvent {
    fn check_log_is_erc777_redeem_event<L: EthLogCompatible>(log: &L) -> Result<()> {
        if log.get_topics().get(0) == Some(&ERC_777_REDEEM_EVENT_TOPIC_WITH_USER_DATA)
            || log.get_topics().get(0) == Some(&ERC_777_REDEEM_EVENT_TOPIC_WITHOUT_USER_DATA)
        {
            Ok(())
        } else {
            Err("Log is NOT from an ERC777 redeem event!".into())
        }
    }

    fn get_err_msg(field: &str) -> String {
        format!("Error getting `{}` from `EthOnEvmErc777RedeemEvent`!", field)
    }

    fn from_log_without_user_data<L: EthLogCompatible>(log: &L) -> Result<Self> {
        info!("✔ Attemping to get `Erc777RedeemEvent` from log WITHOUT user data...");
        let tokens = eth_abi_decode(&[EthAbiParamType::Uint(256), EthAbiParamType::String], &log.get_data())?;
        log.check_has_x_topics(2).and_then(|_| {
            Ok(Self {
                user_data: vec![],
                redeemer: EthAddress::from_slice(
                    &log.get_topics()[1][ETH_WORD_SIZE_IN_BYTES - ETH_ADDRESS_SIZE_IN_BYTES..],
                ),
                value: match tokens[0] {
                    EthAbiToken::Uint(value) => Ok(value),
                    _ => Err(Self::get_err_msg("value")),
                }?,
                underlying_asset_recipient: match tokens[1] {
                    EthAbiToken::String(ref value) => Ok(value.clone()),
                    _ => Err(Self::get_err_msg("underlying_asset_recipient")),
                }?,
            })
        })
    }

    fn from_log_with_user_data<L: EthLogCompatible>(log: &L) -> Result<Self> {
        info!("✔ Attemping to get `Erc777RedeemEvent` from log WITH user data...");
        let tokens = eth_abi_decode(
            &[
                EthAbiParamType::Uint(256),
                EthAbiParamType::String,
                EthAbiParamType::Bytes,
            ],
            &log.get_data(),
        )?;
        log.check_has_x_topics(2).and_then(|_| {
            Ok(Self {
                redeemer: EthAddress::from_slice(
                    &log.get_topics()[1][ETH_WORD_SIZE_IN_BYTES - ETH_ADDRESS_SIZE_IN_BYTES..],
                ),
                value: match tokens[0] {
                    EthAbiToken::Uint(value) => Ok(value),
                    _ => Err(Self::get_err_msg("value")),
                }?,
                underlying_asset_recipient: match tokens[1] {
                    EthAbiToken::String(ref value) => Ok(value.clone()),
                    _ => Err(Self::get_err_msg("underlying_asset_recipient")),
                }?,
                user_data: match tokens[2] {
                    EthAbiToken::Bytes(ref bytes) => Ok(bytes.to_vec()),
                    _ => Err(Self::get_err_msg("user_data")),
                }?,
            })
        })
    }

    fn log_contains_user_data<L: EthLogCompatible>(log: &L) -> Result<bool> {
        log.check_has_x_topics(1)
            .map(|_| log.get_topics()[0] == *ERC_777_REDEEM_EVENT_TOPIC_WITH_USER_DATA)
    }

    pub fn from_eth_log<L: EthLogCompatible>(log: &L) -> Result<Self> {
        Self::check_log_is_erc777_redeem_event(log).and_then(|_| {
            if Self::log_contains_user_data(log)? {
                Self::from_log_with_user_data(log)
            } else {
                Self::from_log_without_user_data(log)
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::eth::eth_test_utils::{
        get_sample_log_with_erc20_peg_in_event,
        get_sample_log_with_erc777_redeem,
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
        let expected_result = "dcdc7dd00000000000000000000000001739624f5cd969885a224da84418d12b8570d61a0000000000000000000000000000000000000000000000000000000000000001000000000000000000000000000000000000000000000000000000000000008000000000000000000000000000000000000000000000000000000000000000c00000000000000000000000000000000000000000000000000000000000000003decaff00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000003c0ffee0000000000000000000000000000000000000000000000000000000000";
        let recipient = EthAddress::from_slice(&hex::decode("1739624f5cd969885a224da84418d12b8570d61a").unwrap());
        let amount = U256::from_dec_str("1").unwrap();
        let user_data = vec![0xde, 0xca, 0xff];
        let operator_data = vec![0xc0, 0xff, 0xee];
        let result = encode_erc777_mint_with_data_fxn(&recipient, &amount, &user_data, &operator_data).unwrap();
        assert_eq!(hex::encode(result), expected_result);
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
            vec![],
        );
        let result = Erc777RedeemEvent::from_log_without_user_data(&log).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_fail_to_get_params_from_non_erc777_redeem_event() {
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = Erc777RedeemEvent::from_log_without_user_data(&log);
        assert!(result.is_err());
    }
}
