use derive_more::Constructor;
use ethabi::{decode as eth_abi_decode, ParamType as EthAbiParamType, Token as EthAbiToken};
use ethereum_types::{Address as EthAddress, H256 as EthHash, U256};

use crate::{
    chains::eth::{eth_contracts::encode_fxn_call, eth_traits::EthLogCompatible},
    types::{Bytes, Result},
};

pub const ERC20_VAULT_MIGRATE_GAS_LIMIT: usize = 2_000_000;
pub const ERC20_VAULT_PEGOUT_WITH_USER_DATA_GAS_LIMIT: usize = 450_000;
pub const ERC20_VAULT_CHANGE_SUPPORTED_TOKEN_GAS_LIMIT: usize = 100_000;
pub const ERC20_VAULT_PEGOUT_WITHOUT_USER_DATA_GAS_LIMIT: usize = 250_000;

const ERC20_VAULT_ABI: &str = "[{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_tokenRecipient\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_tokenAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_tokenAmount\",\"type\":\"uint256\"}],\"name\":\"pegOut\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"addresspayable\",\"name\":\"_to\",\"type\":\"address\"}],\"name\":\"migrate\",\"outputs\":[],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_tokenAddress\",\"type\":\"address\"}],\"name\":\"addSupportedToken\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"SUCCESS\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_tokenAddress\",\"type\":\"address\"}],\"name\":\"removeSupportedToken\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"SUCCESS\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\"},{\"inputs\":[{\"internalType\":\"address payable\",\"name\":\"_tokenRecipient\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_tokenAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_tokenAmount\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"_userData\",\"type\":\"bytes\"}],\"name\":\"pegOut\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\",\"signature\":\"0x22965469\"}]";

// NOTE: Separate from the above ABI ∵ `ethabi` crate can't handle overloaded functions.
const ERC20_VAULT_PEGOUT_WITH_USER_DATA_ABI: &str = "[{\"inputs\":[{\"internalType\":\"address\",\"name\":\"_tokenRecipient\",\"type\":\"address\"},{\"internalType\":\"address\",\"name\":\"_tokenAddress\",\"type\":\"address\"},{\"internalType\":\"uint256\",\"name\":\"_tokenAmount\",\"type\":\"uint256\"},{\"internalType\":\"bytes\",\"name\":\"_userData\",\"type\":\"bytes\"}],\"name\":\"pegOut\",\"outputs\":[{\"internalType\":\"bool\",\"name\":\"\",\"type\":\"bool\"}],\"stateMutability\":\"nonpayable\",\"type\":\"function\",\"signature\":\"0x22965469\"}]";

pub const ERC20_VAULT_PEG_IN_EVENT_WITHOUT_USER_DATA_TOPIC_HEX: &str =
    "42877668473c4cba073df41397388516dc85c3bbae14b33603513924cec55e36";

pub const ERC20_VAULT_PEG_IN_EVENT_WITH_USER_DATA_TOPIC_HEX: &str =
    "d45bf0460398ad3b27d2bd85144872898591943b81eca880e34fca0a229aa0dc";

lazy_static! {
    pub static ref ERC20_VAULT_PEG_IN_EVENT_WITHOUT_USER_DATA_TOPIC: EthHash = {
        EthHash::from_slice(
            &hex::decode(ERC20_VAULT_PEG_IN_EVENT_WITHOUT_USER_DATA_TOPIC_HEX)
                .expect("✘ Invalid hex in `ERC20_VAULT_PEG_IN_EVENT_WITHOUT_USER_DATA_TOPIC`!"),
        )
    };
    pub static ref ERC20_VAULT_PEG_IN_EVENT_WITH_USER_DATA_TOPIC: EthHash = {
        EthHash::from_slice(
            &hex::decode(ERC20_VAULT_PEG_IN_EVENT_WITH_USER_DATA_TOPIC_HEX)
                .expect("✘ Invalid hex in `ERC20_VAULT_PEG_IN_EVENT_WITH_USER_DATA_TOPIC`!"),
        )
    };
}

pub fn encode_erc20_vault_peg_out_fxn_data_without_user_data(
    recipient: EthAddress,
    token_contract_address: EthAddress,
    amount: U256,
) -> Result<Bytes> {
    encode_fxn_call(ERC20_VAULT_ABI, "pegOut", &[
        EthAbiToken::Address(recipient),
        EthAbiToken::Address(token_contract_address),
        EthAbiToken::Uint(amount),
    ])
}

pub fn encode_erc20_vault_peg_out_fxn_data_with_user_data(
    recipient: EthAddress,
    token_contract_address: EthAddress,
    amount: U256,
    user_data: Bytes,
) -> Result<Bytes> {
    encode_fxn_call(ERC20_VAULT_PEGOUT_WITH_USER_DATA_ABI, "pegOut", &[
        EthAbiToken::Address(recipient),
        EthAbiToken::Address(token_contract_address),
        EthAbiToken::Uint(amount),
        EthAbiToken::Bytes(user_data),
    ])
}

pub fn encode_erc20_vault_migrate_fxn_data(migrate_to: EthAddress) -> Result<Bytes> {
    encode_fxn_call(ERC20_VAULT_ABI, "migrate", &[EthAbiToken::Address(migrate_to)])
}

pub fn encode_erc20_vault_add_supported_token_fx_data(token_to_support: EthAddress) -> Result<Bytes> {
    encode_fxn_call(ERC20_VAULT_ABI, "addSupportedToken", &[EthAbiToken::Address(
        token_to_support,
    )])
}

pub fn encode_erc20_vault_remove_supported_token_fx_data(token_to_remove: EthAddress) -> Result<Bytes> {
    encode_fxn_call(ERC20_VAULT_ABI, "removeSupportedToken", &[EthAbiToken::Address(
        token_to_remove,
    )])
}

#[derive(Debug, PartialEq, Constructor)]
pub struct Erc20VaultPegInEventParams {
    pub user_data: Bytes,
    pub token_amount: U256,
    pub token_sender: EthAddress,
    pub token_address: EthAddress,
    pub destination_address: String,
}

impl Erc20VaultPegInEventParams {
    fn get_err_msg(field: &str) -> String {
        format!("Error getting `{}` for `Erc20VaultPegInEventParams`!", field)
    }

    fn from_eth_log_without_user_data<L: EthLogCompatible>(log: &L) -> Result<Self> {
        let tokens = eth_abi_decode(
            &[
                EthAbiParamType::Address,
                EthAbiParamType::Address,
                EthAbiParamType::Uint(256),
                EthAbiParamType::String,
            ],
            &log.get_data(),
        )?;
        Ok(Self {
            user_data: vec![],
            token_address: match tokens[0] {
                EthAbiToken::Address(value) => Ok(value),
                _ => Err(Self::get_err_msg("token_address")),
            }?,
            token_sender: match tokens[1] {
                EthAbiToken::Address(value) => Ok(value),
                _ => Err(Self::get_err_msg("token_sender")),
            }?,
            token_amount: match tokens[2] {
                EthAbiToken::Uint(value) => Ok(value),
                _ => Err(Self::get_err_msg("token_amount")),
            }?,
            destination_address: match tokens[3] {
                EthAbiToken::String(ref value) => Ok(value.clone()),
                _ => Err(Self::get_err_msg("destination_address")),
            }?,
        })
    }

    fn from_eth_log_with_user_data<L: EthLogCompatible>(log: &L) -> Result<Self> {
        let tokens = eth_abi_decode(
            &[
                EthAbiParamType::Address,
                EthAbiParamType::Address,
                EthAbiParamType::Uint(256),
                EthAbiParamType::String,
                EthAbiParamType::Bytes,
            ],
            &log.get_data(),
        )?;
        Ok(Self {
            token_address: match tokens[0] {
                EthAbiToken::Address(value) => Ok(value),
                _ => Err(Self::get_err_msg("token_address")),
            }?,
            token_sender: match tokens[1] {
                EthAbiToken::Address(value) => Ok(value),
                _ => Err(Self::get_err_msg("token_sender")),
            }?,
            token_amount: match tokens[2] {
                EthAbiToken::Uint(value) => Ok(value),
                _ => Err(Self::get_err_msg("token_amount")),
            }?,
            destination_address: match tokens[3] {
                EthAbiToken::String(ref value) => Ok(value.clone()),
                _ => Err(Self::get_err_msg("destination_address")),
            }?,
            user_data: match tokens[4] {
                EthAbiToken::Bytes(ref value) => Ok(value.clone()),
                _ => Err(Self::get_err_msg("user_data")),
            }?,
        })
    }

    pub fn from_eth_log<L: EthLogCompatible>(log: &L) -> Result<Self> {
        Self::from_eth_log_with_user_data(log).or_else(|_| Self::from_eth_log_without_user_data(log))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::eth::eth_test_utils::{get_sample_eth_address, get_sample_log_with_erc20_peg_in_event},
        erc20_on_evm::test_utils::get_sample_erc20_vault_log_with_user_data,
    };

    #[test]
    fn should_encode_peg_out_fxn_data_without_user_data() {
        let amount = U256::from(1337);
        let recipient_address =
            EthAddress::from_slice(&hex::decode("edB86cd455ef3ca43f0e227e00469C3bDFA40628").unwrap());
        let token_address = EthAddress::from_slice(&hex::decode("fEDFe2616EB3661CB8FEd2782F5F0cC91D59DCaC").unwrap());
        let expected_result = "83c09d42000000000000000000000000edb86cd455ef3ca43f0e227e00469c3bdfa40628000000000000000000000000fedfe2616eb3661cb8fed2782f5f0cc91d59dcac0000000000000000000000000000000000000000000000000000000000000539";
        let result = hex::encode(
            encode_erc20_vault_peg_out_fxn_data_without_user_data(recipient_address, token_address, amount).unwrap(),
        );
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_encode_peg_out_fxn_data_with_user_data() {
        let user_data = vec![0xde, 0xca, 0xff];
        let amount = U256::from(1337);
        let recipient_address =
            EthAddress::from_slice(&hex::decode("edB86cd455ef3ca43f0e227e00469C3bDFA40628").unwrap());
        let token_address = EthAddress::from_slice(&hex::decode("fEDFe2616EB3661CB8FEd2782F5F0cC91D59DCaC").unwrap());
        let expected_result = "22965469000000000000000000000000edb86cd455ef3ca43f0e227e00469c3bdfa40628000000000000000000000000fedfe2616eb3661cb8fed2782f5f0cc91d59dcac000000000000000000000000000000000000000000000000000000000000053900000000000000000000000000000000000000000000000000000000000000800000000000000000000000000000000000000000000000000000000000000003decaff0000000000000000000000000000000000000000000000000000000000";
        let result = hex::encode(
            encode_erc20_vault_peg_out_fxn_data_with_user_data(recipient_address, token_address, amount, user_data)
                .unwrap(),
        );
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_encode_migrate_fxn_data() {
        let address = EthAddress::from_slice(&hex::decode("edB86cd455ef3ca43f0e227e00469C3bDFA40628").unwrap());
        let expected_result = "ce5494bb000000000000000000000000edb86cd455ef3ca43f0e227e00469c3bdfa40628";
        let result = hex::encode(encode_erc20_vault_migrate_fxn_data(address).unwrap());
        assert_eq!(result, expected_result)
    }

    #[test]
    fn should_encode_erc20_vault_add_supported_token_fx_data() {
        let expected_result = "6d69fcaf0000000000000000000000001739624f5cd969885a224da84418d12b8570d61a";
        let address = get_sample_eth_address();
        let result = encode_erc20_vault_add_supported_token_fx_data(address).unwrap();
        assert_eq!(hex::encode(&result), expected_result);
    }

    #[test]
    fn should_encode_erc20_vault_remove_supported_token_fx_data() {
        let expected_result = "763191900000000000000000000000001739624f5cd969885a224da84418d12b8570d61a";
        let address = get_sample_eth_address();
        let result = encode_erc20_vault_remove_supported_token_fx_data(address).unwrap();
        assert_eq!(hex::encode(&result), expected_result);
    }

    #[test]
    fn should_get_params_from_eth_log_without_user_data() {
        let log = get_sample_log_with_erc20_peg_in_event().unwrap();
        let result = Erc20VaultPegInEventParams::from_eth_log(&log).unwrap();
        let expected_result = Erc20VaultPegInEventParams {
            user_data: vec![],
            token_amount: U256::from_dec_str("1337").unwrap(),
            token_sender: EthAddress::from_slice(&hex::decode(&"fedfe2616eb3661cb8fed2782f5f0cc91d59dcac").unwrap()),
            token_address: EthAddress::from_slice(&hex::decode(&"9f57cb2a4f462a5258a49e88b4331068a391de66").unwrap()),
            destination_address: "aneosaddress".to_string(),
        };
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_params_from_eth_log_with_user_data() {
        // NOTE This is the correct type of log, only the pegin wasn't made with any user data :/
        // FIXME / TODO  Get a real sample WITH some actual user data & test that.
        let log = get_sample_erc20_vault_log_with_user_data();
        let result = Erc20VaultPegInEventParams::from_eth_log(&log).unwrap();
        let expected_result = Erc20VaultPegInEventParams {
            user_data: vec![],
            token_amount: U256::from_dec_str("1000000000000000000").unwrap(),
            token_sender: EthAddress::from_slice(&hex::decode(&"8127192c2e4703dfb47f087883cc3120fe061cb8").unwrap()),
            token_address: EthAddress::from_slice(&hex::decode(&"89ab32156e46f46d02ade3fecbe5fc4243b9aaed").unwrap()),
            // NOTE: This address was from when @bertani accidentally included the `"` chars in the string!
            destination_address: "\"0x8127192c2e4703dfb47f087883cc3120fe061cb8\"".to_string(),
        };
        assert_eq!(result, expected_result);
    }
}
