use ethereum_types::Address as EthAddress;
use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::eth::{
        eth_crypto::eth_transaction::EthTransaction,
        eth_contracts::{
            erc777_proxy::{
                ERC777_CHANGE_PNETWORK_BY_PROXY_GAS_LIMIT,
                encode_erc777_proxy_change_pnetwork_fxn_data,
                encode_erc777_proxy_change_pnetwork_by_proxy_fxn_data,
            },
            erc777::{
                ERC777_CHANGE_PNETWORK_GAS_LIMIT,
                encode_erc777_change_pnetwork_fxn_data,
            },
        },
    },
    btc_on_eth::eth::{
        eth_database_utils::{
            get_eth_chain_id_from_db,
            get_eth_gas_price_from_db,
            get_eth_private_key_from_db,
            get_eth_account_nonce_from_db,
            increment_eth_account_nonce_in_db,
            get_erc777_contract_address_from_db,
            get_erc777_proxy_contract_address_from_db,
        },
    },
};

const ZERO_ETH_VALUE: usize = 0;

pub fn get_signed_erc777_change_pnetwork_tx<D>(
    db: &D,
    new_address: EthAddress
) -> Result<String>
    where D: DatabaseInterface
{
    let nonce_before_incrementing = get_eth_account_nonce_from_db(db)?;
    increment_eth_account_nonce_in_db(db, 1)
        .and_then(|_|
            Ok(
                EthTransaction::new_unsigned(
                    encode_erc777_change_pnetwork_fxn_data(new_address)?,
                    nonce_before_incrementing,
                    ZERO_ETH_VALUE,
                    get_erc777_contract_address_from_db(db)?,
                    get_eth_chain_id_from_db(db)?,
                    ERC777_CHANGE_PNETWORK_GAS_LIMIT,
                    get_eth_gas_price_from_db(db)?,
                )
                    .sign(get_eth_private_key_from_db(db)?)?
                    .serialize_hex()
            )
        )
}

pub fn get_signed_erc777_proxy_change_pnetwork_tx<D>(
    db: &D,
    new_address: EthAddress
) -> Result<String>
    where D: DatabaseInterface
{
    let nonce_before_incrementing = get_eth_account_nonce_from_db(db)?;
    increment_eth_account_nonce_in_db(db, 1)
        .and_then(|_|
            Ok(
                EthTransaction::new_unsigned(
                    encode_erc777_proxy_change_pnetwork_fxn_data(new_address)?,
                    nonce_before_incrementing,
                    ZERO_ETH_VALUE,
                    get_erc777_proxy_contract_address_from_db(db)?,
                    get_eth_chain_id_from_db(db)?,
                    ERC777_CHANGE_PNETWORK_GAS_LIMIT,
                    get_eth_gas_price_from_db(db)?,
                )
                    .sign(get_eth_private_key_from_db(db)?)?
                    .serialize_hex()
            )
        )
}

pub fn get_signed_erc777_proxy_change_pnetwork_by_proxy_tx<D>(
    db: &D,
    new_address: EthAddress
) -> Result<String>
    where D: DatabaseInterface
{
    let nonce_before_incrementing = get_eth_account_nonce_from_db(db)?;
    increment_eth_account_nonce_in_db(db, 1)
        .and_then(|_|
            Ok(
                EthTransaction::new_unsigned(
                    encode_erc777_proxy_change_pnetwork_by_proxy_fxn_data(new_address)?,
                    nonce_before_incrementing,
                    ZERO_ETH_VALUE,
                    get_erc777_proxy_contract_address_from_db(db)?,
                    get_eth_chain_id_from_db(db)?,
                    ERC777_CHANGE_PNETWORK_BY_PROXY_GAS_LIMIT,
                    get_eth_gas_price_from_db(db)?,
                )
                    .sign(get_eth_private_key_from_db(db)?)?
                    .serialize_hex()
            )
        )
}
