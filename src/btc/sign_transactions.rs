use ethereum_types::{
    U256,
    Address as EthAddress,
};
use crate::{
    traits::DatabaseInterface,
    types::{
        Result,
    },
    btc::{
        btc_state::BtcState,
        btc_types::MintingParams,
        btc_database_utils::get_btc_canon_block_from_db,
    },
    eth::{
        eth_types::EthTransactions,
        eth_crypto::{
            eth_private_key::EthPrivateKey,
            eth_transaction::get_signed_minting_tx,
        },
        eth_database_utils::{
            get_eth_chain_id_from_db,
            get_eth_gas_price_from_db,
            get_eth_private_key_from_db,
            get_eth_account_nonce_from_db,
            get_eth_smart_contract_address_from_db,
        },
    },
};

fn get_eth_signed_txs(
    signing_params: &EthSigningParams,
    minting_params: &MintingParams,
) -> Result<EthTransactions> {
    trace!("✔ Getting ETH signed transactions...");
    minting_params
        .iter()
        .enumerate()
        .map(|(i, minting_param_struct)| {
            info!(
                "✔ Signing ETH tx for amount: {}, to address: {}",
                minting_param_struct.amount,
                minting_param_struct.eth_address,
            );
            get_signed_minting_tx(
                U256::from(minting_param_struct.amount.clone()),
                signing_params.eth_account_nonce + i as u64,
                signing_params.chain_id,
                signing_params.ptoken_contract_address,
                signing_params.gas_price,
                minting_param_struct.eth_address.clone(),
                signing_params.eth_private_key.clone(),
            )
        })
        .collect::<Result<EthTransactions>>()
}

#[derive(Debug)]
pub struct EthSigningParams {
    chain_id: u8,
    gas_price: u64,
    eth_account_nonce: u64,
    eth_private_key: EthPrivateKey,
    ptoken_contract_address: EthAddress,
}

fn get_signing_params_from_db<D>(
    db: &D,
) -> Result<EthSigningParams>
    where D: DatabaseInterface
{
    trace!("✔ Getting signing params from db...");
    Ok(
        EthSigningParams {
            chain_id:
                get_eth_chain_id_from_db(db)?,
            gas_price:
                get_eth_gas_price_from_db(db)?,
            eth_private_key:
                get_eth_private_key_from_db(db)?,
            eth_account_nonce:
                get_eth_account_nonce_from_db(db)?,
            ptoken_contract_address:
                get_eth_smart_contract_address_from_db(db)?,
        }
    )
}

pub fn maybe_sign_canon_block_transactions_and_add_to_state<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe signing txs...");
    get_eth_signed_txs(
        &get_signing_params_from_db(&state.db)?,
        &get_btc_canon_block_from_db(&state.db)?.minting_params,
    )
        .and_then(|signed_txs| {
            #[cfg(feature="debug")] {
                debug!("✔ Signed transactions: {:?}", signed_txs);
            }
            state.add_eth_signed_txs(signed_txs)
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use bitcoin::util::address::Address as BtcAddress;
    use bitcoin_hashes::{
        Hash,
        sha256d,
    };
    use crate::{
        test_utils::get_test_database,
        utils::convert_satoshis_to_ptoken,
        btc::{
            btc_types::MintingParamStruct,
            btc_test_utils::SAMPLE_TARGET_BTC_ADDRESS,
        },
        eth::{
            eth_test_utils::{
                get_sample_eth_address,
                get_sample_eth_private_key,
            },
            eth_database_utils::{
                put_eth_chain_id_in_db,
                put_eth_gas_price_in_db,
                put_eth_private_key_in_db,
                put_eth_account_nonce_in_db,
                put_eth_smart_contract_address_in_db,
            }
        }
    };

    #[test]
    fn should_get_eth_signing_params() {
        let nonce = 6;
        let chain_id = 2;
        let db = get_test_database();
        let gas_price = 20_000_000_000;
        let contract_address = get_sample_eth_address();
        let eth_private_key = get_sample_eth_private_key();
        if let Err(e) = put_eth_smart_contract_address_in_db(
            &db,
            &contract_address,
        ) {
            panic!("Error putting eth smart contract address in db: {}", e);
        };
        if let Err(e) = put_eth_chain_id_in_db(&db, &chain_id) {
            panic!("Error putting eth chain id in db: {}", e);
        };
        if let Err(e) = put_eth_gas_price_in_db(&db, &gas_price) {
            panic!("Error putting eth gas price in db: {}", e);
        };
        if let Err(e) = put_eth_account_nonce_in_db(&db, &nonce) {
            panic!("Error putting eth account nonce in db: {}", e);
        };
        if let Err(e) = put_eth_private_key_in_db(&db, &eth_private_key) {
            panic!("Error putting eth private key in db: {}", e);
        }
        match get_signing_params_from_db(&db) {
            Ok(signing_params) => {
                assert!(
                    signing_params.chain_id == chain_id &&
                    signing_params.gas_price == gas_price &&
                    signing_params.eth_account_nonce == nonce &&
                    signing_params.eth_private_key == eth_private_key &&
                    signing_params.ptoken_contract_address == contract_address
                );
            }
            Err(e) => {
                panic!("Error getting signing parms from db: {}", e);
            }
        }
    }

    #[test]
    fn should_get_eth_signatures() {
        let signing_params = EthSigningParams {
            chain_id: 1,
            eth_account_nonce: 0,
            gas_price: 20_000_000_000,
            eth_private_key: get_sample_eth_private_key(),
            ptoken_contract_address: get_sample_eth_address(),
        };
        let originating_address = BtcAddress::from_str(
            SAMPLE_TARGET_BTC_ADDRESS
        ).unwrap();
        let recipient_1 = EthAddress::from_slice(&hex::decode(
            "789e39e46117DFaF50A1B53A98C7ab64750f9Ba3",
        ).unwrap());
        let recipient_2 = EthAddress::from_slice(&hex::decode(
            "9360a5C047e8Eb44647f17672638c3bB8e2B8a53",
        ).unwrap());
        let minting_params = vec![
            MintingParamStruct::new(
                convert_satoshis_to_ptoken(1337),
                recipient_1,
                sha256d::Hash::hash(&vec![0xc0]),
                originating_address.clone(),
            ),
            MintingParamStruct::new(
                convert_satoshis_to_ptoken(666),
                recipient_2,
                sha256d::Hash::hash(&vec![0xc0]),
                originating_address,
            ),
        ];
        let result = get_eth_signed_txs(
            &signing_params,
            &minting_params,
        ).unwrap();
        assert!(result.len() == minting_params.len());
    }
}
