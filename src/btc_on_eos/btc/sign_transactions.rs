use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::eos::eos_constants::{
        MEMO,
        EOS_MAX_EXPIRATION_SECS,
        PEOS_ACCOUNT_PERMISSION_LEVEL,
    },
    btc_on_eos::{
        btc::{
            btc_state::BtcState,
            btc_types::MintingParamStruct,
            btc_database_utils::get_btc_canon_block_from_db,
        },
        eos::{
            eos_types::{
                EosSignedTransaction,
                EosSignedTransactions,
            },
            eos_crypto::{
                eos_private_key::EosPrivateKey,
                eos_transaction::{
                    sign_peos_transaction,
                    get_unsigned_eos_minting_tx,
                },
            },
            eos_database_utils::{
                get_eos_chain_id_from_db,
                get_eos_account_name_string_from_db,
            },
        },
    },
};

fn get_signed_tx(
    ref_block_num: u16,
    ref_block_prefix: u32,
    to: &str,
    amount: &str,
    chain_id: &str,
    private_key: &EosPrivateKey,
    account_name: &str,
) -> Result<EosSignedTransaction> {
    info!("✔ Signing tx for {} to {}...", &amount, &to);
    get_unsigned_eos_minting_tx(
        to,
        account_name,
        MEMO,
        account_name,
        amount,
        ref_block_num,
        ref_block_prefix,
        EOS_MAX_EXPIRATION_SECS,
        PEOS_ACCOUNT_PERMISSION_LEVEL,
    )
        .and_then(|unsigned_tx|
            sign_peos_transaction(
                to,
                amount,
                chain_id,
                private_key,
                &unsigned_tx,
            )
        )
}

pub fn get_signed_txs(
    ref_block_num: u16,
    ref_block_prefix: u32,
    chain_id: &str,
    private_key: &EosPrivateKey,
    account_name: &str,
    minting_params: &[MintingParamStruct],
) -> Result<EosSignedTransactions> {
    info!("✔ Signing {} txs...", minting_params.len());
    minting_params
        .iter()
        .map(|params|
            get_signed_tx(
                ref_block_num,
                ref_block_prefix,
                &params.to,
                &params.amount,
                chain_id,
                private_key,
                account_name,
            )
        )
        .collect()
}

pub fn maybe_sign_canon_block_txs_and_add_to_state<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe signing minting txs...");
    get_signed_txs(
        state.ref_block_num,
        state.ref_block_prefix,
        &get_eos_chain_id_from_db(&state.db)?,
        &EosPrivateKey::get_from_db(&state.db)?,
        &get_eos_account_name_string_from_db(&state.db)?,
        &get_btc_canon_block_from_db(&state.db)?.minting_params,
    )
        .and_then(|signed_txs| state.add_signed_txs(signed_txs))
}

/*
#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use bitcoin::util::address::Address as BtcAddress;
    use bitcoin_hashes::{
        Hash,
        sha256d,
    };
    use crate::btc_on_eos::{
        test_utils::get_test_database,
        utils::convert_satoshis_to_ptoken,
        btc::{
            btc_types::MintingParamStruct,
            btc_test_utils::SAMPLE_TARGET_BTC_ADDRESS,
        },
        eth::{
            eth_types::EthAddress,
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
        let result = get_signed_txs(
            &signing_params,
            &minting_params,
        ).unwrap();
        assert_eq!(result.len(), minting_params.len());
    }
}
*/
