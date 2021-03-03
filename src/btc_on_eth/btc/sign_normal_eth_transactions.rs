use crate::{
    btc_on_eth::btc::minting_params::BtcOnEthMintingParamStruct,
    chains::{
        btc::{btc_database_utils::get_btc_canon_block_from_db, btc_state::BtcState},
        eth::{
            eth_crypto::eth_transaction::get_signed_minting_tx,
            eth_database_utils::get_signing_params_from_db,
            eth_metadata::{EthMetadataFromBtc, EthMetadataVersion},
            eth_types::{EthSigningParams, EthTransactions},
        },
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn get_eth_signed_txs(
    signing_params: &EthSigningParams,
    minting_params: &[BtcOnEthMintingParamStruct],
) -> Result<EthTransactions> {
    trace!("✔ Getting ETH signed transactions...");
    minting_params
        .iter()
        .enumerate()
        .map(|(i, minting_param_struct)| {
            info!(
                "✔ Signing ETH tx for amount: {}, to address: {}",
                minting_param_struct.amount, minting_param_struct.eth_address,
            );
            get_signed_minting_tx(
                &minting_param_struct.amount,
                signing_params.eth_account_nonce + i as u64,
                signing_params.chain_id,
                signing_params.smart_contract_address,
                signing_params.gas_price,
                &minting_param_struct.eth_address,
                signing_params.eth_private_key.clone(),
                None,
                Some(
                    &EthMetadataFromBtc::from_btc_minting_params(&EthMetadataVersion::V1, minting_param_struct)
                        .serialize()?,
                ),
            )
        })
        .collect::<Result<EthTransactions>>()
}

pub fn maybe_sign_normal_canon_block_txs_and_add_to_state<D>(state: BtcState<D>) -> Result<BtcState<D>>
where
    D: DatabaseInterface,
{
    if state.use_any_sender_tx_type() {
        info!("✔ Using AnySender therefore not signing normal ETH transactions!");
        return Ok(state);
    }
    info!("✔ Maybe signing normal ETH txs...");
    get_eth_signed_txs(
        &get_signing_params_from_db(&state.db)?,
        &get_btc_canon_block_from_db(&state.db)?.get_eth_minting_params(),
    )
    .and_then(|signed_txs| {
        #[cfg(feature = "debug")]
        {
            debug!("✔ Signed transactions: {:?}", signed_txs);
        }
        state.add_eth_signed_txs(signed_txs)
    })
}

#[cfg(test)]
mod tests {
    use std::str::FromStr;

    use bitcoin::util::address::Address as BtcAddress;
    use bitcoin_hashes::{sha256d, Hash};

    use super::*;
    use crate::{
        btc_on_eth::utils::convert_satoshis_to_ptoken,
        chains::{
            btc::btc_test_utils::SAMPLE_TARGET_BTC_ADDRESS,
            eth::{
                eth_database_utils::{
                    put_btc_on_eth_smart_contract_address_in_db,
                    put_eth_account_nonce_in_db,
                    put_eth_chain_id_in_db,
                    put_eth_gas_price_in_db,
                    put_eth_private_key_in_db,
                },
                eth_test_utils::{get_sample_eth_address, get_sample_eth_private_key},
                eth_types::EthAddress,
            },
        },
        test_utils::get_test_database,
    };

    #[test]
    fn should_get_eth_signing_params() {
        let nonce = 6;
        let chain_id = 2;
        let db = get_test_database();
        let gas_price = 20_000_000_000;
        let contract_address = get_sample_eth_address();
        let eth_private_key = get_sample_eth_private_key();
        if let Err(e) = put_btc_on_eth_smart_contract_address_in_db(&db, &contract_address) {
            panic!("Error putting eth smart contract address in db: {}", e);
        };
        if let Err(e) = put_eth_chain_id_in_db(&db, chain_id) {
            panic!("Error putting eth chain id in db: {}", e);
        };
        if let Err(e) = put_eth_gas_price_in_db(&db, gas_price) {
            panic!("Error putting eth gas price in db: {}", e);
        };
        if let Err(e) = put_eth_account_nonce_in_db(&db, nonce) {
            panic!("Error putting eth account nonce in db: {}", e);
        };
        if let Err(e) = put_eth_private_key_in_db(&db, &eth_private_key) {
            panic!("Error putting eth private key in db: {}", e);
        }
        match get_signing_params_from_db(&db) {
            Ok(signing_params) => {
                assert!(
                    signing_params.chain_id == chain_id
                        && signing_params.gas_price == gas_price
                        && signing_params.eth_account_nonce == nonce
                        && signing_params.eth_private_key == eth_private_key
                        && signing_params.smart_contract_address == contract_address
                );
            },
            Err(e) => {
                panic!("Error getting signing parms from db: {}", e);
            },
        }
    }

    #[test]
    fn should_get_eth_signatures() {
        let signing_params = EthSigningParams {
            chain_id: 1,
            eth_account_nonce: 0,
            gas_price: 20_000_000_000,
            eth_private_key: get_sample_eth_private_key(),
            smart_contract_address: get_sample_eth_address(),
        };
        let originating_address = BtcAddress::from_str(SAMPLE_TARGET_BTC_ADDRESS).unwrap();
        let recipient_1 = EthAddress::from_slice(&hex::decode("789e39e46117DFaF50A1B53A98C7ab64750f9Ba3").unwrap());
        let recipient_2 = EthAddress::from_slice(&hex::decode("9360a5C047e8Eb44647f17672638c3bB8e2B8a53").unwrap());
        let minting_params = vec![
            BtcOnEthMintingParamStruct::new(
                convert_satoshis_to_ptoken(1337),
                hex::encode(recipient_1),
                sha256d::Hash::hash(&[0xc0]),
                originating_address.clone(),
            )
            .unwrap(),
            BtcOnEthMintingParamStruct::new(
                convert_satoshis_to_ptoken(666),
                hex::encode(recipient_2),
                sha256d::Hash::hash(&[0xc0]),
                originating_address,
            )
            .unwrap(),
        ];
        let result = get_eth_signed_txs(&signing_params, &minting_params).unwrap();
        assert_eq!(result.len(), minting_params.len());
    }
}
