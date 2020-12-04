use crate::{
    btc_on_eth::btc::minting_params::BtcOnEthMintingParamStruct,
    chains::{
        btc::{btc_database_utils::get_btc_canon_block_from_db, btc_state::BtcState},
        eth::{
            any_sender::relay_transaction::RelayTransaction,
            eth_database_utils::get_any_sender_signing_params_from_db,
            eth_types::{AnySenderSigningParams, RelayTransactions},
        },
    },
    traits::DatabaseInterface,
    types::Result,
};

pub fn get_any_sender_signed_txs(
    signing_params: &AnySenderSigningParams,
    minting_params: &[BtcOnEthMintingParamStruct],
) -> Result<RelayTransactions> {
    trace!("✔ Getting AnySender signed transactions...");
    minting_params
        .iter()
        .enumerate()
        .map(|(i, minting_param_struct)| {
            info!(
                "✔ Signing AnySender tx for amount: {}, to address: {}",
                minting_param_struct.amount, minting_param_struct.eth_address,
            );

            let any_sender_nonce = signing_params.any_sender_nonce + i as u64;

            RelayTransaction::new_mint_by_proxy_tx(
                signing_params.chain_id,
                signing_params.public_eth_address,
                minting_param_struct.amount,
                any_sender_nonce,
                &signing_params.eth_private_key,
                signing_params.erc777_proxy_address,
                minting_param_struct.eth_address,
            )
        })
        .collect::<Result<RelayTransactions>>()
}

pub fn maybe_sign_any_sender_canon_block_txs_and_add_to_state<D>(state: BtcState<D>) -> Result<BtcState<D>>
where
    D: DatabaseInterface,
{
    if !state.use_any_sender_tx_type() {
        info!("✔ Using normal ETH therefore not signing AnySender transactions!");
        return Ok(state);
    }

    info!("✔ Maybe signing AnySender txs...");

    get_any_sender_signed_txs(
        &get_any_sender_signing_params_from_db(&state.db)?,
        &get_btc_canon_block_from_db(&state.db)?.get_eth_minting_params(),
    )
    .and_then(|signed_txs| {
        #[cfg(feature = "debug")]
        {
            debug!("✔ Signed AnySender transactions: {:?}", signed_txs);
        }
        state.add_any_sender_signed_txs(signed_txs)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        btc_on_eth::{
            btc::minting_params::BtcOnEthMintingParamStruct,
            eth::eth_test_utils::{get_sample_eth_address, get_sample_eth_private_key},
            utils::convert_satoshis_to_ptoken,
        },
        chains::{btc::btc_test_utils::SAMPLE_TARGET_BTC_ADDRESS, eth::eth_types::EthAddress},
    };
    use bitcoin::util::address::Address as BtcAddress;
    use bitcoin_hashes::{sha256d, Hash};
    use std::str::FromStr;

    #[test]
    fn should_get_any_sender_signatures() {
        let signing_params = AnySenderSigningParams {
            chain_id: 1,
            any_sender_nonce: 0,
            eth_private_key: get_sample_eth_private_key(),
            public_eth_address: get_sample_eth_address(),
            erc777_proxy_address: get_sample_eth_address(),
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
        let result = get_any_sender_signed_txs(&signing_params, &minting_params).unwrap();
        assert_eq!(result.len(), minting_params.len());
    }
}
