use bitcoin::{
    util::address::Address as BtcAddress,
    network::constants::Network as BtcNetwork,
    blockdata::transaction::Transaction as BtcTransaction,
};
use crate::{
    types::Result,
    traits::DatabaseInterface,
    utils::convert_satoshis_to_ptoken,
    btc::{
        btc_state::BtcState,
        btc_database_utils::get_btc_network_from_db,
        btc_types::{
            MintingParams,
            BtcTransactions,
            DepositInfoHashMap,
            MintingParamStruct,
        },
    },
};

fn parse_minting_params_from_p2sh_deposit_tx(
    p2sh_deposit_containing_tx: &BtcTransaction,
    deposit_info_hash_map: &DepositInfoHashMap,
    btc_network: BtcNetwork,
) -> Result<MintingParams> {
    info!("✔ Parsing minting params from single `p2sh` transaction...");
    p2sh_deposit_containing_tx
        .output
        .iter()
        .filter(|tx_out| tx_out.script_pubkey.is_p2sh())
        .map(|p2sh_tx_out| {
            match BtcAddress::from_script(
                &p2sh_tx_out.script_pubkey,
                btc_network,
            ) {
                None => {
                    info!(
                        "✘ Could not derive BTC address from tx: {:?}",
                        p2sh_deposit_containing_tx,
                    );
                    None
                }
                Some(btc_address) => {
                    info!(
                        "✔ BTC address extracted from `tx_out`: {}",
                        btc_address,
                    );
                    match deposit_info_hash_map.get(&btc_address) {
                        None => {
                            info!(
                                "✘ BTC address {} not in deposit hash map!",
                                btc_address,
                            );
                            None
                        }
                        Some(deposit_info) => {
                            info!(
                                "✔ Deposit info extracted from hash map: {:?}",
                                deposit_info,
                            );
                            Some(
                                MintingParamStruct::new(
                                    convert_satoshis_to_ptoken(
                                        p2sh_tx_out.value,
                                    ),
                                    deposit_info.eth_address,
                                    p2sh_deposit_containing_tx.txid(),
                                    btc_address,
                                )
                            )
                        }
                    }
                }
            }
        })
        .filter(|maybe_minting_params| maybe_minting_params.is_some())
        .map(|maybe_minting_params| Ok(maybe_minting_params?))
        .collect::<Result<MintingParams>>()
}

fn parse_minting_params_from_p2sh_deposit_txs(
    p2sh_deposit_containing_txs: &BtcTransactions,
    deposit_info_hash_map: &DepositInfoHashMap,
    btc_network: BtcNetwork,
) -> Result<MintingParams> {
    info!("✔ Parsing minting params from `p2sh` transactions...");
    Ok(
        p2sh_deposit_containing_txs
            .iter()
            .flat_map(|tx|
                 parse_minting_params_from_p2sh_deposit_tx(
                     tx,
                     deposit_info_hash_map,
                     btc_network
                 )
            )
            .flatten()
            .collect::<MintingParams>()
   )
}

pub fn parse_minting_params_from_p2sh_deposits_and_add_to_state<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Parsing minting params from `p2sh` deposit txs in state...");
    parse_minting_params_from_p2sh_deposit_txs(
        state.get_p2sh_deposit_txs()?,
        state.get_deposit_info_hash_map()?,
        get_btc_network_from_db(&state.db)?,
    )
        .and_then(|minting_params| state.add_minting_params(minting_params))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::str::FromStr;
    use ethereum_types::H160 as EthAddress;
    use bitcoin::{
        hashes::sha256d,
        util::address::Address as BtcAddress,
    };
    use crate::{
        btc::{
            filter_p2sh_deposit_txs::filter_p2sh_deposit_txs,
            btc_test_utils::{
                get_sample_btc_block_n,
                get_sample_btc_pub_key_bytes,
            },
            get_deposit_info_hash_map::{
                create_hash_map_from_deposit_info_list,
            },
        },
    };

    #[test]
    fn should_parse_minting_params_struct_from_p2sh_deposit_tx() {
        let pub_key = get_sample_btc_pub_key_bytes();
        let expected_amount = convert_satoshis_to_ptoken(10000);
        let expected_num_results = 1;
        let expected_eth_address_bytes = hex::decode(
            "fedfe2616eb3661cb8fed2782f5f0cc91d59dcac"
        ).unwrap();
        let expected_btc_address = "2N2LHYbt8K1KDBogd6XUG9VBv5YM6xefdM2";
        let expected_tx_hash =
            "4d19fed40e7d1944c8590a8a2e21d1f16f65c060244277a3d207770d1c848352";
        let btc_network = BtcNetwork::Testnet;
        let block_and_id = get_sample_btc_block_n(5)
            .unwrap();
        let deposit_address_list = block_and_id
            .deposit_address_list
            .clone();
        let txs = block_and_id
            .block
            .txdata
            .clone();
        let hash_map = create_hash_map_from_deposit_info_list(
            &deposit_address_list
        ).unwrap();
        let tx = filter_p2sh_deposit_txs(
            &hash_map,
            &pub_key[..],
            &txs,
            &btc_network,
        )
            .unwrap()
            [0]
            .clone();
        let result = parse_minting_params_from_p2sh_deposit_tx(
            &tx,
            &hash_map,
            btc_network,
        ).unwrap();
        assert!(result.len() == expected_num_results);
        assert!(result[0].amount == expected_amount);
        assert!(result[0].originating_tx_hash.to_string() == expected_tx_hash);
        assert!(
            result[0].originating_tx_address.to_string() == expected_btc_address
        );
        assert!(
            result[0].eth_address.as_bytes() == &expected_eth_address_bytes[..]
        );
    }

    #[test]
    fn should_parse_minting_params_struct_from_p2sh_deposit_txs() {
        let expected_num_results = 1;
        let expected_amount = convert_satoshis_to_ptoken(10000);
        let expected_eth_address_bytes = hex::decode(
            "fedfe2616eb3661cb8fed2782f5f0cc91d59dcac"
        ).unwrap();
        let expected_btc_address = "2N2LHYbt8K1KDBogd6XUG9VBv5YM6xefdM2";
        let expected_tx_hash =
            "4d19fed40e7d1944c8590a8a2e21d1f16f65c060244277a3d207770d1c848352";
        let btc_network = BtcNetwork::Testnet;
        let block_and_id = get_sample_btc_block_n(5)
            .unwrap();
        let deposit_address_list = block_and_id
            .deposit_address_list
            .clone();
        let txs = block_and_id
            .block
            .txdata
            .clone();
        let hash_map = create_hash_map_from_deposit_info_list(
            &deposit_address_list
        ).unwrap();
        let result = parse_minting_params_from_p2sh_deposit_txs(
            &txs,
            &hash_map,
            btc_network,
        ).unwrap();
        assert!(result.len() == expected_num_results);
        assert!(result[0].amount == expected_amount);
        assert!(result[0].originating_tx_hash.to_string() == expected_tx_hash);
        assert!(
            result[0].originating_tx_address.to_string() == expected_btc_address
        );
        assert!(
            result[0].eth_address.as_bytes() == &expected_eth_address_bytes[..]
        );
    }

    #[test]
    fn should_parse_minting_params_struct_from_two_p2sh_deposit_txs() {
        let expected_num_results = 2;
        let expected_amount_1 = convert_satoshis_to_ptoken(314159);
        let expected_btc_address_1 = BtcAddress::from_str(
            "2NCfNHvNAecRyXPBDaAkfgMLL7NjvPrC6GU"
        ).unwrap();
        let expected_amount_2 = convert_satoshis_to_ptoken(1000000);
        let expected_btc_address_2 = BtcAddress::from_str(
            "2N6DgNSaX3D5rUYXuMM3b5Ujgw4sPrddSHp"
        ).unwrap();
        let expected_eth_address_1 = EthAddress::from_slice(
            &hex::decode("edb86cd455ef3ca43f0e227e00469c3bdfa40628")
                .unwrap()[..]
        );
        let expected_eth_address_2 = EthAddress::from_slice(
            &hex::decode("7344d31d7025f72bd1d3c08645fa6b12d406fc05")
                .unwrap()[..]
        );
        let expected_originating_tx_hash_1 = sha256d::Hash::from_str(
            "ee022f1be2981fbdd51f7c7ac2e07c1233bb7806e481df9c52b8077a628b2ea8"
        ).unwrap();
        let expected_originating_tx_hash_2 = sha256d::Hash::from_str(
            "130a150ff71f8cabf02d4315f7d61f801ced234c7fcc3144d858816033578110"
        ).unwrap();
        let pub_key_bytes = hex::decode(
            "03a3bea6d8d15a38d9c96074d994c788bc1286d557ef5bdbb548741ddf265637ce"
        ).unwrap();
        let expected_result_1 = MintingParamStruct::new(
            expected_amount_1,
            expected_eth_address_1,
            expected_originating_tx_hash_1,
            expected_btc_address_1,
        );
        let expected_result_2 = MintingParamStruct::new(
            expected_amount_2,
            expected_eth_address_2,
            expected_originating_tx_hash_2,
            expected_btc_address_2,
        );
        let btc_network = BtcNetwork::Testnet;
        let block_and_id = get_sample_btc_block_n(6)
            .unwrap();
        let deposit_address_list = block_and_id
            .deposit_address_list
            .clone();
        let txs = block_and_id
            .block
            .txdata
            .clone();
        let hash_map = create_hash_map_from_deposit_info_list(
            &deposit_address_list
        ).unwrap();
        let filtered_txs = filter_p2sh_deposit_txs(
            &hash_map,
            &pub_key_bytes[..],
            &txs,
            &btc_network,
        ).unwrap();
        let result = parse_minting_params_from_p2sh_deposit_txs(
            &filtered_txs,
            &hash_map,
            btc_network,
        ).unwrap();
        let result_1 = result[0].clone();
        let result_2 = result[1].clone();
        assert!(result.len() == expected_num_results);
        assert!(result_1 == expected_result_1);
        assert!(result_2 == expected_result_2);
    }
}
