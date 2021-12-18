use bitcoin::{blockdata::transaction::Transaction as BtcTransaction, network::constants::Network as BtcNetwork};

use crate::{
    btc_on_eos::eos::redeem_info::BtcOnEosRedeemInfos,
    chains::{
        btc::{
            btc_database_utils::{
                get_btc_address_from_db,
                get_btc_fee_from_db,
                get_btc_network_from_db,
                get_btc_private_key_from_db,
            },
            btc_transaction::create_signed_raw_btc_tx_for_n_input_n_outputs,
            btc_types::{BtcRecipientAndAmount, BtcRecipientsAndAmounts},
            utxo_manager::utxo_utils::get_enough_utxos_to_cover_total,
        },
        eos::eos_state::EosState,
    },
    traits::DatabaseInterface,
    types::Result,
};

fn get_address_and_amounts_from_redeem_infos(redeem_infos: &BtcOnEosRedeemInfos) -> Result<BtcRecipientsAndAmounts> {
    info!("✔ Getting addresses & amounts from redeem params...");
    redeem_infos
        .0
        .iter()
        .map(|params| {
            let recipient_and_amount = BtcRecipientAndAmount::new(&params.recipient[..], params.amount);
            info!(
                "✔ Recipients & amount retrieved from redeem: {:?}",
                recipient_and_amount
            );
            recipient_and_amount
        })
        .collect()
}

fn sign_txs_from_redeem_infos<D: DatabaseInterface>(
    db: &D,
    sats_per_byte: u64,
    btc_network: BtcNetwork,
    redeem_infos: &BtcOnEosRedeemInfos,
) -> Result<BtcTransaction> {
    info!("✔ Getting correct amount of UTXOs...");
    debug!("✔ Network: {}", btc_network);
    debug!("✔ Satoshis per byte: {}", sats_per_byte);
    let utxos_and_values =
        get_enough_utxos_to_cover_total(db, redeem_infos.sum(), redeem_infos.len(), sats_per_byte, vec![].into())?;
    debug!("✔ Retrieved {} UTXOs!", utxos_and_values.len());
    info!("✔ Signing transaction...");
    create_signed_raw_btc_tx_for_n_input_n_outputs(
        sats_per_byte,
        get_address_and_amounts_from_redeem_infos(redeem_infos)?,
        &get_btc_address_from_db(db)?[..],
        get_btc_private_key_from_db(db)?,
        utxos_and_values,
    )
}

pub fn maybe_sign_txs_and_add_to_state<D: DatabaseInterface>(state: EosState<D>) -> Result<EosState<D>> {
    info!("✔ Maybe signing tx(s) from redeem params...");
    match &state.btc_on_eos_redeem_infos.len() {
        0 => {
            info!("✔ No redeem params in state ∴ not signing txs!");
            Ok(state)
        },
        _ => {
            info!("✔ Redeem params in state ∴ signing txs...");
            sign_txs_from_redeem_infos(
                &state.db,
                get_btc_fee_from_db(&state.db)?,
                get_btc_network_from_db(&state.db)?,
                &state.btc_on_eos_redeem_infos,
            )
            .and_then(|signed_tx| {
                #[cfg(feature = "debug")]
                {
                    debug!("✔ Signed transaction: {:?}", signed_tx);
                }
                state.add_btc_on_eos_signed_txs(vec![signed_tx])
            })
        },
    }
}

#[cfg(test)]
mod tests {
    use bitcoin::network::constants::Network as BtcNetwork;

    use super::*;
    use crate::{
        chains::{
            btc::{
                btc_constants::BTC_PRIVATE_KEY_DB_KEY,
                btc_crypto::btc_private_key::BtcPrivateKey,
                btc_database_utils::{put_btc_address_in_db, put_btc_network_in_db},
                btc_test_utils::{get_sample_p2sh_utxo_and_value_2, get_sample_p2sh_utxo_and_value_3},
                btc_utils::get_hex_tx_from_signed_btc_tx,
                utxo_manager::{utxo_database_utils::save_utxos_to_db, utxo_types::BtcUtxosAndValues},
            },
            eos::{eos_action_proofs::EosActionProof, eos_test_utils::get_sample_eos_submission_material_json_n},
        },
        test_utils::get_test_database,
    };

    #[test]
    fn should_get_correct_signed_btc_tx_3() {
        let db = get_test_database();
        let sats_per_byte = 23;
        let btc_network = BtcNetwork::Testnet;
        let btc_address = "mwi6VyZUqwqdu1DtQMruV4UzEqJADZzj6n".to_string();
        let submission_material = get_sample_eos_submission_material_json_n(3);
        let action_proof = EosActionProof::from_json(&submission_material.action_proofs[0]).unwrap();
        let redeem_infos = BtcOnEosRedeemInfos::from_action_proofs(&[action_proof]).unwrap();
        let utxo = get_sample_p2sh_utxo_and_value_2().unwrap();
        save_utxos_to_db(&db, &BtcUtxosAndValues::new(vec![utxo])).unwrap();
        let pk = BtcPrivateKey::from_slice(
            &hex::decode("2cc48e2f9066a0452e73cc7874f3fa8ba5ef705067d64bef627c686baa514336").unwrap(),
            btc_network,
        )
        .unwrap();
        pk.write_to_db(&db, &BTC_PRIVATE_KEY_DB_KEY.to_vec()).unwrap();
        put_btc_network_in_db(&db, btc_network).unwrap();
        put_btc_address_in_db(&db, &btc_address).unwrap();
        let result = sign_txs_from_redeem_infos(&db, sats_per_byte, btc_network, &redeem_infos).unwrap();
        let result_hex = get_hex_tx_from_signed_btc_tx(&result);
        let expected_hex_result = "0100000001f8c70a7ecd6759cae01e96fca12993e5460d80a720d3fcffe2c95816ee29ef40000000008f483045022100a0872343ef2b50d1258443233b8f1e66ba7cfcf79689be7be78da4f8fb217ebc0220626084ef0b7d41f2d06903cd815295a60c225ef8a04ee9a73edced72684af14f0145201729dce0b4e54e39610a95376a8bc96335fd93da68ae6aa27a62d4c282fb1ad3752102babc00d91bacf32c9ed07774e2be9aa3bc63296a858296c2fde390c339551f8dacffffffff0222160000000000001976a9149ae6e42c56f1ea319cfc704ad50db0683015029b88ac2f3a0000000000001976a914b19d7011a6107944209d5ebf9ef31a0fdf3115f188ac00000000";
        assert_eq!(result_hex, expected_hex_result);
    }

    #[test]
    fn should_get_correct_signed_btc_tx_4() {
        let db = get_test_database();
        let sats_per_byte = 23;
        let btc_network = BtcNetwork::Testnet;
        let btc_address = "mwi6VyZUqwqdu1DtQMruV4UzEqJADZzj6n".to_string();
        let submission_material = get_sample_eos_submission_material_json_n(4);
        let action_proof = EosActionProof::from_json(&submission_material.action_proofs[0]).unwrap();
        let redeem_infos = BtcOnEosRedeemInfos::from_action_proofs(&[action_proof]).unwrap();
        let utxo = get_sample_p2sh_utxo_and_value_3().unwrap();
        save_utxos_to_db(&db, &BtcUtxosAndValues::new(vec![utxo])).unwrap();
        let pk = BtcPrivateKey::from_slice(
            &hex::decode("040cc91d329860197e118a1ea26b7ed7042de8f991d0600df9e482c367bb1c45").unwrap(),
            btc_network,
        )
        .unwrap();
        pk.write_to_db(&db, &BTC_PRIVATE_KEY_DB_KEY.to_vec()).unwrap();
        put_btc_network_in_db(&db, btc_network).unwrap();
        put_btc_address_in_db(&db, &btc_address).unwrap();
        let result = sign_txs_from_redeem_infos(&db, sats_per_byte, btc_network, &redeem_infos).unwrap();
        let result_hex = get_hex_tx_from_signed_btc_tx(&result);
        let expected_hex_result = "0100000001d8baf6344ab19575fe40ad81e5ca1fa57345025e40de3975f7d58c7266e7b7a6000000008f48304502210088a40269c4fe59aa8b2d6d0c5eb24f4e5d54879042806ea9140d00f7b4f372f4022077fa2da7c5fd70537d2a2006535f2151e3c9dbe1274664f2c59ba22cacca3c7a014520d11539e07a521c78c20381c98cc546e3ccdd8a5c97f1cffe83ae5537f61a6e39752102f55e923c43236f553424b863b1d589b9b67add4d8c49aeca7e667c4772e7b942acffffffff02b3150000000000001976a9149ae6e42c56f1ea319cfc704ad50db0683015029b88ac469c0000000000001976a914b19d7011a6107944209d5ebf9ef31a0fdf3115f188ac00000000";
        assert_eq!(result_hex, expected_hex_result);
    }
}
