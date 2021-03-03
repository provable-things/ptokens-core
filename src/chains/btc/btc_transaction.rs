use bitcoin::{
    blockdata::transaction::{Transaction as BtcTransaction, TxIn as BtcUtxo, TxOut as BtcTxOut},
    hashes::sha256d,
};

use crate::{
    chains::btc::{
        btc_crypto::btc_private_key::BtcPrivateKey,
        btc_types::BtcRecipientsAndAmounts,
        btc_utils::{
            calculate_btc_tx_fee,
            create_new_pay_to_pub_key_hash_output,
            create_new_tx_output,
            get_p2sh_redeem_script_sig,
            get_p2sh_script_sig_from_redeem_script,
            get_script_sig,
        },
        deposit_address_info::DepositAddressInfo,
        utxo_manager::utxo_types::BtcUtxosAndValues,
    },
    types::{Bytes, Result},
};

// NOTE: Current tx constants. Could make generic in future if needed.
pub const VERSION: u32 = 1;
pub const LOCK_TIME: u32 = 0;
pub const SIGN_ALL_HASH_TYPE: u8 = 1;

pub fn create_signed_raw_btc_tx_for_n_input_n_outputs(
    sats_per_byte: u64,
    recipient_addresses_and_amounts: BtcRecipientsAndAmounts,
    remainder_btc_address: &str,
    btc_private_key: BtcPrivateKey,
    utxos_and_values: BtcUtxosAndValues,
) -> Result<BtcTransaction> {
    let total_to_spend: u64 = recipient_addresses_and_amounts
        .iter()
        .map(|recipient_and_amount| recipient_and_amount.amount)
        .sum();
    let fee = calculate_btc_tx_fee(
        utxos_and_values.len(),
        recipient_addresses_and_amounts.len(),
        sats_per_byte,
    );
    let utxo_total = utxos_and_values
        .iter()
        .fold(0, |acc, utxo_and_value| acc + utxo_and_value.value);
    info!("✔ UTXO(s) total:  {}", utxo_total);
    info!("✔ Outgoing total: {}", total_to_spend);
    info!("✔ Change amount:  {}", utxo_total - (total_to_spend + fee));
    info!("✔ Tx fee:         {}", fee);
    if total_to_spend + fee > utxo_total {
        return Err("✘ Not enough UTXO value to make transaction!".into());
    };
    let mut outputs = recipient_addresses_and_amounts
        .iter()
        .map(|recipient_and_amount| {
            create_new_tx_output(
                recipient_and_amount.amount,
                recipient_and_amount.recipient.script_pubkey(),
            )
        })
        .flatten()
        .collect::<Vec<BtcTxOut>>();
    let change = utxo_total - total_to_spend - fee;
    if change > 0 {
        outputs.push(create_new_pay_to_pub_key_hash_output(change, remainder_btc_address)?)
    };
    let tx = BtcTransaction {
        output: outputs,
        version: VERSION,
        lock_time: LOCK_TIME,
        input: utxos_and_values
            .0
            .iter()
            .map(|utxo_and_value| utxo_and_value.get_utxo())
            .collect::<Result<Vec<BtcUtxo>>>()?,
    };
    let signatures = utxos_and_values
        .0
        .iter()
        .map(|utxo_and_value| utxo_and_value.get_utxo())
        .enumerate()
        .map(|(i, utxo)| {
            let script = match utxos_and_values.0[i].clone().maybe_deposit_info_json {
                None => {
                    info!("✔ Signing a `p2pkh` UTXO!");
                    utxo?.script_sig
                },
                Some(deposit_info_json) => {
                    info!("✔ Signing a `p2sh` UTXO!");
                    get_p2sh_redeem_script_sig(
                        &btc_private_key.to_public_key_slice(),
                        &DepositAddressInfo::from_json(&deposit_info_json)?.commitment_hash,
                    )
                },
            };
            Ok(tx.signature_hash(i, &script, SIGN_ALL_HASH_TYPE as u32))
        })
        .map(|hash: Result<sha256d::Hash>| Ok(hash?.to_vec()))
        .map(|tx_hash_to_sign: Result<Bytes>| {
            btc_private_key.sign_hash_and_append_btc_hash_type(tx_hash_to_sign?.to_vec(), SIGN_ALL_HASH_TYPE as u8)
        })
        .collect::<Result<Vec<Bytes>>>()?;
    let utxos_with_signatures = utxos_and_values
        .0
        .iter()
        .map(|utxo_and_value| utxo_and_value.get_utxo())
        .enumerate()
        .map(|(i, maybe_utxo)| {
            let utxo = maybe_utxo?;
            let script_sig = match utxos_and_values.0[i].clone().maybe_deposit_info_json {
                None => {
                    info!("✔ Spending a `p2pkh` UTXO!");
                    get_script_sig(&signatures[i], &btc_private_key.to_public_key_slice())
                },
                Some(deposit_info_json) => {
                    info!("✔ Spending a `p2sh` UTXO!");
                    get_p2sh_script_sig_from_redeem_script(
                        &signatures[i],
                        &get_p2sh_redeem_script_sig(
                            &btc_private_key.to_public_key_slice(),
                            &DepositAddressInfo::from_json(&deposit_info_json)?.commitment_hash,
                        ),
                    )
                },
            };
            Ok(BtcUtxo {
                script_sig,
                sequence: utxo.sequence,
                witness: utxo.witness.clone(),
                previous_output: utxo.previous_output,
            })
        })
        .collect::<Result<Vec<BtcUtxo>>>()?;
    Ok(BtcTransaction {
        output: tx.output,
        version: tx.version,
        lock_time: tx.lock_time,
        input: utxos_with_signatures,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::chains::btc::{
        btc_test_utils::{
            get_sample_btc_private_key,
            get_sample_p2pkh_utxo_and_value,
            get_sample_p2pkh_utxo_and_value_n,
            SAMPLE_TARGET_BTC_ADDRESS,
        },
        btc_types::BtcRecipientAndAmount,
        btc_utils::{get_hex_tx_from_signed_btc_tx, get_tx_id_from_signed_btc_tx},
    };

    #[test]
    fn should_serialize_1_input_1_output_tx_correctly() {
        // NOTE: Actual txhash on BTC testnet:
        let expected_tx_id = "ce1d7929ed6039485c3ef4040732fb7908174759831a0bbf5acb8d255036a12c";
        let expected_serialized_tx = "01000000010e8d588f88d5624148070a8cd79508da8cb76625e4fcdb19a5fc996aa843bf04000000006b483045022100967d2fb7f4595102dc85a8f90996b8b46fd51d808ab47311b49e6f1ecdfa333502201ba9bebcacef5a66cb1e207148e368bfc4b7c6a65e241a01564a3062304d8b49012103d2a5e3b162eb580fe2ce023cd5e0dddbb6286923acde77e3e5468314dc9373f7ffffffff0133023300000000001976a9149ae6e42c56f1ea319cfc704ad50db0683015029b88ac00000000";
        let sats_per_byte = 23;
        let recipient_addresses_and_amounts =
            vec![BtcRecipientAndAmount::new("mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM", 3342899).unwrap()];
        let btc_private_key = get_sample_btc_private_key();
        let remainder_btc_address = SAMPLE_TARGET_BTC_ADDRESS;
        let utxos_and_values = BtcUtxosAndValues::new(vec![get_sample_p2pkh_utxo_and_value()]);
        let final_signed_tx = create_signed_raw_btc_tx_for_n_input_n_outputs(
            sats_per_byte,
            recipient_addresses_and_amounts,
            remainder_btc_address,
            btc_private_key,
            utxos_and_values,
        )
        .unwrap();
        let tx_id = get_tx_id_from_signed_btc_tx(&final_signed_tx);
        let result_hex = get_hex_tx_from_signed_btc_tx(&final_signed_tx);
        assert_eq!(result_hex, expected_serialized_tx);
        assert_eq!(tx_id, expected_tx_id);
    }

    #[test]
    fn should_serialize_1_input_2_outputs_tx_correctly() {
        // NOTE: Actual txhash on BTC testnet:
        let expected_tx_id = "02a76498ed723f38d2872416555199c5eeba0357267eb045d44b724ce4a3b3a5";
        let expected_serialized_tx = "0100000001b5f75f17e28fa0edaa8148bc6e255797975e1529d9ad97d790914f7c6be26bb5020000006b483045022100d7f563a7523408d4dd04fc272e98ab8aea900cf0dc872f98eac30873e720bb09022063812e1e45b9bc87f5eca162822082712cd5b3e3aa8ee7fcbe1e729f5a9b9775012103d2a5e3b162eb580fe2ce023cd5e0dddbb6286923acde77e3e5468314dc9373f7ffffffff0239050000000000001976a9149ae6e42c56f1ea319cfc704ad50db0683015029b88ac0fa60e00000000001976a91454102783c8640c5144d039cea53eb7dbb470081488ac00000000";
        let utxos_and_values = BtcUtxosAndValues::new(vec![get_sample_p2pkh_utxo_and_value_n(2).unwrap()]);
        let sats_per_byte = 23;
        let recipient_addresses_and_amounts =
            vec![BtcRecipientAndAmount::new("mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM", 1337).unwrap()];
        let remainder_btc_address = SAMPLE_TARGET_BTC_ADDRESS;
        let btc_private_key = get_sample_btc_private_key();
        let final_signed_tx = create_signed_raw_btc_tx_for_n_input_n_outputs(
            sats_per_byte,
            recipient_addresses_and_amounts,
            remainder_btc_address,
            btc_private_key,
            utxos_and_values,
        )
        .unwrap();
        let tx_id = get_tx_id_from_signed_btc_tx(&final_signed_tx);
        let result_hex = get_hex_tx_from_signed_btc_tx(&final_signed_tx);
        assert_eq!(result_hex, expected_serialized_tx);
        assert_eq!(tx_id, expected_tx_id);
    }

    #[test]
    fn should_serialize_tx_with_n_inputs_and_n_outputs() {
        // NOTE: Actual txhash on BTC testnet:
        let expected_tx_id = "b56be26b7c4f9190d797add929155e979757256ebc4881aaeda08fe2175ff7b5";
        let expected_result = "0100000002637cb89f9647c2de31478d554696fb1878f86fd91e399989747e3c6ff296828f000000006b483045022100f25cf2c01caf78152a4d7ed2acaea70ac4723b32bf69d472a155d4f6f726f79b0220656f96577fbf1a8bb9d12de20c784a21f79db357ebcf53f2f8a35cbe1a4131fa012103d2a5e3b162eb580fe2ce023cd5e0dddbb6286923acde77e3e5468314dc9373f7ffffffff637cb89f9647c2de31478d554696fb1878f86fd91e399989747e3c6ff296828f010000006a473044022057ea8a3669fbec98536019701187ab519f44681186c36f83eac780ac3b08d852022017f806e100c3fedc82dd44615434db9f5c911d1fc0d3ceecb65424bc5ba1c9d4012103d2a5e3b162eb580fe2ce023cd5e0dddbb6286923acde77e3e5468314dc9373f7ffffffff039a020000000000001976a9149ae6e42c56f1ea319cfc704ad50db0683015029b88ac39050000000000001976a91493f36f39571997887fb4eff72d7a96259c34292288ac9fbc0e00000000001976a91454102783c8640c5144d039cea53eb7dbb470081488ac00000000";
        let utxos_and_values = BtcUtxosAndValues::new(vec![
            get_sample_p2pkh_utxo_and_value_n(3).unwrap(),
            get_sample_p2pkh_utxo_and_value_n(4).unwrap(),
        ]);
        let sats_per_byte = 23;
        let btc_private_key = get_sample_btc_private_key();
        let remainder_btc_address = SAMPLE_TARGET_BTC_ADDRESS;
        let recipient_addresses_and_amounts = vec![
            BtcRecipientAndAmount::new("mudzxCq9aCQ4Una9MmayvJVCF1Tj9fypiM", 666).unwrap(),
            BtcRecipientAndAmount::new("mu1FFNnoiMytR5tKGXp6M1XhUZFQd3Mc8n", 1337).unwrap(),
        ];
        let final_signed_tx = create_signed_raw_btc_tx_for_n_input_n_outputs(
            sats_per_byte,
            recipient_addresses_and_amounts,
            remainder_btc_address,
            btc_private_key,
            utxos_and_values,
        )
        .unwrap();
        let tx_id = get_tx_id_from_signed_btc_tx(&final_signed_tx);
        let result_hex = get_hex_tx_from_signed_btc_tx(&final_signed_tx);
        assert_eq!(result_hex, expected_result);
        assert_eq!(tx_id, expected_tx_id);
    }
}
