use std::str::FromStr;

use bitcoin::hashes::{sha256, Hash};
use eos_chain::{AccountName as EosAccountName, PublicKey as EosProducerKey};
use secp256k1::Message;

use crate::{
    chains::eos::{
        eos_block_header::{EosBlockHeaderV1, EosBlockHeaderV2},
        eos_crypto::{eos_public_key::EosPublicKey, eos_signature::EosSignature},
        eos_producer_key::EosProducerKeyV1,
        eos_producer_schedule::{EosProducerScheduleV1, EosProducerScheduleV2},
        eos_state::EosState,
        protocol_features::WTMSIG_BLOCK_SIGNATURE_FEATURE_HASH,
    },
    constants::{CORE_IS_VALIDATING, DEBUG_MODE, NOT_VALIDATING_WHEN_NOT_IN_DEBUG_MODE_ERROR},
    traits::DatabaseInterface,
    types::{Byte, Bytes, Result},
};

fn create_eos_signing_digest(block_mroot: &[Byte], schedule_hash: &[Byte], block_header_digest: &[Byte]) -> Bytes {
    let hash_1 = sha256::Hash::hash(&[block_header_digest, block_mroot].concat());
    sha256::Hash::hash(&[&hash_1[..], schedule_hash].concat()).to_vec()
}

fn get_block_digest(msig_enabled: bool, block_header: &EosBlockHeaderV2) -> Result<Bytes> {
    match msig_enabled {
        true => Ok(block_header.digest()?.to_bytes().to_vec()),
        false => {
            info!("✔ MSIG not enabled, converting block to contain V1 schedule...");
            Ok(
                convert_v2_schedule_block_header_to_v1_schedule_block_header(block_header)
                    .digest()?
                    .to_bytes()
                    .to_vec(),
            )
        },
    }
}

fn convert_v2_schedule_block_header_to_v1_schedule_block_header(
    v2_block_header: &EosBlockHeaderV2,
) -> EosBlockHeaderV1 {
    EosBlockHeaderV1::new(
        v2_block_header.timestamp,
        v2_block_header.producer,
        v2_block_header.confirmed,
        v2_block_header.previous,
        v2_block_header.transaction_mroot,
        v2_block_header.action_mroot,
        v2_block_header.schedule_version,
        v2_block_header
            .new_producer_schedule
            .as_ref()
            .map(|v2_schedule| convert_v2_schedule_to_v1(&v2_schedule.clone())),
        &v2_block_header.header_extensions,
    )
}

fn convert_v2_schedule_to_v1(v1_schedule: &EosProducerScheduleV2) -> EosProducerScheduleV1 {
    // NOTE Only the first msig key is used in this conversion!
    EosProducerScheduleV1::new(
        v1_schedule.version,
        v1_schedule
            .producers
            .iter()
            .map(|producer| EosProducerKeyV1::new(producer.producer_name, producer.authority.1.keys[0].key.clone()))
            .collect::<Vec<EosProducerKeyV1>>(),
    )
}

fn get_schedule_hash(msig_enabled: bool, v2_schedule: &EosProducerScheduleV2) -> Result<Bytes> {
    let hash = match msig_enabled {
        true => v2_schedule.schedule_hash()?,
        false => convert_v2_schedule_to_v1(v2_schedule).schedule_hash()?,
    };
    Ok(hash.to_bytes().to_vec())
}

fn get_signing_digest(
    msig_enabled: bool,
    block_mroot: &[Byte],
    block_header: &EosBlockHeaderV2,
    v2_schedule: &EosProducerScheduleV2,
) -> Result<Bytes> {
    let block_digest = get_block_digest(msig_enabled, block_header)?;
    let schedule_hash = get_schedule_hash(msig_enabled, v2_schedule)?;
    let signing_digest = create_eos_signing_digest(block_mroot, &schedule_hash, &block_digest);
    debug!("   block mroot: {}", hex::encode(&block_mroot));
    debug!("  block digest: {}", hex::encode(&block_digest));
    debug!(" schedule hash: {}", hex::encode(&schedule_hash));
    debug!("signing digest: {}", hex::encode(&signing_digest));
    debug!(" sched version: {:?}", v2_schedule.version);
    Ok(signing_digest)
}

fn get_signing_key_from_active_schedule(
    block_producer: EosAccountName,
    v2_schedule: &EosProducerScheduleV2,
) -> Result<EosProducerKey> {
    let filtered_keys = v2_schedule
        .producers
        .iter()
        .map(|producer| producer.producer_name)
        .zip(v2_schedule.producers.iter())
        .filter(|(name_from_schedule, _)| *name_from_schedule == block_producer)
        // NOTE/FIXME We're only getting the first key so far.
        .map(|(_, producer)| &producer.authority.1.keys[0].key)
        .cloned()
        .collect::<Vec<EosProducerKey>>();
    match &filtered_keys.len() {
        0 => Err("✘ Could not extract a signing key from active schedule!".into()),
        _ => Ok(filtered_keys[0].clone()), // NOTE: Can this ever be > 1?
    }
}

fn recover_block_signer_public_key(
    msig_enabled: bool,
    block_mroot: &[Byte],
    producer_signature: &str,
    block_header: &EosBlockHeaderV2,
    v2_schedule: &EosProducerScheduleV2,
) -> Result<EosPublicKey> {
    EosPublicKey::recover_from_digest(
        &Message::from_slice(&get_signing_digest(
            msig_enabled,
            block_mroot,
            block_header,
            v2_schedule,
        )?)?,
        &EosSignature::from_str(producer_signature)?,
    )
}

pub fn check_block_signature_is_valid(
    msig_enabled: bool,
    block_mroot: &[Byte],
    producer_signature: &str,
    block_header: &EosBlockHeaderV2,
    v2_schedule: &EosProducerScheduleV2,
) -> Result<()> {
    let signing_key = get_signing_key_from_active_schedule(block_header.producer, v2_schedule)?.to_string();
    let recovered_key =
        recover_block_signer_public_key(msig_enabled, block_mroot, producer_signature, block_header, v2_schedule)?
            .to_string();
    debug!("     Producer: {}", block_header.producer);
    debug!("  Signing key: {}", signing_key);
    debug!("Recovered key: {}", recovered_key);
    match signing_key == recovered_key {
        true => Ok(()),
        _ => Err("✘ Block signature not valid!".into()),
    }
}

pub fn validate_block_header_signature<D>(state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    if !CORE_IS_VALIDATING {
        info!("✔ Skipping EOS block header signature validation");
        match DEBUG_MODE {
            true => Ok(state),
            false => Err(NOT_VALIDATING_WHEN_NOT_IN_DEBUG_MODE_ERROR.into()),
        }
    } else if state.get_eos_block_header()?.new_producer_schedule.is_some() {
        // NOTE/FIXME; To be cleaned up once validation for these has been fixed!
        info!("✔ New producer schedule exists in EOS block ∴ skipping validation check...");
        Ok(state)
    } else {
        info!("✔ Validating EOS block header signature...");
        check_block_signature_is_valid(
            state
                .enabled_protocol_features
                .is_enabled(&WTMSIG_BLOCK_SIGNATURE_FEATURE_HASH.to_vec()),
            &state.incremerkle.get_root().to_bytes().to_vec(),
            &state.producer_signature,
            state.get_eos_block_header()?,
            state.get_active_schedule()?,
        )
        .and(Ok(state))
    }
}

#[cfg(test)]
mod tests {
    use eos_chain::Checksum256;

    use super::*;
    use crate::chains::eos::{
        eos_merkle_utils::Incremerkle,
        eos_test_utils::{
            get_init_and_subsequent_blocks_json_n,
            get_sample_eos_submission_material_json_n,
            get_sample_eos_submission_material_n,
            get_sample_j3_schedule_37,
            get_sample_mainnet_schedule_1713,
            get_sample_v2_schedule,
            EosInitAndSubsequentBlocksJson,
        },
        eos_utils::convert_hex_to_checksum256,
    };

    fn validate_subsequent_block(block_num: usize, blocks_json: &EosInitAndSubsequentBlocksJson) {
        println!("Checking subsequent block #{} is valid...", block_num);
        let msig_enabled = blocks_json.is_msig_enabled();
        let producer_signature = blocks_json.get_producer_signature_for_block_n(block_num).unwrap();
        let block_header = blocks_json.get_block_n(block_num).unwrap();
        let active_schedule = blocks_json.init_block.active_schedule.clone();
        let block_mroot = blocks_json.get_block_mroot_for_block_n(block_num).unwrap();
        if let Err(e) = check_block_signature_is_valid(
            msig_enabled,
            &block_mroot,
            &producer_signature,
            &block_header,
            &active_schedule,
        ) {
            panic!("Subsequent block num {} not valid: {}", block_num, e);
        }
    }

    #[test]
    fn should_get_block_digest() {
        let msig_enabled = true;
        let expected_result = hex::decode("3f1fc3e079cb5120749aecdb3803ce13035f14fa5878122d0f6fe170c314b5a7").unwrap();
        let submission_material = get_sample_eos_submission_material_n(1);
        let result = get_block_digest(msig_enabled, &submission_material.block_header).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_schedule_hash_msig_disabled() {
        let msig_enabled = false;
        let expected_result = hex::decode("d21c31828d933975965bf58a8bf53b4a9a104600e149ff831071f59efb6e8796").unwrap();
        let active_schedule = get_sample_v2_schedule().unwrap();
        let result = get_schedule_hash(msig_enabled, &active_schedule).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_get_schedule_hash_msig_enabled() {
        let msig_enabled = true;
        let expected_result = hex::decode("a722944989081591e0b9742e3065206251a0041e4480cd6a6642ce929f255194").unwrap();
        let active_schedule = get_sample_v2_schedule().unwrap();
        let result = get_schedule_hash(msig_enabled, &active_schedule).unwrap();
        assert_eq!(result, expected_result);
    }

    #[test]
    fn should_validate_initial_and_subequent_jungle_3_blocks() {
        let blocks_json = get_init_and_subsequent_blocks_json_n(1).unwrap();
        blocks_json.init_block.validate();
        vec![0; blocks_json.num_subsequent_blocks()]
            .iter()
            .enumerate()
            .for_each(|(i, _)| validate_subsequent_block(i + 1, &blocks_json));
    }

    #[test]
    fn should_validate_initial_and_subequent_mainnet_blocks() {
        let blocks_json = get_init_and_subsequent_blocks_json_n(2).unwrap();
        blocks_json.init_block.validate();
        vec![0; blocks_json.num_subsequent_blocks()]
            .iter()
            .enumerate()
            .for_each(|(i, _)| validate_subsequent_block(i + 1, &blocks_json));
    }

    #[ignore] // TODO: Fix this test
    #[test]
    fn should_validate_mainnet_block_with_new_producers() {
        // simple_logger::init().unwrap();
        let submission_material_num = 8;
        let submission_material = get_sample_eos_submission_material_n(submission_material_num);
        let submission_material_json = get_sample_eos_submission_material_json_n(submission_material_num);
        let blockroot_merkle = vec![
            "07763257699ad91ee8203419112afadc99d199d36eecfbcaa55540b26fa3a407",
            "ce4b15cbd132697431858839e314dd7d58d57ef7ac81c09b07394aa311389ae1",
            "08b59231faef395eacde8b3d9f7929a95600262eb9019c7daec9a7dc33b5ccff",
            "1b7695c61dcb94d9ad95994f60a328d3b51838c590a1bd38516659db35d48a68",
            "c5292346bca5450e536f110e32c39031956516ca8b9d9cd8aaed3793affc755a",
            "9a9191bc1b21200cdd754540fb362c5590a2d3465974958b7f8f2563578e9717",
            "0ced749aac2af82f5aa8a2ed1acec348e047ab2a3297fd53745ad035c7c5b2b0",
            "fab53e764872c8bb38a7d32560ba3c3f74d6d548068a83a5fa4a39f95e54fb1c",
            "391c0f30f4540da77ef1eec28cdf8f3aa946ada4b8e33437f12752935e15fc4e",
            "a898585a19f8e2b7784b62332497584559a060ebf7053a222c94b5f1d09ba086",
            "7dafe2596164d6b05731e1f9800466c9bd7fbd4cbc255625e125a27323f23d28",
            "1a006e0c1ab25c23dfe46eeeaa0ccf75e566c4e62e79a5a8cfe89910a00d1dcc",
            "6480cbe40d9ea3b218f7c3a02a755150229097e92be39b8644fc3bc430943f00",
            "4fbd698b322c014491e8049dac6de99a6c9bcce7a75ce0d158c6db2148f8fd08",
            "bb9510acd010b1fa793869b71c6cbe5095a03f9a093c2e2ce88af15b0a62e293",
            "13a8e892cdb0b99194176f09e742f137bc46b4fd5c83ef27921241e9a5d54740",
            "caa64b849f848f0122e5ad1f0fd6979c85572467e7061ffb371e5c1f0f51b2b1",
        ]
        .iter()
        .map(convert_hex_to_checksum256)
        .collect::<Result<Vec<Checksum256>>>()
        .unwrap();
        let node_count = submission_material.block_header.block_num() - 1;
        let block_mroot = Incremerkle::new(node_count.into(), blockroot_merkle)
            .get_root()
            .as_bytes()
            .to_vec();
        let msig_enabled = false;
        let producer_signature = submission_material_json.block_header.producer_signature;
        let block_header = submission_material.block_header;
        let active_schedule = get_sample_mainnet_schedule_1713().unwrap();
        if let Err(e) = check_block_signature_is_valid(
            msig_enabled,
            &block_mroot,
            &producer_signature,
            &block_header,
            &active_schedule,
        ) {
            panic!("Mainnet block w/ schedule signature not valid: {}", e);
        }
    }

    #[ignore] // TODO: Fix this test
    #[test]
    fn should_validate_jungle_3_block_with_new_producers() {
        // simple_logger::init().unwrap();
        let submission_material_num = 9;
        let submission_material = get_sample_eos_submission_material_n(submission_material_num);
        let submission_material_json = get_sample_eos_submission_material_json_n(submission_material_num);
        let blockroot_merkle = vec![
            "0faf171fd0e46c146d51c83e2d5364344221db22b5ad400fa54c0842b55eb8ce",
            "ad3514ed548a8292590d1725782206cde321fe58bca92b1660fe9608dd96ad6d",
            "abe96721b9ec88313bbf3149efd0af60760ae461410f8b8d012f3022d4a7d017",
            "5fb63649eece93dce92d0f2825094a6dc00b937f003fe0db7caaeff78a729d56",
            "562e492839d129f0bd144d1495f4979dedbe432b74030a236fb7d64b464a6740",
            "639c4ef56abde7efc67104f6fcc1b94379e3d51b1def8cd8fd16a02fae949226",
            "8ae24f840b2bbb7c217f1c23ef71d88d001aaf33763f05e02b237bd38680f647",
            "9292a3e4f9af07c619ba70ca31f8aef64bae7a31154369544f32874b416b2dad",
            "1db45036e746ddde8051425bb462ea6639f4ec751ee0ef18abbe4d8ada53d0fc",
        ]
        .iter()
        .map(convert_hex_to_checksum256)
        .collect::<Result<Vec<Checksum256>>>()
        .unwrap();
        let node_count = submission_material.block_header.block_num() - 1;
        let block_mroot = Incremerkle::new(node_count.into(), blockroot_merkle)
            .get_root()
            .as_bytes()
            .to_vec();
        let msig_enabled = true;
        let producer_signature = submission_material_json.block_header.producer_signature;
        let block_header = submission_material.block_header;
        let active_schedule = get_sample_j3_schedule_37().unwrap();
        if let Err(e) = check_block_signature_is_valid(
            msig_enabled,
            &block_mroot,
            &producer_signature,
            &block_header,
            &active_schedule,
        ) {
            panic!("Jungle3 block w/ schedule signature not valid: {}", e);
        }
    }
}
