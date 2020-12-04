use crate::{
    chains::eos::{
        eos_crypto::eos_private_key::EosPrivateKey,
        eos_database_utils::{
            get_eos_schedule_from_db,
            get_incremerkle_from_db,
            get_latest_eos_block_number,
            put_eos_account_name_in_db,
            put_eos_account_nonce_in_db,
            put_eos_chain_id_in_db,
            put_eos_known_schedules_in_db,
            put_eos_last_seen_block_id_in_db,
            put_eos_last_seen_block_num_in_db,
            put_eos_public_key_in_db,
            put_eos_schedule_in_db,
            put_eos_token_symbol_in_db,
            put_incremerkle_in_db,
            put_processed_tx_ids_in_db,
        },
        eos_erc20_dictionary::{EosErc20Dictionary, EosErc20DictionaryJson},
        eos_merkle_utils::Incremerkle,
        eos_state::EosState,
        eos_types::{Checksum256s, EosBlockHeaderJson, EosKnownSchedules, ProcessedTxIds},
        eos_utils::convert_hex_to_checksum256,
        parse_eos_schedule::{convert_v2_schedule_json_to_v2_schedule, EosProducerScheduleJsonV2},
        parse_submission_material::parse_eos_block_header_from_json,
        protocol_features::{EnabledFeatures, WTMSIG_BLOCK_SIGNATURE_FEATURE_HASH},
        validate_signature::check_block_signature_is_valid,
    },
    constants::CORE_IS_VALIDATING,
    traits::DatabaseInterface,
    types::{Bytes, Result},
};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EosInitJson {
    pub block: EosBlockHeaderJson,
    pub blockroot_merkle: Vec<String>,
    pub active_schedule: EosProducerScheduleJsonV2,
    pub maybe_protocol_features_to_enable: Option<Vec<String>>,
    pub erc20_on_eos_token_dictionary: Option<EosErc20DictionaryJson>,
}

impl EosInitJson {
    pub fn from_json_string(json_string: &str) -> Result<Self> {
        match serde_json::from_str(&json_string) {
            Ok(result) => Ok(result),
            Err(err) => Err(err.into()),
        }
    }

    #[cfg(test)]
    pub fn validate(&self) {
        use eos_primitives::Checksum256;
        let msig_enabled = match &self.maybe_protocol_features_to_enable {
            None => false,
            Some(features) => features.contains(&hex::encode(WTMSIG_BLOCK_SIGNATURE_FEATURE_HASH)),
        };
        let schedule = convert_v2_schedule_json_to_v2_schedule(&self.active_schedule).unwrap();
        let block_header = parse_eos_block_header_from_json(&self.block).unwrap();
        let blockroot_merkle = self
            .blockroot_merkle
            .iter()
            .map(convert_hex_to_checksum256)
            .collect::<Result<Vec<Checksum256>>>()
            .unwrap();
        let producer_signature = self.block.producer_signature.clone();
        let incremerkle = Incremerkle::new((block_header.block_num() - 1).into(), blockroot_merkle);
        let block_mroot = incremerkle.get_root().to_bytes().to_vec();
        debug!("block mroot: {}", hex::encode(&block_mroot));
        if check_block_signature_is_valid(
            msig_enabled,
            &block_mroot,
            &producer_signature,
            &block_header,
            &schedule,
        )
        .is_err()
        {
            panic!("Could not validate init block!");
        }
    }
}

pub fn maybe_enable_protocol_features_and_return_state<D>(
    maybe_protocol_features_to_enable: &Option<Vec<String>>,
    state: EosState<D>,
) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    match maybe_protocol_features_to_enable {
        None => {
            info!("✘ No protocol features to enable: Skipping!");
            Ok(state)
        },
        Some(feature_hash_strings) => {
            info!("✔ Maybe enabling {} protocol features...", feature_hash_strings.len());
            let mut feature_hashes = feature_hash_strings
                .iter()
                .map(|hex| Ok(hex::decode(hex)?))
                .collect::<Result<Vec<Bytes>>>()?;
            EnabledFeatures::init()
                .enable_multi(&state.db, &mut feature_hashes)
                .and_then(|features| state.add_enabled_protocol_features(features))
        },
    }
}

pub fn test_block_validation_and_return_state<D>(
    block_json: &EosBlockHeaderJson,
    state: EosState<D>,
) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    if CORE_IS_VALIDATING {
        info!("✔ Checking block validation passes...");
        check_block_signature_is_valid(
            state
                .enabled_protocol_features
                .is_enabled(&WTMSIG_BLOCK_SIGNATURE_FEATURE_HASH.to_vec()),
            &get_incremerkle_from_db(&state.db)?.get_root().to_bytes().to_vec(),
            &block_json.producer_signature,
            &parse_eos_block_header_from_json(&block_json)?,
            &get_eos_schedule_from_db(&state.db, block_json.schedule_version)?,
        )
        .and(Ok(state))
    } else {
        info!("✔ Skipping EOS init block validation check!");
        Ok(state)
    }
}

pub fn generate_and_put_incremerkle_in_db<D>(db: &D, blockroot_merkle: &[String]) -> Result<()>
where
    D: DatabaseInterface,
{
    info!("✔ Generating and putting incremerkle in db...");
    put_incremerkle_in_db(
        db,
        &Incremerkle::new(
            get_latest_eos_block_number(db)? - 1,
            blockroot_merkle
                .iter()
                .map(convert_hex_to_checksum256)
                .collect::<Result<Checksum256s>>()?,
        ),
    )
}

pub fn generate_and_put_incremerkle_in_db_and_return_state<D>(
    blockroot_merkle: &[String],
    state: EosState<D>,
) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    generate_and_put_incremerkle_in_db(&state.db, &blockroot_merkle).and(Ok(state))
}

pub fn put_eos_latest_block_info_in_db<D>(db: &D, block_json: &EosBlockHeaderJson) -> Result<()>
where
    D: DatabaseInterface,
{
    info!(
        "✔ Putting latest block number '{}' & ID '{}' into db...",
        &block_json.block_num, &block_json.block_id
    );
    put_eos_last_seen_block_num_in_db(db, block_json.block_num)
        .and_then(|_| put_eos_last_seen_block_id_in_db(db, &convert_hex_to_checksum256(block_json.block_id.clone())?))
}

pub fn put_eos_latest_block_info_in_db_and_return_state<D>(
    block_json: &EosBlockHeaderJson,
    state: EosState<D>,
) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    put_eos_latest_block_info_in_db(&state.db, block_json).and(Ok(state))
}

pub fn put_eos_known_schedule_in_db_and_return_state<D>(
    schedule_json: &EosProducerScheduleJsonV2,
    state: EosState<D>,
) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Putting EOS known schedule into db...");
    convert_v2_schedule_json_to_v2_schedule(schedule_json)
        .map(|sched| EosKnownSchedules::new(sched.version))
        .and_then(|sched| put_eos_known_schedules_in_db(&state.db, &sched))
        .and(Ok(state))
}

pub fn put_eos_schedule_in_db_and_return_state<D>(
    schedule_json: &EosProducerScheduleJsonV2,
    state: EosState<D>,
) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Putting EOS schedule into db...");
    convert_v2_schedule_json_to_v2_schedule(schedule_json)
        .and_then(|schedule| put_eos_schedule_in_db(&state.db, &schedule))
        .and(Ok(state))
}

pub fn generate_and_save_eos_keys_and_return_state<D>(state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Generating EOS keys & putting into db...");
    let private_key = EosPrivateKey::generate_random()?;
    put_eos_public_key_in_db(&state.db, &private_key.to_public_key())
        .and_then(|_| private_key.write_to_db(&state.db))
        .and(Ok(state))
}

pub fn get_eos_init_output<D>(_state: EosState<D>) -> Result<String>
where
    D: DatabaseInterface,
{
    Ok("{eos_core_initialized:true}".to_string())
}

pub fn put_eos_account_name_in_db_and_return_state<D>(account_name: &str, state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Putting EOS account name '{}' into db...", account_name);
    put_eos_account_name_in_db(&state.db, &account_name).and(Ok(state))
}

pub fn put_eos_account_nonce_in_db_and_return_state<D>(state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Putting EOS account nonce in db...");
    put_eos_account_nonce_in_db(&state.db, 0).and(Ok(state))
}

pub fn put_eos_token_symbol_in_db_and_return_state<D>(token_symbol: &str, state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Putting EOS token symbol '{}' into db...", token_symbol);
    put_eos_token_symbol_in_db(&state.db, &token_symbol).and(Ok(state))
}

pub fn put_empty_processed_tx_ids_in_db_and_return_state<D>(state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Initializing EOS processed tx ids & putting into db...");
    put_processed_tx_ids_in_db(&state.db, &ProcessedTxIds::init()).and(Ok(state))
}

pub fn put_eos_chain_id_in_db_and_return_state<D>(chain_id: &str, state: EosState<D>) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    info!("✔ Putting EOS chain ID '{}' into db...", chain_id);
    put_eos_chain_id_in_db(&state.db, chain_id).and(Ok(state))
}
pub fn maybe_put_erc20_dictionary_in_db_and_return_state<D>(
    init_json: &EosInitJson,
    state: EosState<D>,
) -> Result<EosState<D>>
where
    D: DatabaseInterface,
{
    match init_json.erc20_on_eos_token_dictionary {
        None => {
            info!("✔ No `EosErc20DictionaryJson` in `init-json` ∴ doing nothing!");
            Ok(state)
        },
        Some(ref dictionary_json) => {
            info!("✔ `EosErc20Dictionary` in `init-json` ∴ putting it in db...");
            EosErc20Dictionary::from_json(dictionary_json)
                .and_then(|dict| dict.save_to_db(&state.db))
                .and(Ok(state))
        },
    }
}

#[cfg(test)]
mod tests {
    use crate::btc_on_eos::eos::eos_test_utils::{
        get_j3_init_json_n,
        get_mainnet_init_json_n,
        get_sample_mainnet_init_json_with_erc20_dictionary,
        NUM_J3_INIT_SAMPLES,
        NUM_MAINNET_INIT_SAMPLES,
    };

    #[test]
    fn should_validate_jungle_3_init_blocks() {
        vec![0; NUM_J3_INIT_SAMPLES].iter().enumerate().for_each(|(i, _)| {
            println!("Validating jungle 3 init block #{}...", i + 1);
            get_j3_init_json_n(i + 1).unwrap().validate();
        });
    }

    #[test]
    fn should_validate_mainnet_init_blocks() {
        vec![0; NUM_MAINNET_INIT_SAMPLES].iter().enumerate().for_each(|(i, _)| {
            println!("Validating mainnet init block #{}...", i + i);
            get_mainnet_init_json_n(i + 1).unwrap().validate();
        });
    }

    #[test]
    fn should_parse_init_json_with_erc20_dictionary() {
        let init_json_with_erc20_dictionary = get_sample_mainnet_init_json_with_erc20_dictionary();
        assert!(init_json_with_erc20_dictionary.is_ok());
    }
}
