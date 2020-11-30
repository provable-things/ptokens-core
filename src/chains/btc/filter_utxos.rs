use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::btc::{
        btc_state::BtcState,
        btc_constants::MINIMUM_REQUIRED_SATOSHIS,
        utxo_manager::{
            utxo_utils::utxos_exist_in_db,
            utxo_types::{
                BtcUtxoAndValue,
                BtcUtxosAndValues,
            },
        },
    },
};

pub fn filter_out_utxos_extant_in_db<D>(
    db: &D,
    utxos: &BtcUtxosAndValues
) -> Result<BtcUtxosAndValues>
    where D: DatabaseInterface
{
    utxos_exist_in_db(db, utxos)
        .map(|bool_arr| BtcUtxosAndValues::new(
            utxos
                .0
                .iter()
                .enumerate()
                .filter(|(i, _)| {
                    match !bool_arr[*i] {
                        true => true,
                        false => {
                            info!("✔ Filtering out UTXO because it's already in the db: {:?}", utxos.0[*i]);
                            false
                        }
                    }
                })
                .map(|(_, utxo)| utxo)
                .cloned()
                .collect::<Vec<BtcUtxoAndValue>>()
        ))
}

pub fn filter_out_utxos_whose_value_is_too_low(utxos: &BtcUtxosAndValues) -> Result<BtcUtxosAndValues> {
    Ok(BtcUtxosAndValues::new(
        utxos
            .0
            .iter()
            .filter(|utxo| {
                match utxo.value >= MINIMUM_REQUIRED_SATOSHIS {
                    true => true,
                    false => {
                        info!("✘ Filtering UTXO ∵ value too low: {:?}", utxo);
                        false
                    }
                }
            })
            .cloned()
            .collect::<Vec<BtcUtxoAndValue>>()
    ))
}

pub fn filter_out_utxos_extant_in_db_from_state<D: DatabaseInterface>(state: BtcState<D>) -> Result<BtcState<D>> {
    info!("✔ Maybe filtering out any UTXOs that are already in the DB...");
    filter_out_utxos_extant_in_db(&state.db, &state.utxos_and_values)
        .and_then(|utxos| state.replace_utxos_and_values(utxos))
}

pub fn filter_out_value_too_low_utxos_from_state<D: DatabaseInterface>(state: BtcState<D>) -> Result<BtcState<D>> {
    info!("✔ Maybe filtering out any UTXOs below minimum # of Satoshis...");
    filter_out_utxos_whose_value_is_too_low(&state.utxos_and_values)
        .and_then(|utxos| state.replace_utxos_and_values(utxos))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::btc::{
            btc_test_utils::get_sample_utxo_and_values,
            utxo_manager::utxo_database_utils::save_utxos_to_db,
        },
        test_utils::{
            get_test_database,
            get_random_num_between,
        },
    };

    #[test]
    fn should_filter_utxos() {
        let expected_num_utxos_after_filtering = 3;
        let utxos = get_sample_utxo_and_values();
        let utxos_length_before = utxos.len();
        let result = filter_out_utxos_whose_value_is_too_low(&utxos).unwrap();
        let utxos_length_after = result.len();
        assert!(utxos_length_after < utxos_length_before);
        assert_ne!(utxos_length_before, utxos_length_after);
        assert_eq!(utxos_length_after, expected_num_utxos_after_filtering);
    }

    #[test]
    fn should_filter_out_extant_utxos() {
        let expected_num_utxos_after_filtering = 1;
        let db = get_test_database();
        let all_utxos = get_sample_utxo_and_values();
        let num_utxos = all_utxos.len();
        let random_index = get_random_num_between(0, num_utxos);
        let expected_utxo_after_filtering = all_utxos.0[random_index].clone();
        let mut utxos_to_insert_in_db = all_utxos.clone();
        utxos_to_insert_in_db.0.remove(random_index);
        save_utxos_to_db(&db, &utxos_to_insert_in_db).unwrap();
        let result = filter_out_utxos_extant_in_db(&db, &all_utxos).unwrap();
        assert_eq!(result.len(), expected_num_utxos_after_filtering);
        assert_eq!(result.0[0], expected_utxo_after_filtering);
    }
}
