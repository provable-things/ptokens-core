use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::btc::{
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
    utxos: &[BtcUtxoAndValue]
) -> Result<BtcUtxosAndValues>
    where D: DatabaseInterface
{
    utxos_exist_in_db(db, utxos)
        .map(|bool_arr| {
            utxos
                .iter()
                .enumerate()
                .filter(|(i, _)| {
                    match !bool_arr[*i] {
                        true => true,
                        false => {
                            info!("✔ Filtering out UTXO because it's already in the db: {:?}", utxos[*i]);
                            false
                        }
                    }
                })
                .map(|(_, utxo)| utxo)
                .cloned()
                .collect::<BtcUtxosAndValues>()
        })
}

pub fn filter_out_utxos_whose_value_is_too_low(utxos: &[BtcUtxoAndValue]) -> Result<BtcUtxosAndValues> {
    Ok(
        utxos
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
            .collect::<BtcUtxosAndValues>()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        btc_on_eth::btc::btc_test_utils::get_sample_utxo_and_values,
        chains::btc::utxo_manager::utxo_database_utils::save_utxos_to_db,
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
        let expected_utxo_after_filtering = all_utxos[random_index].clone();
        let mut utxos_to_insert_in_db = all_utxos.clone();
        utxos_to_insert_in_db.remove(random_index);
        save_utxos_to_db(&db, &utxos_to_insert_in_db).unwrap();
        let result = filter_out_utxos_extant_in_db(&db, &all_utxos).unwrap();
        assert_eq!(result.len(), expected_num_utxos_after_filtering);
        assert_eq!(result[0], expected_utxo_after_filtering);
    }
}
