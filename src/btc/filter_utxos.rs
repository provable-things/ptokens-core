use crate::{
    types::Result,
    traits::DatabaseInterface,
    constants::MINIMUM_REQUIRED_SATOSHIS,
    btc::{
        btc_state::BtcState,
        btc_types::{
            BtcUtxosAndValues,
        },
    },
};

fn filter_utxos(utxos: &BtcUtxosAndValues) -> Result<BtcUtxosAndValues> {
    Ok(
        utxos
            .into_iter()
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

pub fn maybe_filter_utxos_in_state<D>(
    state: BtcState<D>
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    info!("✔ Maybe filtering out any UTXOs below minimum # of Satoshis...");
    filter_utxos(&state.utxos_and_values)
        .and_then(|utxos| state.replace_utxos_and_values(utxos))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::btc::btc_test_utils::get_sample_utxo_and_values;

    #[test]
    fn should_filter_utxos() {
        let expected_num_after_filtering = 3;
        let utxos = get_sample_utxo_and_values();
        let utxos_length_before = utxos.len();
        let result = filter_utxos(&utxos)
            .unwrap();
        let utxos_length_after = result.len();
        assert!(utxos_length_after < utxos_length_before);
        assert_ne!(utxos_length_before, utxos_length_after);
        assert_eq!(utxos_length_after, expected_num_after_filtering);
    }
}
