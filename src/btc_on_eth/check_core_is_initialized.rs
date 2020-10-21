use crate::{
    types::Result,
    traits::DatabaseInterface,
    chains::eth::{
        eth_state::EthState,
        core_initialization::check_eth_core_is_initialized::is_eth_core_initialized,
    },
    btc_on_eth::btc::{
        btc_state::BtcState,
        initialize_btc::is_btc_initialized::is_btc_enclave_initialized,
    },
};

pub fn check_core_is_initialized<D>(db: &D) -> Result<()> where D: DatabaseInterface {
    info!("✔ Checking core is initialized...");
    match is_btc_enclave_initialized(db) {
        false => Err("✘ BTC core not initialized!".into()),
        true => {
            match is_eth_core_initialized(db) {
                false => Err("✘ ETH core not initialized!".into()),
                true => Ok(())
            }
        }
    }
}

pub fn check_core_is_initialized_and_return_btc_state<D>(
    state: BtcState<D>,
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    check_core_is_initialized(&state.db).and(Ok(state))
}

pub fn check_core_is_initialized_and_return_eth_state<D>(
    state: EthState<D>,
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    check_core_is_initialized(&state.db).and(Ok(state))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        errors::AppError,
        test_utils::get_test_database,
        chains::eth::eth_database_utils::put_public_eth_address_in_db,
        btc_on_eth::{
            eth::eth_test_utils::get_sample_eth_address,
            btc::{
                btc_test_utils::SAMPLE_TARGET_BTC_ADDRESS,
                btc_database_utils::put_btc_address_in_db,
            },
        },
    };

    #[test]
    fn should_return_false_if_enclave_not_initialized() {
        if check_core_is_initialized(&get_test_database()).is_ok() {
            panic!("Core should be initialized!");
        }
    }

    #[test]
    fn should_return_true_if_enclave_initialized() {
        let db = get_test_database();
        if let Err(e) = put_btc_address_in_db(&db, &SAMPLE_TARGET_BTC_ADDRESS) {
            panic!("Error putting pk in db: {}", e);
        };
        if let Err(e) = put_public_eth_address_in_db(&db, &get_sample_eth_address()) {
            panic!("Error putting pk in db: {}", e);
        };
        if let Err(e) = check_core_is_initialized(&db) {
            panic!("Error when enc should be initted: {}", e);
        };
    }

    #[test]
    fn should_error_if_btc_enclave_not_initialized() {
        let db = get_test_database();
        let expected_error = "✘ BTC core not initialized!".to_string();
        if let Err(e) = put_public_eth_address_in_db(&db, &get_sample_eth_address()) {
            panic!("Error putting pk in db: {}", e);
        };
        assert!(!is_btc_enclave_initialized(&db));
        match check_core_is_initialized(&db) {
            Err(AppError::Custom(e)) => assert_eq!(e, expected_error),
            Ok(_) => panic!("Enc should not be initialized!"),
            Err(e) => panic!("Wrong err recieved: {}", e),
        }
    }
}
