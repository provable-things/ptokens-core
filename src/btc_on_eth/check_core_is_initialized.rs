use crate::{
    types::Result,
    traits::DatabaseInterface,
    btc_on_eth::{
        eth::{
            eth_state::EthState,
            initialize_eth::is_eth_initialized::is_eth_enclave_initialized,
        },
        btc::{
            btc_state::BtcState,
            initialize_btc::is_btc_initialized::is_btc_enclave_initialized,
        },
    },
};

pub fn check_core_is_initialized<D>(
    db: &D
) -> Result<()>
    where D: DatabaseInterface
{
    info!("✔ Checking enclave is initialized...");
    match is_btc_enclave_initialized(db) {
        false => Err("✘ BTC side of enclave not initialized!".into()),
        true => {
            match is_eth_enclave_initialized(db) {
                false => Err("✘ ETH side of enclave not initialized!".into()),
                true => Ok(())
            }
        }
    }
}

// TODO/FIXME Make generic
pub fn check_core_is_initialized_and_return_eth_state<D>(
    state: EthState<D>,
) -> Result<EthState<D>>
    where D: DatabaseInterface
{
    check_core_is_initialized(&state.db)
        .map(|_| state)
}

pub fn check_core_is_initialized_and_return_btc_state<D>(
    state: BtcState<D>,
) -> Result<BtcState<D>>
    where D: DatabaseInterface
{
    check_core_is_initialized(&state.db)
        .map(|_| state)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        errors::AppError,
        test_utils::get_test_database,
        btc_on_eth::{
            btc::{
                btc_test_utils::SAMPLE_TARGET_BTC_ADDRESS,
                btc_database_utils::put_btc_address_in_db,
            },
            eth::{
                eth_database_utils::put_public_eth_address_in_db,
                eth_test_utils::{
                    get_valid_eth_state,
                    get_sample_eth_address,
                },
            },
        },
    };

    #[test]
    fn should_return_false_if_enclave_not_initialized() {
        if check_core_is_initialized(&get_test_database()).is_ok() {
            panic!("Enc should be initialized!");
        }
    }

    #[test]
    fn should_return_true_if_enclave_initialized() {
        let db = get_test_database();
        if let Err(e) = put_btc_address_in_db(
            &db,
            &SAMPLE_TARGET_BTC_ADDRESS.to_string(),
        ) {
            panic!("Error putting pk in db: {}", e);
        };
        if let Err(e) = put_public_eth_address_in_db(
            &db,
            &get_sample_eth_address(),
        ) {
            panic!("Error putting pk in db: {}", e);
        };
        if let Err(e) = check_core_is_initialized(&db) {
            panic!("Error when enc should be initted: {}", e);
        };
    }

    #[test]
    fn should_error_if_btc_enclave_not_initialized() {
        let db = get_test_database();
        let expected_error = "✘ BTC side of enclave not initialized!"
            .to_string();
        if let Err(e) = put_public_eth_address_in_db(
            &db,
            &get_sample_eth_address(),
        ) {
            panic!("Error putting pk in db: {}", e);
        };
        assert!(!is_btc_enclave_initialized(&db));
        match check_core_is_initialized(&db) {
            Ok(_) => {
                panic!("Enc should not be initialized!");
            }
            Err(AppError::Custom(e)) => {
                assert_eq!(e, expected_error);
            }
            Err(e) => {
                panic!("Wrong err recieved: {}", e);
            }
        }
    }

    #[test]
    fn should_error_if_eth_enclave_not_initialized() {
        let db = get_test_database();
        let expected_error = "✘ ETH side of enclave not initialized!"
            .to_string();
        if let Err(e) = put_btc_address_in_db(
            &db,
            &SAMPLE_TARGET_BTC_ADDRESS.to_string(),
        ) {
            panic!("Error putting pk in db: {}", e);
        };
        assert!(
            !is_eth_enclave_initialized(&db)
        );
        match check_core_is_initialized(&db) {
            Ok(_) => {
                panic!("Enc should not be initialized!");
            }
            Err(AppError::Custom(e)) => {
                assert_eq!(e, expected_error);
            }
            Err(e) => {
                panic!("Wrong err recieved: {}", e);
            }
        }
    }

    #[test]
    fn should_check_enclave_initialized_and_return_arg() {
        let state = get_valid_eth_state()
            .unwrap();
        if let Err(e) = put_btc_address_in_db(
            &state.db,
            &SAMPLE_TARGET_BTC_ADDRESS.to_string(),
        ) {
            panic!("Error putting pk in db: {}", e);
        };
        if let Err(e) = put_public_eth_address_in_db(
            &state.db,
            &get_sample_eth_address(),
        ) {
            panic!("Error putting pk in db: {}", e);
        };
        if let Err(e)  = check_core_is_initialized_and_return_eth_state(
            state
        ) {
            panic!("Error when enc should be initted: {}", e);
        }
    }
}
