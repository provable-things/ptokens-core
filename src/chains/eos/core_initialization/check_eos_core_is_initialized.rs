use crate::{chains::eos::eos_crypto::eos_private_key::EosPrivateKey, traits::DatabaseInterface, types::Result};

pub fn is_eos_core_initialized<D: DatabaseInterface>(db: &D) -> bool {
    EosPrivateKey::get_from_db(db).is_ok()
}

pub fn check_eos_core_is_initialized<D: DatabaseInterface>(db: &D) -> Result<()> {
    info!("✔ Checking EOS core is initialized...");
    match is_eos_core_initialized(db) {
        false => Err("✘ EOS side of core not initialized!".into()),
        true => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chains::eos::eos_test_utils::get_sample_eos_private_key,
        errors::AppError,
        test_utils::get_test_database,
    };

    #[test]
    fn should_return_true_if_eos_core_initialized() {
        let db = get_test_database();
        let pk = get_sample_eos_private_key();
        pk.write_to_db(&db).unwrap();
        let result = is_eos_core_initialized(&db);
        assert!(result);
    }

    #[test]
    fn should_return_false_if_eos_core_not_initialized() {
        let db = get_test_database();
        let result = is_eos_core_initialized(&db);
        assert!(!result);
    }

    #[test]
    fn should_be_ok_if_eos_core_initialized() {
        let db = get_test_database();
        let pk = get_sample_eos_private_key();
        pk.write_to_db(&db).unwrap();
        let result = check_eos_core_is_initialized(&db);
        assert!(result.is_ok());
    }

    #[test]
    fn should_err_if_eos_core_not_initialized() {
        let db = get_test_database();
        let expected_err = "✘ EOS side of core not initialized!".to_string();
        match check_eos_core_is_initialized(&db) {
            Err(AppError::Custom(err)) => assert_eq!(err, expected_err),
            Ok(_) => panic!("Should not have succeeded!"),
            Err(_) => panic!("Wrong error received!"),
        }
    }
}
