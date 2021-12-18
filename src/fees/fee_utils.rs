use crate::{
    fees::fee_constants::MAX_FEE_BASIS_POINTS,
    types::Result,
    utils::convert_unix_timestamp_to_human_readable,
};

pub fn get_last_withdrawal_date_as_human_readable_string(timestamp: u64) -> String {
    if timestamp == 0 {
        "Fees have not yet been withdrawn!".to_string()
    } else {
        convert_unix_timestamp_to_human_readable(timestamp)
    }
}

pub fn sanity_check_basis_points_value(basis_points: u64) -> Result<u64> {
    if basis_points <= MAX_FEE_BASIS_POINTS {
        Ok(basis_points)
    } else {
        Err(format!("Error! Basis points exceeds maximum of {}!", MAX_FEE_BASIS_POINTS).into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{errors::AppError, fees::fee_constants::MAX_FEE_BASIS_POINTS};

    #[test]
    fn should_pass_basis_points_sanity_check() {
        let basis_points = MAX_FEE_BASIS_POINTS - 1;
        let result = sanity_check_basis_points_value(basis_points).unwrap();
        assert_eq!(result, basis_points)
    }

    #[test]
    fn should_fail_basis_points_sanity_check() {
        let expected_err = format!("Error! Basis points exceeds maximum of {}!", MAX_FEE_BASIS_POINTS);
        let basis_points = MAX_FEE_BASIS_POINTS + 1;
        match sanity_check_basis_points_value(basis_points) {
            Err(AppError::Custom(err)) => assert_eq!(err, expected_err),
            Ok(_) => panic!("Should not have succeeded!"),
            Err(_) => panic!("Wrong error received!"),
        }
    }
}
