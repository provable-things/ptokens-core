use crate::constants::BTC_NUM_DECIMALS;

pub fn convert_u64_to_8_decimal_eos_asset(value: u64, token_symbol: &str) -> String {
    let mut amount_string = value.to_string();
    let asset = match amount_string.len() {
        0 => "0.00000000".to_string(),
        1 => format!("0.0000000{}", amount_string),
        2 => format!("0.000000{}", amount_string),
        3 => format!("0.00000{}", amount_string),
        4 => format!("0.0000{}", amount_string),
        5 => format!("0.000{}", amount_string),
        6 => format!("0.00{}", amount_string),
        7 => format!("0.0{}", amount_string),
        8 => format!("0.{}", amount_string),
        _ => {
            amount_string.insert(amount_string.len() - BTC_NUM_DECIMALS, '.');
            amount_string
        },
    };
    format!("{} {}", asset, token_symbol)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn should_convert_u64_to_8_decimal_eos_asset() {
        let symbol = "SAM";
        let expected_results = vec![
            "1234567891.23456789 SAM",
            "123456789.12345678 SAM",
            "12345678.91234567 SAM",
            "1234567.89123456 SAM",
            "123456.78912345 SAM",
            "12345.67891234 SAM",
            "1234.56789123 SAM",
            "123.45678912 SAM",
            "12.34567891 SAM",
            "1.23456789 SAM",
            "0.12345678 SAM",
            "0.01234567 SAM",
            "0.00123456 SAM",
            "0.00012345 SAM",
            "0.00001234 SAM",
            "0.00000123 SAM",
            "0.00000012 SAM",
            "0.00000001 SAM",
            "0.00000000 SAM",
        ];
        vec![
            123456789123456789 as u64,
            12345678912345678 as u64,
            1234567891234567 as u64,
            123456789123456 as u64,
            12345678912345 as u64,
            1234567891234 as u64,
            123456789123 as u64,
            12345678912 as u64,
            1234567891 as u64,
            123456789 as u64,
            12345678 as u64,
            1234567 as u64,
            123456 as u64,
            12345 as u64,
            1234 as u64,
            123 as u64,
            12 as u64,
            1 as u64,
            0 as u64,
        ]
        .iter()
        .map(|u_64| convert_u64_to_8_decimal_eos_asset(*u_64, symbol))
        .zip(expected_results.iter())
        .for_each(|(result, expected_result)| assert_eq!(&result, expected_result));
    }
}
