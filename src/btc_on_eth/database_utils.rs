use crate::{
    traits::DatabaseInterface,
    types::{Byte, Result},
};

pub fn put_u64_in_db<D>(
    db: &D,
    key: &[Byte],
    u_64: u64,
) -> Result<()>
    where D: DatabaseInterface
{
    trace!("✔ Putting `u64` of {} in db...", u_64);
    db.put(key.to_vec(), u_64.to_le_bytes().to_vec(), None)
}

pub fn get_u64_from_db<D>(
    db: &D,
    key: &[Byte]
) -> Result<u64>
    where D: DatabaseInterface
{
    trace!("✔ Getting `u64` from db...");
    db.get(key.to_vec(), None)
        .and_then(|bytes|
            match bytes.len() <= 8 {
                true => {
                    let mut array = [0; 8];
                    let bytes = &bytes[..array.len()];
                    array.copy_from_slice(bytes);
                    Ok(u64::from_le_bytes(array))
                },
                false => Err("✘ Too many bytes to convert to u64!".into())
            }
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_utils::get_test_database;

    #[test]
    fn should_save_and_get_usize_from_db() {
        let key = vec![0xc0, 0xff, 0xee];
        let u_64 = 1337;
        let db = get_test_database();
        if let Err(e) = put_u64_in_db(&db, &key, u_64) {
            panic!("Error saving eth account usize in db: {}", e);
        };
        match get_u64_from_db(&db, &key) {
            Ok(usize_from_db) => {
                assert_eq!(usize_from_db, u_64);
            }
            Err(e) => {
                panic!("Error getting usize from db: {}", e)
            }
        }
    }

    #[test]
    fn should_convert_to_le_bytes_correctly() {
        let expected_result = "000065cd1d000000";
        let x:u64 = 128_000_000_000;
        let result = hex::encode(x.to_le_bytes());
        assert_eq!(result, expected_result);
    }
}
