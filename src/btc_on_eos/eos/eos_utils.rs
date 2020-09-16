use crate::{
    types::Bytes,
    chains::eos::eos_constants::EOS_SCHEDULE_DB_PREFIX,
};

pub fn get_eos_schedule_db_key(version: u32) -> Bytes {
    format!("{}{}", EOS_SCHEDULE_DB_PREFIX, version).as_bytes().to_vec()
}
