use crate::{
    traits::DatabaseInterface,
    types::{Bytes, DataSensitivity, Result},
};
use rand::Rng;
use std::{collections::HashMap, sync::Mutex};

pub static DB_LOCK_ERRROR: &str = "✘ Cannot get lock on DB!";

pub struct TestDB(pub Mutex<HashMap<Bytes, Bytes>>);

impl TestDB {
    pub fn new() -> Self {
        Self(Mutex::new(HashMap::new()))
    }
}

impl DatabaseInterface for TestDB {
    fn end_transaction(&self) -> Result<()> {
        Ok(())
    }

    fn start_transaction(&self) -> Result<()> {
        Ok(())
    }

    fn put(&self, key: Bytes, value: Bytes, _sensitivity: DataSensitivity) -> Result<()> {
        self.0.lock().expect(DB_LOCK_ERRROR).insert(key, value);
        Ok(())
    }

    fn delete(&self, key: Bytes) -> Result<()> {
        self.0.lock().expect(DB_LOCK_ERRROR).remove(&key);
        Ok(())
    }

    fn get(&self, key: Bytes, _sensitivity: DataSensitivity) -> Result<Bytes> {
        match self.0.lock().expect(DB_LOCK_ERRROR).get(&key) {
            Some(value) => Ok(value.to_vec()),
            None => Err("✘ Cannot find item in database!".into()),
        }
    }
}

pub fn get_test_database() -> TestDB {
    TestDB::new()
}

pub fn get_random_num_between(min: usize, max: usize) -> usize {
    rand::thread_rng().gen_range(min, max)
}

pub fn get_sample_message_to_sign_bytes() -> &'static [u8] {
    b"Provable pToken!"
}
