#![cfg(test)]
use std::{
    sync::Mutex,
    collections::HashMap,
};
use crate::{
    errors::AppError,
    traits::DatabaseInterface,
    types::{
        Bytes,
        Result,
        DataSensitivity,
    },
};

pub static DB_LOCK_ERRROR: &'static str = "✘ Cannot get lock on DB!";

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

    fn put(
        &self,
        key: Bytes,
        value: Bytes,
        _sensitivity: DataSensitivity,
    ) -> Result<()> {
        self
            .0
            .lock()
            .expect(DB_LOCK_ERRROR)
            .insert(key, value);
        Ok(())
    }

    fn delete(&self, key: Bytes) -> Result<()> {
        self
            .0
            .lock()
            .expect(DB_LOCK_ERRROR)
            .remove(&key);
        Ok(())
    }

    fn get(&self, key: Bytes, _sensitivity: DataSensitivity) -> Result<Bytes> {
        match self
            .0
            .lock()
            .expect(DB_LOCK_ERRROR)
            .get(&key) {
                Some(value) => Ok(value.to_vec()),
                None => Err(AppError::Custom(
                    "✘ Cannot find item in database!".to_string()
                ))
            }
    }
}

pub fn get_test_database() -> TestDB {
    TestDB::new()
}
