use std::result;
use crate::{
    errors::AppError,
};

pub type Byte = u8;
pub type Bytes = Vec<Byte>;
pub type DataSensitivity = Option<u8>;
pub type Result<T> = result::Result<T, AppError>;
pub type Sha256HashedMessage = secp256k1::Message;
