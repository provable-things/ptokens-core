//! # pToken types.
use crate::errors::AppError;
use std::result;

// NOTE: Temporary, until try_trait is stabilized
pub(crate) use crate::errors::AppError::NoneError;

pub type Bytes = Vec<Byte>;
pub type Result<T> = result::Result<T, AppError>;

pub(crate) type Byte = u8;
pub(crate) type DataSensitivity = Option<u8>;
