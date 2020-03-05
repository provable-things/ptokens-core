use hex;
use log;
use std::fmt;
use serde_json;
use std::error::Error;

#[derive(Debug)]
pub enum AppError {
    Custom(String),
    IOError(std::io::Error),
    HexError(hex::FromHexError),
    CryptoError(secp256k1::Error),
    Base58Error(crate::base58::Error),
    SerdeJsonError(serde_json::Error),
    NoneError(std::option::NoneError),
    FromUtf8Error(std::str::Utf8Error),
    SetLoggerError(log::SetLoggerError),
    ParseIntError(std::num::ParseIntError),
    BitcoinHexError(bitcoin_hashes::hex::Error),
    SystemTimeError(std::time::SystemTimeError),
    FromSliceError(std::array::TryFromSliceError),
    BitcoinHashError(bitcoin_hashes::error::Error),
    BitcoinError(bitcoin::consensus::encode::Error),
    BitcoinAddressError(bitcoin::util::address::Error),
}

impl fmt::Display for AppError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            AppError::Custom(ref msg) =>
                format!("{}", msg),
            AppError::HexError(ref e) =>
                format!("✘ Hex Error!\n✘ {}", e),
            AppError::IOError(ref e) =>
                format!("✘ I/O Error!\n✘ {}", e),
            AppError::CryptoError(ref e) =>
                format!("✘ Crypto Error!\n✘ {}", e),
            AppError::Base58Error(ref e) =>
                format!("✘ Base58 Error!\n✘ {}", e),
            AppError::BitcoinError(ref e) =>
                format!("✘ Bitcoin Error!\n✘ {}", e),
            AppError::SerdeJsonError(ref e) =>
                format!("✘ Serde-Json Error!\n✘ {}", e),
            AppError::BitcoinHexError(ref e) =>
                format!("✘ Bitcoin Hex Error!\n✘ {}", e),
            AppError::ParseIntError(ref e) =>
                format!("✘ Parse Int Error!\n✘ {:?}", e),
            AppError::SystemTimeError(ref e) =>
                format!("✘ System Time Error!\n✘ {}", e),
            AppError::BitcoinHashError(ref e) =>
                format!("✘ Bitcoin Hash Error!\n✘ {}", e),
            AppError::FromUtf8Error(ref e) =>
                format!("✘ From utf8 error: \n✘ {:?}", e),
            AppError::FromSliceError(ref e) =>
                format!("✘ From slice error: \n✘ {:?}", e),
            AppError::NoneError(ref e) =>
                format!("✘ Nothing to unwrap!\n✘ {:?}", e),
            AppError::BitcoinAddressError(ref e) =>
                format!("✘ Bitcoin Address Error!\n✘ {}", e),
            AppError::SetLoggerError(ref e) =>
                format!("✘ Error setting up logger!\n✘ {}", e),
        };
        f.write_fmt(format_args!("{}", msg))
    }
}

impl Error for AppError {
    fn description(&self) -> &str {
        "\n✘ Program Error!\n"
    }
}

impl From<hex::FromHexError> for AppError {
    fn from(e: hex::FromHexError) -> AppError {
        AppError::HexError(e)
    }
}

impl From<std::io::Error> for AppError {
    fn from(e: std::io::Error) -> AppError {
        AppError::IOError(e)
    }
}

impl From<std::option::NoneError> for AppError {
    fn from(e: std::option::NoneError) -> AppError {
        AppError::NoneError(e)
    }
}

impl From<serde_json::Error> for AppError {
    fn from(e: serde_json::Error) -> AppError {
        AppError::SerdeJsonError(e)
    }
}

impl From<log::SetLoggerError> for AppError {
    fn from(e: log::SetLoggerError) -> AppError {
        AppError::SetLoggerError(e)
    }
}

impl From<secp256k1::Error> for AppError {
    fn from(e: secp256k1::Error) -> AppError {
        AppError::CryptoError(e)
    }
}

impl From<std::time::SystemTimeError> for AppError {
    fn from(e: std::time::SystemTimeError) -> AppError {
        AppError::SystemTimeError(e)
    }
}

impl From<std::num::ParseIntError> for AppError {
    fn from(e: std::num::ParseIntError) -> AppError {
        AppError::ParseIntError(e)
    }
}

impl From<crate::base58::Error> for AppError {
    fn from(e: crate::base58::Error) -> AppError {
        AppError::Base58Error(e)
    }
}

impl From<std::array::TryFromSliceError> for AppError {
    fn from(e: std::array::TryFromSliceError) -> AppError {
        AppError::FromSliceError(e)
    }
}

impl From<std::str::Utf8Error> for AppError {
    fn from(e: std::str::Utf8Error) -> AppError {
        AppError::FromUtf8Error(e)
    }
}

impl From<bitcoin::consensus::encode::Error> for AppError {
    fn from(e: bitcoin::consensus::encode::Error) -> AppError {
        AppError::BitcoinError(e)
    }
}

impl From<bitcoin_hashes::hex::Error> for AppError {
    fn from(e: bitcoin_hashes::hex::Error) -> AppError {
        AppError::BitcoinHexError(e)
    }
}

impl From<bitcoin_hashes::error::Error> for AppError {
    fn from(e: bitcoin_hashes::error::Error) -> AppError {
        AppError::BitcoinHashError(e)
    }
}

impl From<bitcoin::util::address::Error> for AppError {
    fn from(e: bitcoin::util::address::Error) -> AppError {
        AppError::BitcoinAddressError(e)
    }
}
