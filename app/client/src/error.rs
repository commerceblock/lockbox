//! # Error
//!
//! Custom Error types for client

use shared_lib::error::SharedLibError;

use bitcoin::util::{address::Error as AddressError, bip32::Error as Bip32Error};
use daemon_engine::DaemonError;
use reqwest::Error as ReqwestError;
use std::error;
use std::fmt;
use std::num::ParseIntError;

/// Client specific errors
#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum CError {
    /// Generic error from string error message
    Generic(String),
    /// Lockbox errors
    LockboxError(String),
}

impl From<String> for CError {
    fn from(e: String) -> CError {
        CError::Generic(e)
    }
}
impl From<&str> for CError {
    fn from(e: &str) -> CError {
        CError::Generic(e.to_string())
    }
}

impl From<Box<dyn error::Error>> for CError {
    fn from(e: Box<dyn error::Error>) -> CError {
        CError::Generic(e.to_string())
    }
}

impl From<Bip32Error> for CError {
    fn from(e: Bip32Error) -> CError {
        CError::Generic(e.to_string())
    }
}
impl From<AddressError> for CError {
    fn from(e: AddressError) -> CError {
        CError::Generic(e.to_string())
    }
}
impl From<ReqwestError> for CError {
    fn from(e: ReqwestError) -> CError {
        CError::Generic(e.to_string())
    }
}
impl From<ParseIntError> for CError {
    fn from(e: ParseIntError) -> CError {
        CError::Generic(e.to_string())
    }
}
impl From<std::io::Error> for CError {
    fn from(e: std::io::Error) -> CError {
        CError::Generic(e.to_string())
    }
}

impl From<serde_json::Error> for CError {
    fn from(e: serde_json::Error) -> CError {
        CError::Generic(e.to_string())
    }
}

impl From<bitcoin::secp256k1::Error> for CError {
    fn from(e: bitcoin::secp256k1::Error) -> CError {
        CError::Generic(e.to_string())
    }
}

impl From<()> for CError {
    fn from(_e: ()) -> CError {
        CError::Generic(String::default())
    }
}

impl std::convert::From<config::ConfigError> for CError {
    fn from(e: config::ConfigError) -> CError {
        CError::Generic(e.to_string())
    }
}

impl fmt::Display for CError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            CError::Generic(ref e) => write!(f, "Error: {}", e),
            CError::LockboxError(ref e) => write!(f, "Lockbox Error: {}", e),
        }
    }
}

impl error::Error for CError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            _ => None,
        }
    }
}
