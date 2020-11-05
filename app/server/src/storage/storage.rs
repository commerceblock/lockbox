use std::{fmt,error};
use rocket::response::Responder;
use rocket::http::{ContentType, Status};
use uuid::Uuid;
use shared_lib::state_chain::{StateChain, StateChainSig};
use shared_lib::Root;
use shared_lib::structs::*;
use std::io::Cursor;
use bitcoin::blockdata::transaction::Transaction;
use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use rocket_contrib::json::Json;
use chrono::NaiveDateTime;

#[derive(Debug, Deserialize)]
pub enum StorageError {
    /// Generic error from string error message
    Generic(String),
    /// Invalid argument error
    FormatError(String),
    /// Item not found error
    NotFoundError(String),
    ConfigurationError(String),
}

impl PartialEq for StorageError {
    fn eq(&self, other: &Self) -> bool {
        use StorageError::*;
        match (self, other) {
            (Generic(ref a), Generic(ref b)) => a == b,
            (FormatError(ref a), FormatError(ref b)) => a == b,
            (NotFoundError(ref a), NotFoundError(ref b)) => a == b,
            (ConfigurationError(ref a), ConfigurationError(ref b)) => a == b,
            _ => false,
        }
    }
}

impl From<String> for StorageError {
    fn from(e: String) -> Self {
        Self::Generic(e)
    }
}

impl From<&str> for StorageError {
    fn from(e: &str) -> Self {
        Self::Generic(String::from(e))
    }
}

impl fmt::Display for StorageError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            StorageError::Generic(ref e) => write!(f, "StorageError: {}", e),
            StorageError::FormatError(ref e) => write!(f, "StorageError::FormatError: {}", e),
            StorageError::NotFoundError(ref e) => write!(f, "StorageError::NotFoundError: {}", e),
            StorageError::ConfigurationError(ref e) => {
                write!(f, "StorageError::ConfigurationError: {}", e)
            }
        }
    }
}

impl error::Error for StorageError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            _ => None,
        }
    }
}

impl Responder<'static> for StorageError {
    fn respond_to(
        self,
        _: &rocket::Request,
    ) -> ::std::result::Result<rocket::Response<'static>, Status> {
        rocket::Response::build()
            .header(ContentType::JSON)
            .sized_body(Cursor::new(format!("{}", self)))
            .ok()
    }
}


pub type Result<T> = std::result::Result<T, StorageError>;


