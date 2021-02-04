//! # Error
//!
//! Custom Error types for lockbox

//use shared_lib::error::SharedLibError;

use config_rs::ConfigError;
use rocket::http::{ContentType, Status};
use rocket::response::Responder;
use rocket::{Request, Response};
use std::error;
use std::fmt;
use std::io::Cursor;
use std::time::SystemTimeError;


/// State Entity library specific errors
#[derive(Debug, Deserialize)]
pub enum LockboxError {
    /// Generic error from string error message
    Generic(String),
    /// Athorisation failed
    AuthError,
    /// DB error no ID found
    DBError(String),
    /// Client error
    ClientError(String)
}

impl From<String> for LockboxError {
    fn from(e: String) -> Self {
        Self::Generic(e)
    }
}

impl From<rocksdb::Error> for LockboxError {
    fn from(e: rocksdb::Error) -> Self {
	LockboxError::DBError(e.into_string())
    }
}


impl From<SystemTimeError> for LockboxError {
    fn from(e: SystemTimeError) -> Self {
        Self::Generic(e.to_string())
    }
}

impl From<ConfigError> for LockboxError {
    fn from(e: ConfigError) -> Self {
        Self::Generic(e.to_string())
    }
}

impl From<reqwest::Error> for LockboxError {
    fn from(e: reqwest::Error) -> Self {
        Self::ClientError(e.to_string())
    }
}

impl fmt::Display for LockboxError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LockboxError::Generic(ref e) => write!(f, "Error: {}", e),
            LockboxError::AuthError => write!(f, "Authentication Error: User authorisation failed"),
            LockboxError::DBError(ref e) => write!(f, "DB Error: {}", e),
	    LockboxError::ClientError(ref e) => write!(f, "Client Error: {}", e),
        }
    }
}

impl error::Error for LockboxError {
    fn source(&self) -> Option<&(dyn error::Error + 'static)> {
        match *self {
            _ => None,
        }
    }
}

impl Responder<'static> for LockboxError {
    fn respond_to(self, _: &Request) -> ::std::result::Result<Response<'static>, Status> {
        Response::build()
            .header(ContentType::JSON)
            .sized_body(Cursor::new(format!("{}", self)))
            .ok()
    }
}
