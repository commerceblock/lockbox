//! # Error
//!
//! Custom Error types for server

//use shared_lib::error::SharedLibError;

use crate::storage::db::Column;
use config_rs::ConfigError;
use postgres::Error as PostgresError;
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
    DBError(DBErrorType, String),
    /// DB error no data in column for ID
    DBErrorWC(DBErrorType, String, Column),
    // Inherit errors from Util
    //SharedLibError(String),
}

impl From<String> for LockboxError {
    fn from(e: String) -> Self {
        Self::Generic(e)
    }
}
//impl From<SharedLibError> for Error {
//    fn from(e: SharedLibError) -> Error {
//        Error::SharedLibError(e.to_string())
//    }
//}

impl From<SystemTimeError> for LockboxError {
    fn from(e: SystemTimeError) -> Self {
        Self::Generic(e.to_string())
    }
}
impl From<PostgresError> for LockboxError {
    fn from(e: PostgresError) -> Self {
        Self::Generic(e.to_string())
    }
}
impl From<ConfigError> for LockboxError {
    fn from(e: ConfigError) -> Self {
        Self::Generic(e.to_string())
    }
}

/// DB error types
#[derive(Debug, Deserialize)]
pub enum DBErrorType {
    /// No identifier
    NoDataForID,
    /// No update made
    UpdateFailed,
    // Connection to db failed
    ConnectionFailed,
}
impl DBErrorType {
    fn as_str(&self) -> &'static str {
        match *self {
            DBErrorType::NoDataForID => "No data for identifier.",
            DBErrorType::UpdateFailed => "No update made.",
            DBErrorType::ConnectionFailed => "Connection failed.",
        }
    }
}

impl fmt::Display for LockboxError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match *self {
            LockboxError::Generic(ref e) => write!(f, "Error: {}", e),
            LockboxError::AuthError => write!(f, "Authentication Error: User authorisation failed"),
            LockboxError::DBError(ref e, ref id) => write!(f, "DB Error: {} (id: {})", e.as_str(), id),
            LockboxError::DBErrorWC(ref e, ref id, ref col) => write!(
                f,
                "DB Error: {} (id: {} col: {})",
                e.as_str(),
                id,
                col.to_string()
            ),
            //Error::SharedLibError(ref e) => write!(f, "SharedLibError Error: {}", e),
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
