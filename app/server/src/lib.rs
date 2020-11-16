#![allow(unused_parens)]
#![recursion_limit = "128"]
#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use]
extern crate rocket;
#[allow(unused_imports)]
#[macro_use]
extern crate rocket_contrib;
extern crate chrono;
extern crate config as config_rs;
extern crate uuid;
#[macro_use]
extern crate failure;
extern crate error_chain;
#[allow(unused_imports)]
#[macro_use]
extern crate log;
extern crate cfg_if;
extern crate hex;
extern crate jsonwebtoken as jwt;
extern crate log4rs;
extern crate rusoto_dynamodb;
extern crate bitcoin;
extern crate curv;
extern crate kms;
extern crate multi_party_ecdsa;
extern crate rocksdb;
extern crate tempdir;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

extern crate mockall;
#[cfg(test)]
extern crate mockito;
#[cfg(test)]
#[macro_use]
extern crate serial_test;
extern crate shared_lib;

pub mod config;
pub mod error;
pub mod protocol;
pub mod server;
pub mod storage;
pub mod enclave;

pub type Result<T> = std::result::Result<T, error::LockboxError>;

use uuid::Uuid;
use std::convert::AsRef;


pub struct Key(Uuid);

impl Key {
    fn new() -> Self {
	Self(Uuid::new_v4())
    }

    fn from_uuid(id: &Uuid) -> Self {
	Self(*id)
    }
    
    fn inner(&self) -> Uuid {
	self.0
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8]{
	self.0.as_bytes()
    }
}
