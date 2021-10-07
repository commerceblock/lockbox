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
extern crate curv_client;
extern crate kms;
extern crate kms_sgx;
extern crate multi_party_ecdsa;
extern crate multi_party_ecdsa_client;
extern crate rocksdb;
extern crate tempdir;
extern crate num_bigint_dig;
extern crate num_traits;
extern crate rand;
extern crate lazy_static;
extern crate reqwest;
extern crate floating_duration;

extern crate sgx_types;
extern crate sgx_urts;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;
extern crate serde_cbor;
#[macro_use]
extern crate serde_big_array;

big_array! { BigArray; }

extern crate mockall;
#[cfg(test)]
extern crate mockito;
#[cfg(test)]
#[macro_use]
extern crate serial_test;
extern crate shared_lib;

extern crate zk_paillier;
extern crate zk_paillier_client;
extern crate paillier;
extern crate paillier_client;

pub mod config;
pub mod error;
pub mod protocol;
pub mod server;
pub mod client;
pub mod storage;
pub mod enclave;
pub mod db;

pub type Result<T> = std::result::Result<T, error::LockboxError>;

use uuid::Uuid;
use std::convert::{From, AsRef};
use std::fmt;

#[derive(Clone, Debug)]
pub struct Key(Uuid);

impl Key {
    fn from_uuid(id: &Uuid) -> Self {
	Self(*id)
    }
}

impl AsRef<[u8]> for Key {
    fn as_ref(&self) -> &[u8]{
	self.0.as_bytes()
    }
}

impl fmt::Display for Key {
     fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "({})", self.0)
    }
}

impl From<u32> for Key {
    fn from(item : u32) -> Self {
	Self(Uuid::from_u128(item as u128))
    }
}
