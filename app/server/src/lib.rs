#![allow(unused_parens)]
#![recursion_limit = "128"]
#![feature(proc_macro_hygiene, decl_macro)]
#[macro_use]
extern crate rocket;
#[macro_use]
extern crate rocket_contrib;
extern crate chrono;
extern crate config as config_rs;
extern crate uuid;
#[macro_use]
extern crate failure;
extern crate error_chain;
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

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

#[cfg(test)]
#[macro_use]
extern crate serial_test;
extern crate mockall;
#[cfg(test)]
extern crate mockito;

extern crate shared_lib;

pub mod config;
pub mod error;
pub mod protocol;
pub mod server;
pub mod storage;
pub mod enclave;

pub type Result<T> = std::result::Result<T, error::LockboxError>;


