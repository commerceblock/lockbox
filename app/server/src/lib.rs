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

use rocket_contrib::databases::r2d2;
use rocket_contrib::databases::r2d2_postgres::PostgresConnectionManager;

//use crate::protocol::transfer::TransferFinalizeData;
use mockall::predicate::*;
use mockall::*;
use rocket_contrib::databases::postgres;
//use shared_lib::{state_chain::*, structs::TransferMsg3, Root};
use std::collections::{HashMap, HashSet};
use uuid::Uuid;

#[database("postgres_w")]
pub struct DatabaseW(postgres::Connection);
#[database("postgres_r")]
pub struct DatabaseR(postgres::Connection);

/// Postgres database struct
pub struct PGDatabase {
    pub pool: Option<r2d2::Pool<PostgresConnectionManager>>
}

use structs::*;

#[automock]
pub trait Database {
    fn get_new() -> Self;
    fn set_connection_from_config(&mut self, config: &crate::config::Config) -> Result<()>;
    fn set_connection(&mut self, url: &String) -> Result<()>;
    fn from_pool(pool: r2d2::Pool<PostgresConnectionManager>) -> Self;
    fn reset(&self) -> Result<()>;
    fn init(&self) -> Result<()>;
    fn get_user_auth(&self, user_id: Uuid) -> Result<Uuid>;
    fn get_statechain_id(&self, user_id: Uuid) -> Result<Uuid>;
    fn update_statechain_id(&self, user_id: &Uuid, state_chain_id: &Uuid) -> Result<()>;
    // Remove state_chain_id from user session to signal end of session
    fn remove_statechain_id(&self, user_id: &Uuid) -> Result<()>;
    fn get_proof_key(&self, user_id: Uuid) -> Result<String>;
}

pub mod structs {
    use super::*;
}
