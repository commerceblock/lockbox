//! Lockbox Attestation
//!
//! Lockbox Attestation protocol trait and implementation.

pub use super::super::Result;
extern crate shared_lib;
use shared_lib::{state_chain::*, structs::*};

use crate::error::LockboxError;
use crate::server::Lockbox;

use bitcoin::Transaction;
use rocket::State;
use rocket_contrib::json::Json;
use uuid::Uuid;
use curv::FE;

type LB = Lockbox;

/// Lockbox Attestation protocol trait
pub trait Attestation {
    fn session_request(&self, transfer_msg1: &EnclaveIDMsg) -> Result<DHMsg1>;
}

#[post("/attestation/session_request", format = "json", data = "<enclave_id_msg>")]
pub fn session_request(
    lockbox: State<Lockbox>,
    enclave_id_msg: Json<EnclaveIDMsg>,
) -> Result<Json<DHMsg1>> {
    match lockbox.session_request(&enclave_id_msg) {
        Ok(r) => Ok(Json(r)),
        Err(e) => Err(e),
    }
}

#[get("/attestation/enclave_id")]
pub fn enclave_id(
    lockbox: State<Lockbox>,
) -> Result<Json<EnclaveIDMsg>> {
    Ok(Json(EnclaveIDMsg { inner: lockbox.enclave.geteid() }))
}


impl Attestation for Lockbox{
    fn session_request(&self, id_msg: &EnclaveIDMsg) -> Result<DHMsg1> {
	self.enclave.say_something(String::from("doing session request"));
	
	//	match self.enclave.session_request(id_msg) {
//	    Ok(r) => Ok(r),
//	    Err(e) => Err(LockboxError::Generic(format!("session_request: {}",e)))
	//	}
	Ok(DHMsg1::default())
    }
}
