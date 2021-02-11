//! Lockbox Attestation
//!
//! Lockbox Attestation protocol trait and implementation.

pub use super::super::Result;
extern crate shared_lib;
use shared_lib::{state_chain::*, structs::*};
use shared_lib::structs::ExchangeReportMsg;

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
    fn session_request(&self, enclave_id_msg: &EnclaveIDMsg) -> Result<(DHMsg1, usize)>;
    fn exchange_report(&self, er_msg: &shared_lib::structs::ExchangeReportMsg) -> Result<DHMsg3>;
    fn end_session(&self) -> Result<()>;
    fn enclave_id(&self) -> EnclaveIDMsg;
}

#[post("/attestation/session_request", format = "json", data = "<enclave_id_msg>")]
pub fn session_request(
    lockbox: State<Lockbox>,
    enclave_id_msg: Json<EnclaveIDMsg>,
) -> Result<Json<(DHMsg1, usize)>> {
    match lockbox.session_request(&enclave_id_msg) {
        Ok(r) => Ok(Json(r)),
        Err(e) => Err(e),
    }
}

#[post("/attestation/exchange_report", format = "json", data = "<er_msg>")]
pub fn exchange_report(
    lockbox: State<Lockbox>,
    er_msg: Json<ExchangeReportMsg>,
) -> Result<Json<DHMsg3>> {
    match lockbox.exchange_report(&er_msg) {
        Ok(r) => Ok(Json(r)),
        Err(e) => Err(e),
    }
}

#[get("/attestation/enclave_id")]
pub fn enclave_id(
    lockbox: State<Lockbox>,
) -> Result<Json<EnclaveIDMsg>> {
    Ok(Json(lockbox.enclave_id()))
}

#[get("/attestation/end_session")]
pub fn end_session(
    lockbox: State<Lockbox>,
) -> Result<()> {
    match lockbox.end_session() {
        Ok(_) => Ok(()),
        Err(e) => Err(e),
    }
}

impl Attestation for Lockbox{
    fn session_request(&self, id_msg: &EnclaveIDMsg) -> Result<(DHMsg1, usize)> {
	self.enclave.say_something(String::from("doing session request"));
	
	match self.enclave.session_request(id_msg) {
	    Ok(r) => Ok(r),
	    Err(e) => Err(LockboxError::Generic(format!("session_request: {}",e)))
	}
    }

    fn exchange_report(&self, er_msg: &ExchangeReportMsg) -> Result<DHMsg3> {
	self.enclave.say_something(String::from("doing exchange report"));

	match self.enclave.exchange_report(er_msg) {
	    Ok(r) => Ok(r),
	    Err(e) => Err(LockboxError::Generic(format!("session_request: {}",e)))
	}
    }
    
    fn end_session(&self) -> Result<()> {
	self.enclave.say_something(String::from("doing end session"));
	
	Ok(())
    }

    fn enclave_id(&self) -> EnclaveIDMsg {
        EnclaveIDMsg { inner: self.enclave.geteid() }
    }

}
