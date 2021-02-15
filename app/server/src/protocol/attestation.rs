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
    fn proc_msg1(&self, dh_msg1: &DHMsg1) -> Result<DHMsg2>;
    fn exchange_report(&self, er_msg: &shared_lib::structs::ExchangeReportMsg) -> Result<DHMsg3>;
    fn proc_msg3(&self, dh_msg3: &DHMsg3) -> Result<()>;
    fn end_session(&self) -> Result<()>;
    fn test_create_session(&self) -> Result<()>;
//    fn init_session(&self) -> Result<()>;
    fn enclave_id(&self) -> EnclaveIDMsg;
}

#[get("/attestation/test_create_session")]
pub fn test_create_session(
    lockbox: State<Lockbox>,
) -> Result<()> {
    println!("...getting enclave id...");
    match lockbox.test_create_session(){
	Ok(_) => Ok(()),
	Err(e) => Err(e.into()),
    }
}

/*
#[get("/attestation/init_session")]
pub fn init_session(
    lockbox: State<Lockbox>,
) -> Result<> {
    match lockbox.init_session() {
        Ok(r) => Ok(Json(r)),
        Err(e) => Err(e),
    }
}
 */

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

#[post("/attestation/proc_msg1", format = "json", data = "<dh_msg1>")]
pub fn proc_msg1(
    lockbox: State<Lockbox>,
    dh_msg1: Json<DHMsg1>,
) -> Result<Json<DHMsg2>> {
    match lockbox.proc_msg1(&dh_msg1) {
        Ok(r) => Ok(Json(r)),
        Err(e) => Err(e),
    }
}

#[post("/attestation/proc_msg3", format = "json", data = "<dh_msg3>")]
pub fn proc_msg3(
    lockbox: State<Lockbox>,
    dh_msg3: Json<DHMsg3>,
) -> Result<Json<()>> {
    match lockbox.proc_msg3(&dh_msg3) {
        Ok(r) => Ok(Json(())),
        Err(e) => Err(e),
    }
}

#[get("/attestation/enclave_id")]
pub fn enclave_id(
    lockbox: State<Lockbox>,
) -> Result<Json<EnclaveIDMsg>> {
    println!("...getting enclave id...");
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
	println!("...calling enclave.geteid()...");
        EnclaveIDMsg { inner: self.enclave.geteid() }
    }

    fn test_create_session(&self) -> Result<()> {
	match self.enclave.test_create_session() {
	    Ok(r) => {
		Ok(())
	    },
	    Err(e) => Err(LockboxError::Generic(format!("session_request: {}",e))),
	}
    }
    
    fn proc_msg1(&self, dh_msg1: &DHMsg1) -> Result<DHMsg2> {
	match self.enclave.proc_msg1(dh_msg1) {
	    Ok(r) => {
		Ok(r)
	    },
	    Err(e) => Err(LockboxError::Generic(format!("proc_msg1: {}",e))),
	}
    }

    fn proc_msg3(&self, dh_msg3: &DHMsg3) -> Result<()> {
	match self.enclave.proc_msg3(dh_msg3) {
	    Ok(r) => {
		Ok(())
	    },
	    Err(e) => Err(LockboxError::Generic(format!("proc_msg3: {}",e))),
	}
    }

    /*
    fn init_session(&self) -> Result<()> {
	match self.enclave.init_session() {
	    Ok(r) => {
		Ok(())
	    },
	    Err(e) => Err(LockboxError::Generic(format!("init_session: {}",e))),
	}
    }
    */

}
