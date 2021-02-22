
    

//! Lockbox Attestation
//!
//! Lockbox Attestation protocol trait and implementation.

pub use super::super::Result;
extern crate shared_lib;
use shared_lib::{state_chain::*, structs::*};
use shared_lib::structs::ExchangeReportMsg;

use crate::error::LockboxError;
use crate::server::Lockbox;
use enclave::ec_key_sealed;

use bitcoin::Transaction;
use rocket::State;
use rocket_contrib::json::Json;
use uuid::Uuid;
use curv::FE;

use std::convert::TryInto;
use crate::Key;

type LB = Lockbox;

/// Lockbox Attestation protocol trait
pub trait Attestation {
    fn session_request(&self, enclave_id_msg: &EnclaveIDMsg) -> Result<DHMsg1>;
    fn proc_msg1(&self, dh_msg1: &DHMsg1) -> Result<DHMsg2>;
    fn exchange_report(&self, er_msg: &shared_lib::structs::ExchangeReportMsg) -> Result<DHMsg3>;
    fn proc_msg3(&self, dh_msg3: &DHMsg3) -> Result<()>;
    fn end_session(&self) -> Result<()>;
    fn test_create_session(&self) -> Result<()>;
//    fn init_session(&self) -> Result<()>;
    fn enclave_id(&self) -> EnclaveIDMsg;
    fn put_enclave_key(&self, db_key: &Key, sealed_log: ec_key_sealed) -> Result<()>;
    fn get_enclave_key(&self, db_key: &Key) -> Result<Option<ec_key_sealed>>;
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
) -> Result<Json<DHMsg1>> {
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
    fn session_request(&self, id_msg: &EnclaveIDMsg) -> Result<DHMsg1> {
	self.enclave().say_something(String::from("doing session request"));
	
	match self.enclave().session_request(id_msg) {
	    Ok(r) => Ok(r),
	    Err(e) => Err(LockboxError::Generic(format!("session_request: {}",e)))
	}
    }

    fn exchange_report(&self, er_msg: &ExchangeReportMsg) -> Result<DHMsg3> {
	self.enclave().say_something(String::from("doing exchange report"));

	match self.enclave().exchange_report(er_msg) {
	    Ok(r) => Ok(r),
	    Err(e) => Err(LockboxError::Generic(format!("session_request: {}",e)))
	}
    }
    
    fn end_session(&self) -> Result<()> {
	self.enclave().say_something(String::from("doing end session"));
	
	Ok(())
    }

    fn enclave_id(&self) -> EnclaveIDMsg {
	println!("...calling enclave.geteid()...");
        EnclaveIDMsg { inner: self.enclave().geteid() }
    }

    fn test_create_session(&self) -> Result<()> {
	match self.enclave().test_create_session() {
	    Ok(r) => {
		Ok(())
	    },
	    Err(e) => Err(LockboxError::Generic(format!("session_request: {}",e))),
	}
    }
    
    fn proc_msg1(&self, dh_msg1: &DHMsg1) -> Result<DHMsg2> {
	match self.enclave().proc_msg1(dh_msg1) {
	    Ok(r) => {
		Ok(r)
	    },
	    Err(e) => Err(LockboxError::Generic(format!("proc_msg1: {}",e))),
	}
    }

    fn proc_msg3(&self, dh_msg3: &DHMsg3) -> Result<()> {
	let (db_key, sealed_log) = match self.enclave_mut().proc_msg3(dh_msg3) {
	    Ok(sealed_log) => {

		let key_id = dh_msg3.inner.msg3_body.report.key_id.id;
		let mut key_uuid = uuid::Builder::from_bytes(key_id[..16].try_into().unwrap());
		let db_key = Key::from_uuid(&key_uuid.build());

		(db_key, sealed_log)
	    },
	    Err(e) => return Err(LockboxError::Generic(format!("proc_msg3: {}",e))),
	};

	

	self.put_enclave_key(&db_key, sealed_log)
    }

    fn put_enclave_key(&self, db_key: &Key, sealed_log: ec_key_sealed) -> Result<()> {
	let cf = match self.database.cf_handle("enclave_key"){
	    Some(x) => x,
	    None => return Err(LockboxError::Generic(String::from("enclave_key not found"))),
	};
	match self.database.put_cf(cf, db_key, &sealed_log){
	    Ok(_) => {
		self.enclave_mut().set_ec_key(Some(sealed_log));
		Ok(())
	    },
	    Err(e) => Err(LockboxError::Generic(format!("{}",e))),
	}

    }

    fn get_enclave_key(&self, db_key: &Key) -> Result<Option<ec_key_sealed>> {
	let cf = &self.database.cf_handle("enclave_key").unwrap();
	match self.database.get_cf(cf, db_key){
	    Ok(Some(x)) => match x.try_into() {
		Ok(x) => {
		    self.enclave_mut().set_ec_key(Some(x));
		    self.enclave_mut().set_ec_key_enclave(x);
		    Ok(*self.enclave().get_ec_key())
		},
		Err(e) => return Err(LockboxError::Generic(format!("sealed enclave key format error: {:?}", e))),
	    },
	    Ok(None) => Ok(None),
	    Err(e) => Err(e.into()),
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
