//! Lockbox Initialization
//!
//! Lockbox Initialization protocol trait and implementation.

pub use super::super::Result;
extern crate shared_lib;
use shared_lib::structs::*;

use crate::error::LockboxError;
use crate::server::Lockbox;
use crate::enclave::EciesFullPublicKey;

use rocket::State;
use rocket_contrib::json::Json;

use std::{convert::TryInto, path::Path, fs::File, io::Write};
use crate::Key;

extern crate sgx_types;
use self::sgx_types::*;

type LB = Lockbox;

/// Lockbox Initialization protocol trait
pub trait Initialization {
	fn init_ec_key(&self, key: &Vec<uint8_t>) -> Result<()>;
	fn gen_init_key(&self) -> Result<()>;
    fn enclave_id(&self) -> EnclaveIDMsg;
    fn put_enclave_key(&self, db_key: &Key, sealed_log: [u8; 8192]) -> Result<()>;
    fn get_enclave_key(&self, db_key: &Key) -> Result<Option<[u8; 8192]>>;
}

#[post("/initialization/init_ec_key", format = "json", data = "<init_ec_key_msg>")]
pub fn init_ec_key(
    lockbox: State<Lockbox>,
    init_ec_key_msg: Json<InitECKeyMsg>,
) -> Result<Json<()>> {
    lockbox.init_ec_key(&init_ec_key_msg.into_inner().data).map(|_| Json(()))
}

impl Initialization for Lockbox{
   
    fn enclave_id(&self) -> EnclaveIDMsg {
        EnclaveIDMsg { inner: self.enclave_mut().geteid() }
    }

    fn put_enclave_key(&self, db_key: &Key, sealed_log: [u8; 8192]) -> Result<()> {
		let cf = match self.key_database.cf_handle("enclave_key"){
	    	Some(x) => x,
	    	None => return Err(LockboxError::Generic(String::from("enclave_key not found"))),
		};
		match self.key_database.put_cf(cf, db_key, &sealed_log){
	    	Ok(_) => {
				self.enclave_mut().set_ec_key(Some(sealed_log));
				Ok(())
	    	},
	    	Err(e) => Err(LockboxError::Generic(format!("{}",e))),
		}
	}

    fn get_enclave_key(&self, db_key: &Key) -> Result<Option<[u8; 8192]>> {
		let cf = &self.key_database.cf_handle("enclave_key").unwrap();
		match self.key_database.get_cf(cf, db_key){
	    	Ok(Some(x)) => match x.try_into() {
				Ok(x) => {
		    		self.enclave_mut().set_ec_key(Some(x));
		    		self.enclave_mut().set_ec_key_enclave(x).map_err(|e| LockboxError::Generic(format!("set_ec_key_enclave error: {}", e)))?;
		    		Ok(*self.enclave_mut().get_ec_key())
				},
				Err(e) => return Err(LockboxError::Generic(format!("sealed enclave key format error: {:?}", e))),
	    	},
	    	Ok(None) => {
				self.gen_init_key().map_err(|e| LockboxError::Generic(format!("gen_init_key: {}",e)))?;
				Ok(None)
			},
	    	Err(e) => Err(e.into()),
		}
    }

	fn init_ec_key(&self, key: &Vec<uint8_t>) -> Result<()> {
		let report = self.enclave_mut().get_self_report().unwrap();
		let key_id = report.body.mr_enclave.m;
		let mut key_uuid = uuid::Builder::from_bytes(key_id[..16].try_into().unwrap());
		let db_key = Key::from_uuid(&key_uuid.build());	
		//let key_arr: = key.try_into().expect("failed to convert key");
		self.enclave_mut().init_ec_key(key).map_err(|e| LockboxError::Generic(format!("init_ec_key: {}",e)))?;
		//Get sealed ec key
		let ec_key_log = self.enclave_mut().get_ec_key_enclave().map_err(|e| LockboxError::Generic(format!("init_ec_key: {}",e)))?;
		self.put_enclave_key(&db_key, ec_key_log).map_err(|e| LockboxError::Generic(format!("init_ec_key: {}",e)))
	}

	fn gen_init_key(&self) -> Result<()> {
		let k = self.enclave_mut().gen_init_key().map_err(|e| LockboxError::Generic(format!("gen_init_key: {}",e)))?;
		let mut file = File::create(self.config.storage.init_path.clone()).map_err(|e| LockboxError::Generic(format!("gen_init_key: {}",e)))?;
		file.write_all(&k).map_err(|e| LockboxError::Generic(format!("gen_init_key: {}",e)))?;
		Ok(())
	} 

}
