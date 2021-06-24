
pub use super::super::Result;

use crate::error::LockboxError;
use crate::server::Lockbox;
use crate::enclave::{Enclave, ec_key_sealed};
use shared_lib::{
    structs::{KeyGenMsg1, KeyGenMsg2, SignMsg1, SignMsg2, Protocol,
    KUSendMsg, KUReceiveMsg, KUFinalize, KUAttest},
};

pub use kms::ecdsa::two_party::*;
pub use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use rocket::State;
use rocket_contrib::json::Json;
use uuid::Uuid;
use crate::Key;
use rocksdb::ColumnFamily;

use std::convert::TryInto;

/// 2P-ECDSA protocol trait
pub trait Ecdsa {

    fn get_sealed_secrets_ec_key(&self, cf: &ColumnFamily, user_id: &Uuid) -> Result<(ec_key_sealed, Key)>;
    
    fn get_sealed_secrets(&self, cf: &ColumnFamily, user_id: &Uuid) -> Result<([u8;8192], Key)>;

    fn get_sealed_secrets_lg(&self, cf: &ColumnFamily, user_id: &Uuid) -> Result<([u8;32400], Key)>;
	
    fn first_message(&self, key_gen_msg1: KeyGenMsg1) -> Result<(Uuid, party_one::KeyGenFirstMsg)>;

    fn second_message(&self, key_gen_msg2: KeyGenMsg2) -> Result<Option<party1::KeyGenParty1Message2>>;

    fn sign_first(&self, sign_msg1: SignMsg1) -> Result<Option<party_one::EphKeyGenFirstMsg>>;

    fn sign_second(&self, sign_msg2: SignMsg2) -> Result<Option<Vec<Vec<u8>>>>;

    fn keyupdate_first(&self, receiver_msg: KUSendMsg) -> Result<KUReceiveMsg>;

    fn keyupdate_second(&self, finalize_data: KUFinalize) -> Result<KUAttest>;
}

impl Ecdsa for Lockbox {
    fn get_sealed_secrets_ec_key(&self, cf: &ColumnFamily, user_id: &Uuid) -> Result<(ec_key_sealed, Key)>{

        let user_db_key = Key::from_uuid(user_id);

        match self.database.get_cf(cf, &user_db_key) {
            Ok(Some(x)) => match x.try_into(){
				Ok(x) => Ok((x,user_db_key.clone())),
				Err(e) => return Err(LockboxError::Generic(format!("sealed secrets format error: {:?}", e))),
	    	},
            Ok(None) => return Err(LockboxError::Generic(format!("sealed_secrets for DB key {} is None", user_id))),
            Err(e) => return Err(e.into())
		}
    }
    
    fn get_sealed_secrets(&self, cf: &ColumnFamily, user_id: &Uuid) -> Result<([u8; 8192], Key)>{

        let user_db_key = Key::from_uuid(user_id);

        match self.database.get_cf(cf, &user_db_key) {
            Ok(Some(x)) => match x.try_into(){
		Ok(x) => Ok((x,user_db_key.clone())),
		Err(e) => return Err(LockboxError::Generic(format!("sealed secrets format error: {:?}", e))),
	    },
            Ok(None) => return Err(LockboxError::Generic(format!("sealed_secrets for DB key {} is None", user_id))),
            Err(e) => return Err(e.into())
	}
    }

    fn get_sealed_secrets_lg(&self, cf: &ColumnFamily, user_id: &Uuid) -> Result<([u8; 32400], Key)>{

        let user_db_key = Key::from_uuid(user_id);

        match self.database.get_cf(cf, &user_db_key) {
            Ok(Some(x)) => match x.try_into(){
		Ok(x) => Ok((x,user_db_key.clone())),
		Err(e) => return Err(LockboxError::Generic(format!("sealed secrets format error: {:?}", e))),
	    },
            Ok(None) => return Err(LockboxError::Generic(format!("sealed_secrets for DB key {} is None", user_id))),
            Err(e) => return Err(e.into())
	}
    }

    fn first_message(&self, key_gen_msg1: KeyGenMsg1) -> Result<(Uuid, party_one::KeyGenFirstMsg)> {
        let user_db_key = &Key::from_uuid(&key_gen_msg1.shared_key_id);
	let cf = &self.database.cf_handle("ecdsa_first_message").unwrap();
	match self.database.get_cf(cf, user_db_key) {
            Ok(data) => match data {
		Some(x) => {
		    if x.len() > 0 {
			return Err(LockboxError::Generic(format!("Key Generation already completed for ID {}", user_db_key)))
		    } 
		},
		None => self.database.put_cf(cf, user_db_key, &[0u8;0])?
            },
	    Err(e) => return Err(e.into()) 
        };
	
	let (key_gen_first_mess, sealed_secrets) =
	    if key_gen_msg1.protocol == Protocol::Deposit {
		let mut rsd1 = self.enclave_mut().get_random_ec_fe_log().unwrap();
		match self.enclave_mut().first_message(&mut rsd1) {
		    Ok(x) => x,
		    Err(e) => return Err(LockboxError::Generic(format!("generating first message: {}", e)))
		}
	    } else {
		let cf_ku = &self.database.cf_handle("ecdsa_keyupdate").unwrap();
		match self.get_sealed_secrets(cf_ku, &key_gen_msg1.shared_key_id){
		    Ok(mut sealed_in) =>{
			match self.enclave_mut().first_message_transfer(&mut sealed_in.0) {
			    Ok(x) => x,
			    Err(e) => return Err(LockboxError::Generic(format!("{}", e))),
			}
		    },
		    Err(e) => return Err(e.into()) 
		}
	    };

	
        let user_db_key = Key::from_uuid(&key_gen_msg1.shared_key_id);
	//Store the secrets in the DB
	self.database.put_cf(cf, user_db_key, &sealed_secrets)?;

	Ok((key_gen_msg1.shared_key_id, key_gen_first_mess))

     }

    fn second_message(&self, key_gen_msg2: KeyGenMsg2) -> Result<Option<party1::KeyGenParty1Message2>> {
	let cf_in = &self.database.cf_handle("ecdsa_first_message").unwrap();
	let cf_out = &self.database.cf_handle("ecdsa_second_message").unwrap();
	let (mut sealed_secrets, user_db_key) = self.get_sealed_secrets(cf_in, &key_gen_msg2.shared_key_id)?;
	match self.enclave_mut().second_message(&mut sealed_secrets, &key_gen_msg2) {
	    Ok(x) => {
		self.database.put_cf(cf_out, user_db_key, &x.1)?;
		Ok(Some(x.0))
	    },
	    Err(e) => Err(LockboxError::Generic(format!("generating second message: {}", e))),
	}
    }

    fn sign_first(&self, sign_msg1: SignMsg1) -> Result<Option<party_one::EphKeyGenFirstMsg>> {
		let cf_in = &self.database.cf_handle("ecdsa_second_message").unwrap();
		let cf_out = &self.database.cf_handle("ecdsa_sign_first").unwrap();
		let (mut sealed_secrets, user_db_key) = self.get_sealed_secrets(cf_in, &sign_msg1.shared_key_id)?;
		
		match self.enclave_mut().sign_first(&mut sealed_secrets, &sign_msg1) {
	    	Ok(x) => {
				match x {
		    		Some(x) => {
						self.database.put_cf(cf_out, user_db_key, &x.1)?;
						Ok(Some(x.0))
		    		},
		    		None => {
						Ok(None)
					},
				}
	    	},
	    	Err(e) => {
				let err_msg = format!("sign first: {}", e);
				println!("{}", err_msg);
				return Err(LockboxError::Generic(err_msg))
			},
		}
	
    }

    fn sign_second(&self, sign_msg2: SignMsg2) -> Result<Option<Vec<Vec<u8>>>> {
	let cf_in = &self.database.cf_handle("ecdsa_sign_first").unwrap();
	let cf_out = &self.database.cf_handle("ecdsa_sign_second").unwrap();
	let (mut sealed_secrets, user_db_key) = self.get_sealed_secrets(cf_in, &sign_msg2.shared_key_id)?;
	

	match self.enclave_mut().sign_second(&mut sealed_secrets, &sign_msg2) {
	    Ok(x) => {
		self.database.put_cf(cf_out, user_db_key, &x.1)?;
		return Ok(Some(x.0))
	    },
	    Err(e) => return Err(LockboxError::Generic(format!("sign second: {}", e))),
	}
    }

    fn keyupdate_first(&self, receiver_msg: KUSendMsg) -> Result<KUReceiveMsg> {
	let cf_in = &self.database.cf_handle("ecdsa_second_message").unwrap();
	let cf_out = &self.database.cf_handle("ecdsa_keyupdate").unwrap();
	let (mut sealed_secrets, _user_db_key) = self.get_sealed_secrets(cf_in, &receiver_msg.user_id)?;

	match self.enclave_mut().keyupdate_first(&mut sealed_secrets, &receiver_msg) {
	    Ok(x) => {
		let statechain_db_key = Key::from_uuid(&receiver_msg.statechain_id);
		self.database.put_cf(cf_out, statechain_db_key, &x.1)?;
		return Ok(x.0)
	    },
	    Err(e) => return Err(LockboxError::Generic(format!("keyupdate first: {}", e))),
	}
    }

    fn keyupdate_second(&self, finalize_data: KUFinalize) -> Result<KUAttest> {
	
	// Delete keyupdate info
	let cf_ku = &self.database.cf_handle("ecdsa_keyupdate").unwrap();


	let (statechain_secrets, statechain_db_key) = self.get_sealed_secrets(cf_ku, &finalize_data.statechain_id)?;

	match self.database.delete_cf(cf_ku, statechain_db_key) {
	    Ok(_) => {
		let sharedkey_db_key = Key::from_uuid(&finalize_data.shared_key_id);
		self.database.put_cf(cf_ku, sharedkey_db_key, &statechain_secrets)?;
		Ok(KUAttest { statechain_id: finalize_data.statechain_id, attestation: String::from("") })
	    },
	    Err(e) => return Err(LockboxError::Generic(format!("keyupdate second: error deleting transfer data: {}", e))),
	}
    }

}

#[post("/ecdsa/keygen/first", format = "json", data = "<key_gen_msg1>")]
pub fn first_message(
    lockbox: State<Lockbox>,
    key_gen_msg1: Json<KeyGenMsg1>,
) -> Result<Json<(Uuid, party_one::KeyGenFirstMsg)>> {
    match lockbox.first_message(key_gen_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/keygen/second", format = "json", data = "<key_gen_msg2>")]
pub fn second_message(
    lockbox: State<Lockbox>,
    key_gen_msg2: Json<KeyGenMsg2>,
) -> Result<Json<Option<party1::KeyGenParty1Message2>>> {
    match lockbox.second_message(key_gen_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/sign/first", format = "json", data = "<sign_msg1>")]
pub fn sign_first(
    lockbox: State<Lockbox>,
    sign_msg1: Json<SignMsg1>,
) -> Result<Json<Option<party_one::EphKeyGenFirstMsg>>> {
    match lockbox.sign_first(sign_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/sign/second", format = "json", data = "<sign_msg2>")]
pub fn sign_second(lockbox: State<Lockbox>, sign_msg2: Json<SignMsg2>) -> Result<Json<Option<Vec<Vec<u8>>>>> {
    match lockbox.sign_second(sign_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}


#[post("/ecdsa/keyupdate/first", format = "json", data = "<receiver_msg>")]
pub fn keyupdate_first(
    lockbox: State<Lockbox>,
    receiver_msg: Json<KUSendMsg>,
) -> Result<Json<KUReceiveMsg>> {
    match lockbox.keyupdate_first(receiver_msg.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/keyupdate/second", format = "json", data = "<finalize_data>")]
pub fn keyupdate_second(
    lockbox: State<Lockbox>,
    finalize_data: Json<KUFinalize>,
) -> Result<Json<KUAttest>> {
    match lockbox.keyupdate_second(finalize_data.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

