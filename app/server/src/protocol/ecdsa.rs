

pub use super::super::Result;

use crate::error::LockboxError;
use crate::server::Lockbox;
use crate::enclave::Enclave;
use shared_lib::{
    structs::{KeyGenMsg1, KeyGenMsg2, KeyGenMsg3, KeyGenMsg4, SignMsg1, SignMsg2, Protocol,
    KUSendMsg, KUReceiveMsg, KUFinalize, KUAttest},
};

use curv::{
    {BigInt, FE, GE},
    elliptic::curves::traits::{ECPoint, ECScalar}
};
pub use kms::ecdsa::two_party::*;
pub use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use rocket::State;
use rocket_contrib::json::Json;
use std::string::ToString;
use uuid::Uuid;
use curv::cryptographic_primitives::proofs::sigma_dlog::*;
use crate::Key;
use zk_paillier::zkproofs::{NICorrectKeyProof, RangeProofNi, EncryptedPairs, Proof};
use paillier::EncryptionKey;
use rocksdb::ColumnFamily;

use std::convert::TryInto;

/// 2P-ECDSA protocol trait
pub trait Ecdsa {
    fn get_sealed_secrets(&self, _cf: &ColumnFamily, _user_id: &Uuid) -> Result<([u8;8192], Key)>;
	
    fn master_key(&self, user_id: Uuid) -> Result<()>;

    fn first_message(&self, key_gen_msg1: KeyGenMsg1) -> Result<(Uuid, party_one::KeyGenFirstMsg)>;

    fn second_message(&self, key_gen_msg2: KeyGenMsg2) -> Result<Option<party1::KeyGenParty1Message2>>;

    fn sign_first(&self, sign_msg1: SignMsg1) -> Result<Option<party_one::EphKeyGenFirstMsg>>;

    fn sign_second(&self, sign_msg2: SignMsg2) -> Result<Option<Vec<Vec<u8>>>>;

    fn keyupdate_first(&self, receiver_msg: KUSendMsg) -> Result<KUReceiveMsg>;

    fn keyupdate_second(&self, finalize_data: KUFinalize) -> Result<KUAttest>;
}

impl Ecdsa for Lockbox {
    fn get_sealed_secrets(&self, _cf: &ColumnFamily, _user_id: &Uuid) -> Result<([u8;8192], Key)>{

	let db = &self.database;

        let user_db_key = Key::from_uuid(_user_id);

        let mut sealed_log_out = [0u8;8192];
        let enc = Enclave::new().unwrap();


        match self.database.get_cf(_cf, &user_db_key) {
            Ok(Some(x)) => match x.try_into(){
		Ok(x) => Ok((x,user_db_key.clone())),
		Err(e) => return Err(LockboxError::Generic(format!("sealed secrets format error"))),
	    },
            Ok(None) => return Err(LockboxError::Generic(format!("sealed_secrets for DB key {} is None", _user_id))),
            Err(e) => return Err(e.into())
	}
    }

    
    fn master_key(&self, _user_id: Uuid) -> Result<()> {
	Ok(())
/*
	let db = &self.database;

        let mki = db.get_ecdsa_master_key_input(user_id)?;

        let master_key = MasterKey1::set_master_key(
            &BigInt::from(0),
            mki.party_one_private,
            &mki.comm_witness.public_share,
            &mki.party2_public,
            mki.paillier_key_pair,
        );

        db.update_ecdsa_master(&user_id, master_key)
*/
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
	
	let enc = Enclave::new().unwrap();

	let (key_gen_first_mess, sealed_secrets) =
	    if key_gen_msg1.protocol == Protocol::Deposit {
		let mut rsd1 = enc.get_random_sealed_fe_log().unwrap();
		match enc.first_message(&mut rsd1) {
		    Ok(x) => x,
		    Err(e) => return Err(LockboxError::Generic(format!("generating first message: {}", e)))
		}
	    } else {
		let cf_ku = &self.database.cf_handle("ecdsa_keyupdate").unwrap();
		println!("first_message getting  sealed secrets");
		match self.get_sealed_secrets(cf_ku, &key_gen_msg1.shared_key_id){
		    Ok(mut sealed_in) =>{
			match enc.first_message_transfer(&mut sealed_in.0) {
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
	println!("second_message getting  sealed secrets");
	let (mut sealed_secrets, user_db_key) = self.get_sealed_secrets(cf_in, &key_gen_msg2.shared_key_id)?;
	println!("got sealed secrets");
	
	let enc = Enclave::new().unwrap();
	
	match enc.second_message(&mut sealed_secrets, &key_gen_msg2) {
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
	println!("sign_first getting  sealed secrets");
	let (mut sealed_secrets, user_db_key) = self.get_sealed_secrets(cf_in, &sign_msg1.shared_key_id)?;
	
	let enc = Enclave::new().unwrap();

	match enc.sign_first(&mut sealed_secrets, &sign_msg1) {
	    Ok(x) => {
		match x {
		    Some(x) => {
			let sealed_log = &x.1;
			self.database.put_cf(cf_out, user_db_key, &x.1)?;
			Ok(Some(x.0))
		    },
		    None => Ok(None)
		}
	    },
	    Err(e) => return Err(LockboxError::Generic(format!("sign first: {}", e))),
	}
	
    }

    fn sign_second(&self, sign_msg2: SignMsg2) -> Result<Option<Vec<Vec<u8>>>> {
	let cf_in = &self.database.cf_handle("ecdsa_sign_first").unwrap();
	let cf_out = &self.database.cf_handle("ecdsa_sign_second").unwrap();
	println!("sign_second getting  sealed secrets");
	let (mut sealed_secrets, user_db_key) = self.get_sealed_secrets(cf_in, &sign_msg2.shared_key_id)?;
	

	let mut sealed_log_out = [0u8;8192];
	let enc = Enclave::new().unwrap();

	match enc.sign_second(&mut sealed_secrets, &sign_msg2) {
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
	println!("keyupdate_first getting  sealed secrets");
	let (mut sealed_secrets, user_db_key) = self.get_sealed_secrets(cf_in, &receiver_msg.user_id)?;

	let mut sealed_log_out = [0u8;8192];
	let enc = Enclave::new().unwrap();

	match enc.keyupdate_first(&mut sealed_secrets, &receiver_msg) {
	    Ok(x) => {
		let statechain_db_key = Key::from_uuid(&receiver_msg.statechain_id);
		self.database.put_cf(cf_out, statechain_db_key, &x.1)?;
		println!("finished keyupdate first");
		return Ok(x.0)
	    },
	    Err(e) => return Err(LockboxError::Generic(format!("keyupdate first: {}", e))),
	}
    }

    fn keyupdate_second(&self, finalize_data: KUFinalize) -> Result<KUAttest> {
	
	// Delete keyupdate info
	let cf_ku = &self.database.cf_handle("ecdsa_keyupdate").unwrap();


	let (mut statechain_secrets, statechain_db_key) = self.get_sealed_secrets(cf_ku, &finalize_data.statechain_id)?;

	println!("deleting keyupdate info");
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

