

pub use super::super::Result;

use crate::error::LockboxError;
use crate::server::Lockbox;
use crate::enclave::Enclave;
use shared_lib::{
    structs::{KeyGenMsg1, KeyGenMsg2, KeyGenMsg3, KeyGenMsg4, SignMsg1, SignMsg2, Protocol},
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

use std::convert::TryInto;

/// 2P-ECDSA protocol trait
pub trait Ecdsa {
    fn get_sealed_secrets(&self, _user_id: &Uuid) -> Result<([u8;8192], Key)>;
	
    fn master_key(&self, user_id: Uuid) -> Result<()>;

    fn first_message(&self, key_gen_msg1: KeyGenMsg1) -> Result<(Uuid, party_one::KeyGenFirstMsg)>;

    fn second_message(&self, key_gen_msg2: KeyGenMsg2) -> Result<Option<party1::KeyGenParty1Message2>>;

    fn sign_first(&self, sign_msg1: SignMsg1) -> Result<Option<party_one::EphKeyGenFirstMsg>>;

    fn sign_second(&self, sign_msg2: SignMsg2) -> Result<Option<Vec<Vec<u8>>>>;
}

impl Ecdsa for Lockbox {
    fn get_sealed_secrets(&self, _user_id: &Uuid) -> Result<([u8;8192], Key)>{

	let db = &self.database;

        let user_db_key = Key::from_uuid(_user_id);

        let mut sealed_log_out = [0u8;8192];
        let enc = Enclave::new().unwrap();


        match self.database.get(&user_db_key) {
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
	match self.database.get(user_db_key) {
            Ok(data) => match data {
		Some(x) => {
		    if x.len() > 0 {
			return Err(LockboxError::Generic(format!("Key Generation already completed for ID {}", user_db_key)))
		    } 
		},
		None => self.database.put(user_db_key, &[0u8;0])?
            },
	    Err(e) => return Err(e.into()) 
        };
	
	let (key_gen_first_mess, sealed_secrets) =
	    if key_gen_msg1.protocol == Protocol::Deposit {
		let enc = Enclave::new().unwrap();
		let mut rsd1 = enc.get_random_sealed_log(32).unwrap();
		match enc.first_message(&mut rsd1) {
		    Ok(x) => x,
		    Err(e) => return Err(LockboxError::Generic(format!("generating first message: {}", e)))
		}
	    } else {
		return Err(LockboxError::Generic("transfer first message not yet implemented".to_string()))
	    };

        let user_db_key = Key::from_uuid(&key_gen_msg1.shared_key_id);
	//Store the secrets in the DB
	self.database.put(user_db_key, &sealed_secrets)?;

	Ok((key_gen_msg1.shared_key_id, key_gen_first_mess))
     }

    fn second_message(&self, key_gen_msg2: KeyGenMsg2) -> Result<Option<party1::KeyGenParty1Message2>> {

	let (mut sealed_secrets, user_db_key) = self.get_sealed_secrets(&key_gen_msg2.shared_key_id)?;
	
        let party2_public: GE = key_gen_msg2.dlog_proof.pk.clone();
	
	let mut sealed_log_out = [0u8;8192];
	let enc = Enclave::new().unwrap();
	
	match enc.second_message(&mut sealed_secrets, &key_gen_msg2) {
	    Ok(x) => {
		self.database.put(user_db_key, &sealed_log_out)?;
		Ok(Some(x.0))
	    },
	    Err(e) => Err(LockboxError::Generic(format!("generating second message: {}", e))),
	}
    }

    fn sign_first(&self, sign_msg1: SignMsg1) -> Result<Option<party_one::EphKeyGenFirstMsg>> {

	let (mut sealed_secrets, user_db_key) = self.get_sealed_secrets(&sign_msg1.shared_key_id)?;
	
	let enc = Enclave::new().unwrap();

	match enc.sign_first(&mut sealed_secrets, &sign_msg1) {
	    Ok(x) => {
		let sealed_log = &x.1;
		self.database.put(user_db_key, &x.1)?;
		return Ok(Some(x.0))
	    },
	    Err(e) => return Err(LockboxError::Generic(format!("generating second message: {}", e))),
	}
	
    }

    fn sign_second(&self, sign_msg2: SignMsg2) -> Result<Option<Vec<Vec<u8>>>> {
	let (mut sealed_secrets, user_db_key) = self.get_sealed_secrets(&sign_msg2.shared_key_id)?;
	

	let mut sealed_log_out = [0u8;8192];
	let enc = Enclave::new().unwrap();

	
	match enc.sign_second(&mut sealed_secrets, &sign_msg2) {
	    Ok(x) => {
		self.database.put(user_db_key, &x.1)?;
		return Ok(Some(x.0))
	    },
	    Err(e) => return Err(LockboxError::Generic(format!("generating second message: {}", e))),
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

