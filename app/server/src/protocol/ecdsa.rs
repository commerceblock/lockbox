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
    fn master_key(&self, user_id: Uuid) -> Result<()>;

    fn first_message(&self, key_gen_msg1: KeyGenMsg1) -> Result<(Uuid, party_one::KeyGenFirstMsg)>;

    fn second_message(&self, key_gen_msg2: KeyGenMsg2) -> Result<Option<party1::KeyGenParty1Message2>>;

    fn sign_first(&self, sign_msg1: SignMsg1) -> Result<Option<party_one::EphKeyGenFirstMsg>>;

    fn sign_second(&self, sign_msg2: SignMsg2) -> Result<Vec<Vec<u8>>>;
}

impl Ecdsa for Lockbox {
    fn master_key(&self, _user_id: Uuid) -> Result<()> {
	Ok(())
    }


    fn first_message(&self, key_gen_msg1: KeyGenMsg1) -> Result<(Uuid, party_one::KeyGenFirstMsg)> {

	
	let user_id = &key_gen_msg1.shared_key_id;
	let user_db_key = &Key::from_uuid(user_id);

        // Create new entry in ecdsa table if key not already in table.
        match self.database.get(user_db_key) {
            Ok(Some(_)) =>  {
                return Err(LockboxError::Generic(format!(
                    "Key Generation already completed for ID {}",
                    user_id
                )))
            },
	    Ok(None) => (),
            Err(e) => return Err(e.into()),
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


	//Store the secrets in the DB
	println!("sealed secrets: {:?} ", &sealed_secrets);
	self.database.put(user_db_key, &sealed_secrets)?;

	Ok((key_gen_msg1.shared_key_id, key_gen_first_mess))
     }

    fn second_message(&self, key_gen_msg2: KeyGenMsg2) -> Result<Option<party1::KeyGenParty1Message2>> {
	let db = &self.database;

        let user_id = &key_gen_msg2.shared_key_id;
	let user_db_key = &Key::from_uuid(user_id);

        let party2_public: GE = key_gen_msg2.dlog_proof.pk.clone();

	let mut sealed_secrets : [u8;8192] = match db.get(user_db_key) {
	    Ok(Some(x)) => x.try_into().unwrap(),
	    Ok(None) => return Err(LockboxError::Generic(format!("second_message: sealed_secrets for DB key {} is None", user_id))),
	    Err(e) => return Err(e.into())
	};

	println!("sealed secrets: {:?} ", &sealed_secrets);
	
	let mut sealed_log_out = [0u8;8192];
	let enc = Enclave::new().unwrap();

	match enc.second_message(&mut sealed_secrets, &key_gen_msg2) {
	    Ok(x) => {
		self.database.put(user_db_key, &sealed_log_out)?;
		Ok(Some(x))
	    },
	    Err(e) => Err(LockboxError::Generic(format!("generating second message: {}", e))),
	}
    }

    fn sign_first(&self, sign_msg1: SignMsg1) -> Result<Option<party_one::EphKeyGenFirstMsg>> {
	let db = &self.database;

        let user_id = &sign_msg1.shared_key_id;
	let user_db_key = &Key::from_uuid(user_id);

	let mut sealed_log_out = [0u8;8192];
	let enc = Enclave::new().unwrap();


	let mut sealed_secrets: [u8;8192] = match db.get(user_db_key) {
	    Ok(Some(x)) => x.try_into().unwrap(),
	    Ok(None) => return Err(LockboxError::Generic(format!("second_message: sealed_secrets for DB key {} is None", user_id))),
	    Err(e) => return Err(e.into())
	};

	match enc.sign_first(&mut sealed_secrets, &sign_msg1) {
	    Ok(x) => {
		self.database.put(user_db_key, &sealed_log_out)?;
		//		Ok(Some(x))
		return Ok(None)
	    },
	    Err(e) => return Err(LockboxError::Generic(format!("generating second message: {}", e))),
	}
	
	//To go outside sgx
	/*
	db.update_ecdsa_sign_first(
            user_id,
            sign_msg1.eph_key_gen_first_message_party_two,
            eph_ec_key_pair_party1,
        )?;
	 */
//	sign_party_one_first_msg = sign_party_one_first_message;
        
	//party_one::EphKeyGenFirstMsg
	// Ok(sign_party_one_first_msg)
//	Ok(None)
    }

    fn sign_second(&self, _sign_msg2: SignMsg2) -> Result<Vec<Vec<u8>>> {
	Ok(Vec::<Vec::<u8>>::new())
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
pub fn sign_second(lockbox: State<Lockbox>, sign_msg2: Json<SignMsg2>) -> Result<Json<Vec<Vec<u8>>>> {
    match lockbox.sign_second(sign_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

