pub use super::super::Result;

use crate::error::LockboxError;
use crate::server::Lockbox;
use shared_lib::{
    structs::{KeyGenMsg1, KeyGenMsg2, KeyGenMsg3, KeyGenMsg4, SignMsg1, SignMsg2},
};

pub use kms::ecdsa::two_party::*;
pub use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use rocket::State;
use rocket_contrib::json::Json;
use std::string::ToString;
use uuid::Uuid;


/// 2P-ECDSA protocol trait
pub trait Ecdsa {
    fn master_key(&self, user_id: Uuid) -> Result<()>;

    fn first_message(&self, key_gen_msg1: KeyGenMsg1) -> Result<(Uuid, party_one::KeyGenFirstMsg)>;

    fn second_message(&self, key_gen_msg2: KeyGenMsg2) -> Result<party1::KeyGenParty1Message2>;

    fn third_message(&self, key_gen_msg3: KeyGenMsg3) -> Result<party_one::PDLFirstMessage>;

    fn fourth_message(&self, key_gen_msg4: KeyGenMsg4) -> Result<party_one::PDLSecondMessage>;

    fn sign_first(&self, sign_msg1: SignMsg1) -> Result<party_one::EphKeyGenFirstMsg>;

    fn sign_second(&self, sign_msg2: SignMsg2) -> Result<Vec<Vec<u8>>>;
}

impl Ecdsa for Lockbox {
    fn master_key(&self, _user_id: Uuid) -> Result<()> {
       Err(LockboxError::Generic("unimplemented".to_string()))
    }

    fn first_message(&self, key_gen_msg1: KeyGenMsg1) -> Result<(Uuid, party_one::KeyGenFirstMsg)> {
	let _ = self.enclave.say_something("calling enclave from first_message".to_string()).map_err(|e| LockboxError::Generic(e.to_string()))?;
	let sealed = self.enclave.get_random_sealed_data().map_err(|e| LockboxError::Generic(e.to_string()))?;
	self.enclave.verify_sealed_data(sealed).map_err(|e| LockboxError::Generic(e.to_string()))?;
	Err(LockboxError::Generic("sealed and unsealed data successfully".to_string()))
    }

    fn second_message(&self, _key_gen_msg2: KeyGenMsg2) -> Result<party1::KeyGenParty1Message2> {
        Err(LockboxError::Generic("unimplemented".to_string()))
    }

    fn third_message(&self, _key_gen_msg3: KeyGenMsg3) -> Result<party_one::PDLFirstMessage> {
        Err(LockboxError::Generic("unimplemented".to_string()))
    }

    fn fourth_message(&self, _key_gen_msg4: KeyGenMsg4) -> Result<party_one::PDLSecondMessage> {
        Err(LockboxError::Generic("unimplemented".to_string()))
    }

    fn sign_first(&self, _sign_msg1: SignMsg1) -> Result<party_one::EphKeyGenFirstMsg> {
        Err(LockboxError::Generic("unimplemented".to_string()))
    }

    fn sign_second(&self, _sign_msg2: SignMsg2) -> Result<Vec<Vec<u8>>> {
        Err(LockboxError::Generic("unimplemented".to_string()))
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
) -> Result<Json<party1::KeyGenParty1Message2>> {
    match lockbox.second_message(key_gen_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/keygen/third", format = "json", data = "<key_gen_msg3>")]
pub fn third_message(
    lockbox: State<Lockbox>,
    key_gen_msg3: Json<KeyGenMsg3>,
) -> Result<Json<party_one::PDLFirstMessage>> {
    match lockbox.third_message(key_gen_msg3.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/keygen/fourth", format = "json", data = "<key_gen_msg4>")]
pub fn fourth_message(
    lockbox: State<Lockbox>,
    key_gen_msg4: Json<KeyGenMsg4>,
) -> Result<Json<party_one::PDLSecondMessage>> {
    match lockbox.fourth_message(key_gen_msg4.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/sign/first", format = "json", data = "<sign_msg1>")]
pub fn sign_first(
    lockbox: State<Lockbox>,
    sign_msg1: Json<SignMsg1>,
) -> Result<Json<party_one::EphKeyGenFirstMsg>> {
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

