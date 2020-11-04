pub use super::super::Result;

use crate::error::{DBErrorType, LockboxError};
use crate::Database;
use crate::{server::Lockbox, structs::*};
use shared_lib::{
    structs::{KeyGenMsg1, KeyGenMsg2, KeyGenMsg3, KeyGenMsg4, Protocol, SignMsg1, SignMsg2},
    util::reverse_hex_str,
};

use bitcoin::{hashes::sha256d, secp256k1::Signature, Transaction};
use cfg_if::cfg_if;
use curv::{
    arithmetic::traits::Converter,
    elliptic::curves::traits::ECPoint,
    {BigInt, FE, GE},
};
pub use kms::ecdsa::two_party::*;
pub use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use rocket::State;
use rocket_contrib::json::Json;
use std::string::ToString;
use uuid::Uuid;

cfg_if! {
    if #[cfg(any(test,feature="mockdb"))]{
        use crate::MockDatabase;
        type LB = Lockbox::<MockDatabase>;
    } else {
        use crate::PGDatabase;
        type LB = Lockbox::<PGDatabase>;
    }
}

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

impl Ecdsa for LB {
    fn master_key(&self, user_id: Uuid) -> Result<()> {
        unimplemented!()
    }

    fn first_message(&self, key_gen_msg1: KeyGenMsg1) -> Result<(Uuid, party_one::KeyGenFirstMsg)> {
        unimplemented!()
    }

    fn second_message(&self, key_gen_msg2: KeyGenMsg2) -> Result<party1::KeyGenParty1Message2> {
        unimplemented!()
    }

    fn third_message(&self, key_gen_msg3: KeyGenMsg3) -> Result<party_one::PDLFirstMessage> {
        unimplemented!()
    }

    fn fourth_message(&self, key_gen_msg4: KeyGenMsg4) -> Result<party_one::PDLSecondMessage> {
        unimplemented!()
    }

    fn sign_first(&self, sign_msg1: SignMsg1) -> Result<party_one::EphKeyGenFirstMsg> {
        unimplemented!()
    }

    fn sign_second(&self, sign_msg2: SignMsg2) -> Result<Vec<Vec<u8>>> {
        unimplemented!()
    }
}

#[post("/ecdsa/keygen/first", format = "json", data = "<key_gen_msg1>")]
pub fn first_message(
    lockbox: State<LB>,
    key_gen_msg1: Json<KeyGenMsg1>,
) -> Result<Json<(Uuid, party_one::KeyGenFirstMsg)>> {
    match lockbox.first_message(key_gen_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/keygen/second", format = "json", data = "<key_gen_msg2>")]
pub fn second_message(
    lockbox: State<LB>,
    key_gen_msg2: Json<KeyGenMsg2>,
) -> Result<Json<party1::KeyGenParty1Message2>> {
    match lockbox.second_message(key_gen_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/keygen/third", format = "json", data = "<key_gen_msg3>")]
pub fn third_message(
    lockbox: State<LB>,
    key_gen_msg3: Json<KeyGenMsg3>,
) -> Result<Json<party_one::PDLFirstMessage>> {
    match lockbox.third_message(key_gen_msg3.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/keygen/fourth", format = "json", data = "<key_gen_msg4>")]
pub fn fourth_message(
    lockbox: State<LB>,
    key_gen_msg4: Json<KeyGenMsg4>,
) -> Result<Json<party_one::PDLSecondMessage>> {
    match lockbox.fourth_message(key_gen_msg4.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/sign/first", format = "json", data = "<sign_msg1>")]
pub fn sign_first(
    lockbox: State<LB>,
    sign_msg1: Json<SignMsg1>,
) -> Result<Json<party_one::EphKeyGenFirstMsg>> {
    match lockbox.sign_first(sign_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/sign/second", format = "json", data = "<sign_msg2>")]
pub fn sign_second(lockbox: State<LB>, sign_msg2: Json<SignMsg2>) -> Result<Json<Vec<Vec<u8>>>> {
    match lockbox.sign_second(sign_msg2.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}
