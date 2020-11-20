pub use super::super::Result;

use crate::error::LockboxError;
use crate::server::Lockbox;
use shared_lib::{
    structs::{KeyGenMsg1, KeyGenMsg2, KeyGenMsg3, KeyGenMsg4, SignMsg1, SignMsg2},
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

/// 2P-ECDSA protocol trait
pub trait Ecdsa {
    fn master_key(&self, user_id: Uuid) -> Result<()>;

    fn first_message(&self, key_gen_msg1: KeyGenMsg1) -> Result<(Uuid, party_one::KeyGenFirstMsg)>;

    fn second_message(&self, key_gen_msg2: KeyGenMsg2) -> Result<Option<party1::KeyGenParty1Message2>>;

    fn third_message(&self, key_gen_msg3: KeyGenMsg3) -> Result<Option<party_one::PDLFirstMessage>>;

    fn fourth_message(&self, key_gen_msg4: KeyGenMsg4) -> Result<Option<party_one::PDLSecondMessage>>;

    fn sign_first(&self, sign_msg1: SignMsg1) -> Result<Option<party_one::EphKeyGenFirstMsg>>;

    fn sign_second(&self, sign_msg2: SignMsg2) -> Result<Vec<Vec<u8>>>;
}

impl Ecdsa for Lockbox {
    fn master_key(&self, _user_id: Uuid) -> Result<()> {
	Ok(())
    }


    fn first_message(&self, key_gen_msg1: KeyGenMsg1) -> Result<(Uuid, party_one::KeyGenFirstMsg)> {

        // Generate shared key
        let (key_gen_first_msg, comm_witness, ec_key_pair) =
//            if key_gen_msg1.protocol == Protocol::Deposit {
                MasterKey1::key_gen_first_message();
  //          } else {
    //            let s2: FE = db.get_ecdsa_s2(user_id)?;
      //          let theta: FE = db.get_ecdsa_theta(user_id)?;
        //        MasterKey1::key_gen_first_message_predefined(s2 * theta)
          //  };

	
	let user_id = &Key::from_uuid(&key_gen_msg1.shared_key_id);

        // Create new entry in ecdsa table if key not already in table.
        match self.database.get(user_id) {
            Ok(Some(_)) =>  {
                return Err(LockboxError::Generic(format!(
                    "Key Generation already completed for ID {}",
                    user_id
                )))
            },
	    Ok(None) => (),
            Err(e) => return Err(e.into()),
        };

	/*
        // Generate shared key
        let (key_gen_first_msg, comm_witness, ec_key_pair) =
            if key_gen_msg1.protocol == Protocol::Deposit {
                MasterKey1::key_gen_first_message()
            } else {
                let s2: FE = db.get_ecdsa_s2(user_id)?;
                let theta: FE = db.get_ecdsa_theta(user_id)?;
                MasterKey1::key_gen_first_message_predefined(s2 * theta)
            };

        db.update_keygen_first_msg(&user_id, &key_gen_first_msg, comm_witness, ec_key_pair)?;
         */

	Ok((Uuid::nil(), party_one::KeyGenFirstMsg {
	    pk_commitment: BigInt::zero(),
	    zk_pok_commitment: BigInt::zero(),
	}))
    }

    fn second_message(&self, key_gen_msg2: KeyGenMsg2) -> Result<Option<party1::KeyGenParty1Message2>> {
	Ok(None)
    }

    fn third_message(&self, key_gen_msg3: KeyGenMsg3) -> Result<Option<party_one::PDLFirstMessage>> {
	Ok(None)
    }

    fn fourth_message(&self, key_gen_msg4: KeyGenMsg4) -> Result<Option<party_one::PDLSecondMessage>> {
	Ok(None)
    }

    fn sign_first(&self, sign_msg1: SignMsg1) -> Result<Option<party_one::EphKeyGenFirstMsg>> {
	Ok(None)
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

#[post("/ecdsa/keygen/third", format = "json", data = "<key_gen_msg3>")]
pub fn third_message(
    lockbox: State<Lockbox>,
    key_gen_msg3: Json<KeyGenMsg3>,
) -> Result<Json<Option<party_one::PDLFirstMessage>>> {
    match lockbox.third_message(key_gen_msg3.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/ecdsa/keygen/fourth", format = "json", data = "<key_gen_msg4>")]
pub fn fourth_message(
    lockbox: State<Lockbox>,
    key_gen_msg4: Json<KeyGenMsg4>,
) -> Result<Json<Option<party_one::PDLSecondMessage>>> {
    match lockbox.fourth_message(key_gen_msg4.into_inner()) {
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

