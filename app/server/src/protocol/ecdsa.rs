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
	self.database.put(user_db_key, &sealed_secrets)?;

	Ok((key_gen_msg1.shared_key_id, key_gen_first_mess))
     }

    fn second_message(&self, key_gen_msg2: KeyGenMsg2) -> Result<Option<party1::KeyGenParty1Message2>> {
//	let db = &self.database;

//        let user_id = &key_gen_msg2.shared_key_id;
//	let user_db_key = &Key::from_uuid(user_id);

  //      let party2_public: GE = key_gen_msg2.dlog_proof.pk.clone();

//	let sealed_secrets = match db.get(user_db_key) {
//	    Ok(Some(x)) => x,
//	    Ok(None) => return Err(LockboxError::Generic(format!("second_message: sealed_secrets for DB key {} is None", user_id))),
//	    Err(e) => return Err(e.into())
//	}
	
//        let (comm_witness, ec_key_pair) = db.get_ecdsa_witness_keypair(user_id)?;


	
//        let (kg_party_one_second_message, paillier_key_pair, party_one_private): (
///            party1::KeyGenParty1Message2,
 //           party_one::PaillierKeyPair,
//            party_one::Party1Private,
//        ) = MasterKey1::key_gen_second_message(
//            comm_witness,
//            &ec_key_pair,
//            &key_gen_msg2.dlog_proof,
//        );

//        db.update_keygen_second_msg(
//            &user_id,
//            party2_public,
////            paillier_key_pair,
//            party_one_private,
//        )?;

  

//        Ok(kg_party_one_second_message)

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

