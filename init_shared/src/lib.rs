//! Requests
//!
//! Send requests and decode responses
#![feature(proc_macro_hygiene, decl_macro)]
extern crate serde;
extern crate serde_json;
extern crate reqwest;
extern crate uuid;
#[macro_use]
extern crate serde_derive;
extern crate centipede;
extern crate curv;
extern crate kms;
extern crate multi_party_ecdsa;
extern crate zk_paillier;
extern crate bitcoin;
extern crate subtle;
extern crate hex;
extern crate shared_lib;
#[macro_use]
extern crate serial_test;
use std::time::Duration;

use uuid::Uuid;
use curv::cryptographic_primitives::proofs::sigma_dlog::DLogProof;
use curv::elliptic::curves::traits::ECScalar;
use curv::{
    arithmetic::traits::Converter,
    elliptic::curves::traits::ECPoint,
    {BigInt, FE, GE},
};
use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use reqwest::Error as ReqwestError;
use bitcoin::secp256k1::{Signature, PublicKey, Message, Secp256k1};
use subtle::ConstantTimeEq;
use std::env;
use shared_lib::structs::{EnclaveIDMsg, DHMsg1, DHMsg2, DHMsg3, ExchangeReportMsg};

pub struct Lockbox {
    pub client: reqwest::blocking::Client,
    pub endpoint: String,
    pub active: bool,
}

impl Lockbox {
    pub fn new(endpoint: String) -> Lockbox {
        let client = reqwest::blocking::Client::builder().timeout(Duration::from_secs(60)).build().unwrap();
        let active = endpoint.len() > 0;
        let lb = Lockbox {
            client,
            endpoint,
            active,
        };
        lb
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub enum Protocol {
    Deposit,
    Transfer,
    Withdraw,
}

// 2P-ECDSA Co-signing algorithm structs

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyGenMsg1 {
    pub shared_key_id: Uuid,
    pub protocol: Protocol,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyGenMsg2 {
    pub shared_key_id: Uuid,
    pub dlog_proof: DLogProof,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignMsg1 {
    pub shared_key_id: Uuid,
    pub eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignSecondMsgRequest {
    pub protocol: Protocol,
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignMsg2 {
    pub shared_key_id: Uuid,
    pub sign_second_msg_request: SignSecondMsgRequest,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KUSendMsg {
    pub user_id: Uuid,
    pub statechain_id: Uuid,
    pub x1: FE,
    pub t2: FE,
    pub o2_pub: GE,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KUReceiveMsg {
    pub s2_pub: GE,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KUFinalize {
    pub statechain_id: Uuid,
    pub shared_key_id: Uuid,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KUAttest {
    pub statechain_id: Uuid,
    pub attestation: String,
}

#[derive(Debug, Serialize, Deserialize, Clone, PartialEq)]
pub enum CError {
    /// Generic error from string error message
    Generic(String),
}

impl From<ReqwestError> for CError {
    fn from(e: ReqwestError) -> CError {
        CError::Generic(e.to_string())
    }
}

pub type Result<T> = std::result::Result<T, CError>;

pub fn post_lb<T, V>(lockbox: &Lockbox, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    _post_lb(lockbox, path, body)
}

fn _post_lb<T, V>(lockbox: &Lockbox, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    // catch reqwest errors
    let value = match lockbox.client.post(&format!("{}/{}", lockbox.endpoint, path)).json(&body).send() 
    {
        Ok(v) => {
            //Reject responses that are too long
            match v.content_length() {
                Some(l) => {
                    if l > 1000000 {
                        return Err(CError::Generic(format!(
                            "POST value ignored because of size: {}",
                            l
                        )));
                    }
                }
                None => (),
            };

            let text = v.text()?;

            text
        }
        Err(e) => return Err(CError::from(e)),
    };
    match serde_json::from_str(value.as_str()) {
	Ok(r) => Ok(r),
	Err(e) => {
	    Err(CError::Generic(format!("Error derserialising POST response: {}: {}", value.as_str(), e)))
	}
    }
}

pub fn get_lb<V>(lockbox: &Lockbox, path: &str) -> Result<V>
where
    V: serde::de::DeserializeOwned,
{
    std::thread::sleep(std::time::Duration::from_millis(100));

    let mut b = lockbox
        .client
        .get(&format!("{}/{}", lockbox.endpoint, path));

    // catch reqwest errors
    let value = match b.send() {
        Ok(v) => v.text().unwrap(),
        Err(e) => return Err(CError::from(e)),
    };

    // catch State entity errors
    if value.contains(&String::from("Error: ")) {
        return Err(CError::Generic(value));
    }

    Ok(serde_json::from_str(value.as_str()).unwrap())
}

// verify 2P ECDSA signature
pub fn verify(r: &BigInt, s: &BigInt, pubkey: &GE, message: &BigInt) -> bool {
    let s_fe: FE = ECScalar::from(&s);
    let rx_fe: FE = ECScalar::from(&r);

    let s_inv_fe = s_fe.invert();
    let e_fe: FE = ECScalar::from(&message.mod_floor(&FE::q()));
    let u1 = GE::generator() * e_fe * s_inv_fe;
    let u2 = *pubkey * rx_fe * s_inv_fe;

    // second condition is against malleability
    let rx_bytes = &BigInt::to_vec(&r)[..];
    let u1_plus_u2_bytes = &BigInt::to_vec(&(u1 + u2).x_coor().unwrap())[..];

    let cond1 = rx_bytes.ct_eq(&u1_plus_u2_bytes).unwrap_u8() == 1;
    let cond2 = s < &(FE::q() - s.clone());

    if cond1 && cond2
    {
        return true
    } else {
        return false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn init_dh() -> Lockbox {
	let lockbox_url: &str = &env::var("LOCKBOX_URL").unwrap_or("http://0.0.0.0:8000".to_string());
	
        let lockbox = Lockbox::new(lockbox_url.to_string());

	println!("...getting src enclave id...\n");
	let enclave_id_msg = get_lb::<EnclaveIDMsg>(&lockbox, "attestation/enclave_id").unwrap();

	println!("enclave id: {:?}", enclave_id_msg);

	println!("...requesting session...\n");
	let dhmsg1: DHMsg1 = post_lb(&lockbox, "attestation/session_request", &enclave_id_msg).unwrap();

	println!("...proc_msg1: {:?}\n", dhmsg1);
	let dh_msg2: DHMsg2 = post_lb(&lockbox, "attestation/proc_msg1", &dhmsg1).unwrap();

	let rep_msg = ExchangeReportMsg {
	    src_enclave_id: enclave_id_msg.inner,
	    dh_msg2,
	};
	
	let dh_msg3: DHMsg3 = post_lb(&lockbox, "attestation/exchange_report", &rep_msg).unwrap();

	println!("...proc_msg3...\n");
	let res: () = post_lb(&lockbox, "attestation/proc_msg3", &dh_msg3).unwrap();
	
    println!("...finished\n");
	
	lockbox
    }
    
    #[serial]
    #[test]
    fn test_dh() {
	let _lockbox = init_dh();
    }
	
}
