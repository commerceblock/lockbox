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

use uuid::Uuid;
use curv::{cryptographic_primitives::proofs::sigma_dlog::DLogProof, BigInt, FE, GE};
use curv::elliptic::curves::traits::ECScalar;
use kms::ecdsa::two_party::*;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use reqwest::Error as ReqwestError;

pub struct Lockbox {
    pub client: reqwest::blocking::Client,
    pub endpoint: String,
    pub active: bool,
}

impl Lockbox {
    pub fn new(endpoint: String) -> Lockbox {
        let client = reqwest::blocking::Client::new();
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
    pub t1: FE,
    pub o2_pub: GE,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KUReceiveMsg {
    pub theta: FE,
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

    Ok(serde_json::from_str(value.as_str()).unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    static LOCKBOX_URL: &str = "http://0.0.0.0:8000";

    #[test]
    fn test_keygen() {
        let lockbox = Lockbox::new(LOCKBOX_URL.to_string());

        let shared_key_id = Uuid::new_v4();

        let key_gen_msg1 = KeyGenMsg1 {
            shared_key_id: shared_key_id,
            protocol: Protocol::Deposit,
        };

        let path: &str = "ecdsa/keygen/first";

        let (return_id, key_gen_first_msg): (Uuid, party_one::KeyGenFirstMsg) = post_lb(&lockbox, path, &key_gen_msg1).unwrap();

        assert_eq!(return_id,shared_key_id);

        // generate a secret key share
        let key_share_priv: FE = ECScalar::new_random(); // convert to curv lib

        let (kg_party_two_first_message, kg_ec_key_pair_party2) =
            MasterKey2::key_gen_first_message_predefined(&key_share_priv);

        let key_gen_msg2 = KeyGenMsg2 {
            shared_key_id: shared_key_id,
            dlog_proof: kg_party_two_first_message.d_log_proof,
        };

        let path: &str = "ecdsa/keygen/second";
        let kg_party_one_second_message: party1::KeyGenParty1Message2 = post_lb(&lockbox, path, &key_gen_msg2).unwrap();

        let key_gen_second_message = MasterKey2::key_gen_second_message(
            &key_gen_first_msg,
            &kg_party_one_second_message,
        );

        let (_, party_two_paillier) = key_gen_second_message.unwrap();

        let master_key = MasterKey2::set_master_key(
            &BigInt::from(0),
            &kg_ec_key_pair_party2,
            &kg_party_one_second_message
                .ecdh_second_message
                .comm_witness
                .public_share,
            &party_two_paillier,
        );

        // start signing process
        let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();

        let sign_msg1 = SignMsg1 {
            shared_key_id: shared_key_id,
            eph_key_gen_first_message_party_two,
        };

        let path: &str = "ecdsa/sign/first";
        let sign_party_one_first_message: party_one::EphKeyGenFirstMsg =
            post_lb(&lockbox, path, &sign_msg1).unwrap();

    }

}