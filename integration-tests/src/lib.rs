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
extern crate ecies;
#[macro_use]
extern crate serial_test;

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

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct FESer {
    pub secret_bytes: Vec<u8>,
}

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
    pub t2: FESer,
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

    println!("...proc_msg1...\n");
    let dh_msg2: DHMsg2 = post_lb(&lockbox, "attestation/proc_msg1", &dhmsg1).unwrap();

    let rep_msg = ExchangeReportMsg {
        src_enclave_id: enclave_id_msg.inner,
        dh_msg2,
    };
    
    let dh_msg3: DHMsg3 = post_lb(&lockbox, "attestation/exchange_report", &rep_msg).unwrap();

    println!("...proc_msg3...\n");
    let res: () = post_lb(&lockbox, "attestation/proc_msg3", &dh_msg3).unwrap();
    
    
    let shared_key_id = Uuid::new_v4();
        let key_gen_msg1 = KeyGenMsg1 {
            shared_key_id: shared_key_id,
            protocol: Protocol::Deposit,
        };
    println!("keygen first");
    
        let path: &str = "ecdsa/keygen/first";
    println!("int test: first message");
        let (return_id, key_gen_first_msg): (Uuid, party_one::KeyGenFirstMsg) = post_lb(&lockbox, path, &key_gen_msg1).unwrap();
     
        lockbox
    }
    
    #[serial]
    #[test]
    fn test_dh() {
    let _lockbox = init_dh();
    }

    
    #[serial]
    #[test]
    fn test_keygen() {
        let lockbox_url: &str = &env::var("LOCKBOX_URL").unwrap_or("http://0.0.0.0:8000".to_string());
    
        let lockbox = Lockbox::new(lockbox_url.to_string());

        let shared_key_id = Uuid::new_v4();

        let key_gen_msg1 = KeyGenMsg1 {
            shared_key_id: shared_key_id,
            protocol: Protocol::Deposit,
        };

    println!("keygen first");
    
        let path: &str = "ecdsa/keygen/first";
    println!("int test: first message");
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
    println!("int test: second message");
        let kg_party_one_second_message: party1::KeyGenParty1Message2 = post_lb(&lockbox, path, &key_gen_msg2).unwrap();

        let key_gen_second_message = MasterKey2::key_gen_second_message(
            &key_gen_first_msg,
            &kg_party_one_second_message,      
        );

        let (_, party_two_paillier) = key_gen_second_message.unwrap();

        let _master_key = MasterKey2::set_master_key(
            &BigInt::from(0),
            &kg_ec_key_pair_party2,
            &kg_party_one_second_message
                .ecdh_second_message
                .comm_witness
                .public_share,
            &party_two_paillier,
        );
    }

    #[serial]
    #[test]
    fn test_sign_keygen() {
        let lockbox_url: &str = &env::var("LOCKBOX_URL").unwrap_or("http://0.0.0.0:8000".to_string());
    
        let lockbox = Lockbox::new(lockbox_url.to_string());
    
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

        // choose message to sign
        let message = BigInt::from(1);

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

        let party_two_sign_message = master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness.clone(),
            &sign_party_one_first_message,
            &message,
        );

        let msg = message.clone();

        let sign_msg2 = SignMsg2 {
            shared_key_id: shared_key_id,
            sign_second_msg_request: SignSecondMsgRequest {
                protocol: Protocol::Deposit,
                message,
                party_two_sign_message,
            },
        };

        let path: &str = "ecdsa/sign/second";
        let der_signature: Vec<Vec<u8>> =  post_lb(&lockbox, path, &sign_msg2).unwrap();

        assert_eq!(der_signature.len(),2);
        assert_eq!(der_signature[1].len(),33);

        let sig = Signature::from_der_lax(&der_signature[0][..]).unwrap();
        let sig_compact = sig.serialize_compact();

        let r = BigInt::from_hex(&hex::encode(&sig_compact[0..32]));
        let s = BigInt::from_hex(&hex::encode(&sig_compact[32..64]));

        let _rec_pub = PublicKey::from_slice(&der_signature[1][..]).unwrap();
        let pk_vec = master_key.public.q;
        let ver = verify(&r,&s,&pk_vec,&msg);

        assert!(ver);

    }

    #[serial]
    #[test]
    fn test_transfer_sign_keygen() {
        let lockbox_url: &str = &env::var("LOCKBOX_URL").unwrap_or("http://0.0.0.0:8000".to_string());

        let lockbox = Lockbox::new(lockbox_url.to_string());

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

        // choose message to sign
        let message = BigInt::from(1);

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

        let party_two_sign_message = master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness.clone(),
            &sign_party_one_first_message,
            &message,
        );

        let msg = message.clone();

        let sign_msg2 = SignMsg2 {
            shared_key_id: shared_key_id,
            sign_second_msg_request: SignSecondMsgRequest {
                protocol: Protocol::Deposit,
                message,
                party_two_sign_message,
            },
        };

        let path: &str = "ecdsa/sign/second";
        let der_signature: Vec<Vec<u8>> =  post_lb(&lockbox, path, &sign_msg2).unwrap();
    
        assert_eq!(der_signature.len(),2);
        assert_eq!(der_signature[1].len(),33);

        let sig = Signature::from_der_lax(&der_signature[0][..]).unwrap();
        let sig_compact = sig.serialize_compact();

        let r = BigInt::from_hex(&hex::encode(&sig_compact[0..32]));
        let s = BigInt::from_hex(&hex::encode(&sig_compact[32..64]));

        let _rec_pub = PublicKey::from_slice(&der_signature[1][..]).unwrap();
        let pk_vec = master_key.public.q;
        let ver = verify(&r,&s,&pk_vec,&msg);

        assert!(ver);

        // do transfer
        let statechain_id = Uuid::new_v4();

        let o1 = master_key.private.get_private_key();
        let x1 = FE::new_random();
        let t1 = o1 * x1;
        let o2 = FE::new_random();

        let g: GE = ECPoint::generator();
        let o2_pub: GE = g * o2;

        let t2 = t1 * (o2.invert());

        let pk_bytes = &kg_party_one_second_message
                .ecdh_second_message
                .comm_witness
                .public_share.pk_to_key_slice();

        let t2s = t2.clone().get_element().to_string();

        let t2_bytes = hex::decode(&t2s).expect("hex decode error");
        let encrypted = ecies::encrypt(pk_bytes, &t2_bytes).unwrap();


        let ku_send = KUSendMsg {
            user_id: shared_key_id,
            statechain_id: statechain_id,
            x1: x1,
            t2: FESer { secret_bytes: encrypted },
            o2_pub: o2_pub,
        };

        let path: &str = "ecdsa/keyupdate/first";
        let ku_receive: KUReceiveMsg = post_lb(&lockbox, path, &ku_send).unwrap();               

        let new_shared_key_id = Uuid::new_v4();

        let ku_send = KUFinalize {
            statechain_id,
            shared_key_id: new_shared_key_id,
        };

        let path: &str = "ecdsa/keyupdate/second";
        let ku_attest: KUAttest = post_lb(&lockbox, path, &ku_send).unwrap();

        assert_eq!(ku_attest.statechain_id,statechain_id);

        //generate new shared key
        let key_gen_msg1_2 = KeyGenMsg1 {
            shared_key_id: new_shared_key_id,
            protocol: Protocol::Transfer,
        };

        let path: &str = "ecdsa/keygen/first";
        let (return_id_2, key_gen_first_msg_2): (Uuid, party_one::KeyGenFirstMsg) = post_lb(&lockbox, path, &key_gen_msg1_2).unwrap();

        assert_eq!(return_id_2,new_shared_key_id);

        let (kg_party_two_first_message_2, kg_ec_key_pair_party2_2) =
            MasterKey2::key_gen_first_message_predefined(&o2);

        let key_gen_msg2_2 = KeyGenMsg2 {
            shared_key_id: new_shared_key_id,
            dlog_proof: kg_party_two_first_message_2.d_log_proof,
        };

        let path: &str = "ecdsa/keygen/second";
        let kg_party_one_second_message_2: party1::KeyGenParty1Message2 = post_lb(&lockbox, path, &key_gen_msg2_2).unwrap();

        let key_gen_second_message_2 = MasterKey2::key_gen_second_message(
            &key_gen_first_msg_2,
            &kg_party_one_second_message_2,
        );

        let (_, party_two_paillier_2) = key_gen_second_message_2.unwrap();

        let master_key_2 = MasterKey2::set_master_key(
            &BigInt::from(0),
            &kg_ec_key_pair_party2_2,
            &kg_party_one_second_message_2
                .ecdh_second_message
                .comm_witness
                .public_share,
            &party_two_paillier_2,
        );

        //confirm public key after transfer
        assert_eq!(ku_receive.s2_pub*o2,master_key_2.public.q);

        //confirm public keys are the same
        assert_eq!(master_key.public.q, master_key_2.public.q);        

        // choose message to sign
        let message = BigInt::from(2);

        // start signing process
        let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();

        let sign_msg1 = SignMsg1 {
            shared_key_id: new_shared_key_id,
            eph_key_gen_first_message_party_two,
        };

        let path: &str = "ecdsa/sign/first";
        let sign_party_one_first_message: party_one::EphKeyGenFirstMsg =
            post_lb(&lockbox, path, &sign_msg1).unwrap();

        let party_two_sign_message = master_key_2.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness.clone(),
            &sign_party_one_first_message,
            &message,
        );

        let msg = message.clone();

        let sign_msg2 = SignMsg2 {
            shared_key_id: new_shared_key_id,
            sign_second_msg_request: SignSecondMsgRequest {
                protocol: Protocol::Deposit,
                message,
                party_two_sign_message,
            },
        };

        let path: &str = "ecdsa/sign/second";
        let der_signature: Vec<Vec<u8>> =  post_lb(&lockbox, path, &sign_msg2).unwrap();

        assert_eq!(der_signature.len(),2);
        assert_eq!(der_signature[1].len(),33);

        let sig = Signature::from_der_lax(&der_signature[0][..]).unwrap();
        let sig_compact = sig.serialize_compact();

        let r = BigInt::from_hex(&hex::encode(&sig_compact[0..32]));
        let s = BigInt::from_hex(&hex::encode(&sig_compact[32..64]));

        let _rec_pub = PublicKey::from_slice(&der_signature[1][..]).unwrap();
        let pk_vec = master_key_2.public.q;
        let ver = verify(&r,&s,&pk_vec,&msg);

        assert!(ver);

    }
    
}
