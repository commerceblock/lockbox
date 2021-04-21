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
extern crate ecies;

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

    let client = reqwest::blocking::Client::new();
    // catch reqwest errors
    let value = match client.post(&format!("{}/{}", lockbox.endpoint, path)).json(&body).send()
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

    #[test]
    fn fuzz_cycle_full() {

        // repetitions
        const NCYCLE: u32 = 1;        

        let lockbox_url: &str = &env::var("LOCKBOX_URL").unwrap_or("http://209.250.253.39:8000".to_string());
        let lockbox = Lockbox::new(lockbox_url.to_string());

        // loop keygen
        for iter in 0..NCYCLE {

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

            println!("{:?}", "done keygen first");

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

            println!("{:?}", "done keygen second");

            // choose message to sign
            let message = FE::new_random().to_big_int();
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

                        println!("{:?}", "done sign first");

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

            println!("{:?}", "done sign second");

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

                        println!("{:?}", "done ku first");

            let path: &str = "ecdsa/keyupdate/second";
            let ku_attest: KUAttest = post_lb(&lockbox, path, &ku_send).unwrap();

            assert_eq!(ku_attest.statechain_id,statechain_id);

            //generate new shared key
            let key_gen_msg1_2 = KeyGenMsg1 {
                shared_key_id: new_shared_key_id,
                protocol: Protocol::Transfer,
            };

            println!("{:?}", "done ku second");

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
            let message = FE::new_random().to_big_int();
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

            println!("Iteration {:?}", iter);
        }
    }

    #[test]
    fn fuzz_cycle_transfer() {

        // repetitions
        const NCYCLE: u32 = 10;        

        let lockbox_url: &str = &env::var("LOCKBOX_URL").unwrap_or("http://209.250.253.39:8000".to_string());
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
        let message = FE::new_random().to_big_int();
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

        let statechain_id = Uuid::new_v4();

        //loop transfer
        for iter in 0..NCYCLE {

            // do transfer
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

            println!("{:?}", master_key.public.q);

            // choose message to sign
            let message = FE::new_random().to_big_int();
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

            let shared_key_id = new_shared_key_id;
            let master_key = master_key_2;

            println!("Iteration {:?}", iter);

        }
    }

    #[test]
    fn fuzz_interlace() {

        // repetitions
        const NCYCLE: u32 = 1;        

        let lockbox_url: &str = &env::var("LOCKBOX_URL").unwrap_or("http://209.250.253.39:8000".to_string());
        let lockbox = Lockbox::new(lockbox_url.to_string());

        let mut shared_key_id: Vec<Uuid> = vec![];
        let mut new_shared_key_id: Vec<Uuid> = vec![];
        let mut key_gen_first_msg: Vec<party_one::KeyGenFirstMsg> = vec![];
        let mut master_key: Vec<MasterKey2> = vec![];
        let mut message: Vec<BigInt> = vec![];
        let mut sign_msg2: Vec<SignMsg2> = vec![];
        let mut statechain_id: Vec<Uuid> = vec![];
        let mut kg_party_one_second_message: Vec<party1::KeyGenParty1Message2> = vec![];
        let mut ku_receive: Vec<KUReceiveMsg> = vec![];
        let mut o2: Vec<FE> = vec![];

        for iter in 0..NCYCLE {        

            let shared_key_id0 = Uuid::new_v4();
            let key_gen_msg1 = KeyGenMsg1 {
                shared_key_id: shared_key_id0,
                protocol: Protocol::Deposit,
            };

            shared_key_id.push(shared_key_id0);

            let path: &str = "ecdsa/keygen/first";
            let (return_id, key_gen_first_msg0): (Uuid, party_one::KeyGenFirstMsg) = post_lb(&lockbox, path, &key_gen_msg1).unwrap();
            assert_eq!(return_id,shared_key_id0);

            key_gen_first_msg.push(key_gen_first_msg0);

            println!("Keygen first iteration {:?}", iter);
        }

        for iter in 0..NCYCLE {      

            // generate a secret key share
            let key_share_priv: FE = ECScalar::new_random(); // convert to curv lib
            let (kg_party_two_first_message, kg_ec_key_pair_party2) =
                MasterKey2::key_gen_first_message_predefined(&key_share_priv);

            let key_gen_msg2 = KeyGenMsg2 {
                shared_key_id: shared_key_id[iter as usize],
                dlog_proof: kg_party_two_first_message.d_log_proof,
            };

            let path: &str = "ecdsa/keygen/second";
            let kg_party_one_second_message0: party1::KeyGenParty1Message2 = post_lb(&lockbox, path, &key_gen_msg2).unwrap();

            let key_gen_second_message = MasterKey2::key_gen_second_message(
                &key_gen_first_msg[iter as usize],
                &kg_party_one_second_message0,
            );

            let (_, party_two_paillier) = key_gen_second_message.unwrap();

            let master_key0 = MasterKey2::set_master_key(
                &BigInt::from(0),
                &kg_ec_key_pair_party2,
                &kg_party_one_second_message0
                    .ecdh_second_message
                    .comm_witness
                    .public_share,
                &party_two_paillier,
            );
            master_key.push(master_key0);
            kg_party_one_second_message.push(kg_party_one_second_message0);

            println!("Keygen second iteration {:?}", iter);
        }

        for iter in 0..NCYCLE {
            // choose message to sign
            let message0 = FE::new_random().to_big_int();
            // start signing process
            let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
                MasterKey2::sign_first_message();
            let sign_msg1 = SignMsg1 {
                shared_key_id: shared_key_id[iter as usize],
                eph_key_gen_first_message_party_two,
            };

            let path: &str = "ecdsa/sign/first";
            let sign_party_one_first_message: party_one::EphKeyGenFirstMsg =
                post_lb(&lockbox, path, &sign_msg1).unwrap();
            let party_two_sign_message = master_key[iter as usize].sign_second_message(
                &eph_ec_key_pair_party2,
                eph_comm_witness.clone(),
                &sign_party_one_first_message,
                &message0,
            );
            let msg = message0.clone();
            message.push(msg);
            let sign_msg20 = SignMsg2 {
                shared_key_id: shared_key_id[iter as usize],
                sign_second_msg_request: SignSecondMsgRequest {
                    protocol: Protocol::Deposit,
                    message: message[iter as usize].clone(),
                    party_two_sign_message: party_two_sign_message,
                },
            };
            sign_msg2.push(sign_msg20);

            println!("Sign first iteration {:?}", iter);
        }


        for iter in 0..NCYCLE {  
            let path: &str = "ecdsa/sign/second";
            let der_signature: Vec<Vec<u8>> =  post_lb(&lockbox, path, &sign_msg2[iter as usize]).unwrap();
            assert_eq!(der_signature.len(),2);
            assert_eq!(der_signature[1].len(),33);
            let sig = Signature::from_der_lax(&der_signature[0][..]).unwrap();
            let sig_compact = sig.serialize_compact();
            let r = BigInt::from_hex(&hex::encode(&sig_compact[0..32]));
            let s = BigInt::from_hex(&hex::encode(&sig_compact[32..64]));
            let _rec_pub = PublicKey::from_slice(&der_signature[1][..]).unwrap();
            let pk_vec = master_key[iter as usize].public.q;
            let ver = verify(&r,&s,&pk_vec,&message[iter as usize]);
            assert!(ver);
            println!("Sign second iteration {:?}", iter);
        }

        for iter in 0..NCYCLE {  

            // do transfer
            let statechain_id0 = Uuid::new_v4();
            statechain_id.push(statechain_id0);

            let o1 = master_key[iter as usize].private.get_private_key();
            let x1 = FE::new_random();
            let t1 = o1 * x1;
            let o20 = FE::new_random();
            let g: GE = ECPoint::generator();
            let o2_pub: GE = g * o20;
            let t2 = t1 * (o20.invert());

            o2.push(o20);

            let pk_bytes = &kg_party_one_second_message[iter as usize]
                    .ecdh_second_message
                    .comm_witness
                    .public_share.pk_to_key_slice();

            let t2s = t2.clone().get_element().to_string();
            let t2_bytes = hex::decode(&t2s).expect("hex decode error");
            let encrypted = ecies::encrypt(pk_bytes, &t2_bytes).unwrap();
            let ku_send = KUSendMsg {
                user_id: shared_key_id[iter as usize],
                statechain_id: statechain_id0,
                x1: x1,
                t2: FESer { secret_bytes: encrypted },
                o2_pub: o2_pub,
            };

            let path: &str = "ecdsa/keyupdate/first";
            let ku_receive0: KUReceiveMsg = post_lb(&lockbox, path, &ku_send).unwrap(); 
            ku_receive.push(ku_receive0);              
            let new_shared_key_id0 = Uuid::new_v4();
            new_shared_key_id.push(new_shared_key_id0);

            let ku_send = KUFinalize {
                statechain_id: statechain_id0,
                shared_key_id: new_shared_key_id0,
            };

            let path: &str = "ecdsa/keyupdate/second";
            let ku_attest: KUAttest = post_lb(&lockbox, path, &ku_send).unwrap();

            assert_eq!(ku_attest.statechain_id,statechain_id0);

            println!("Transfer iteration {:?}", iter);
        }

         for iter in 0..NCYCLE {         
            //generate new shared key
            let key_gen_msg1_2 = KeyGenMsg1 {
                shared_key_id: new_shared_key_id[iter as usize],
                protocol: Protocol::Transfer,
            };

            let path: &str = "ecdsa/keygen/first";
            let (return_id_2, key_gen_first_msg_2): (Uuid, party_one::KeyGenFirstMsg) = post_lb(&lockbox, path, &key_gen_msg1_2).unwrap();
            assert_eq!(return_id_2,new_shared_key_id[iter as usize]);
            let (kg_party_two_first_message_2, kg_ec_key_pair_party2_2) =
                MasterKey2::key_gen_first_message_predefined(&o2[iter as usize]);
            let key_gen_msg2_2 = KeyGenMsg2 {
                shared_key_id: new_shared_key_id[iter as usize],
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
            assert_eq!(ku_receive[iter as usize].s2_pub*o2[iter as usize],master_key_2.public.q);
            //confirm public keys are the same
            assert_eq!(master_key[iter as usize].public.q, master_key_2.public.q);

            println!("Transfer keygen iteration {:?}", iter);
        }

    }

}