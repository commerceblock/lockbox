#[macro_use] extern crate rocket;

mod utils;
use rocket::serde::{Deserialize, Serialize};
use rocket::serde::json::{Json};

use rocket::local::blocking::Client;
use rocket::http::{ContentType, Status};
use rocket::serde::json::json;
use rocket::fairing::AdHoc;
use rocket::State;

use std::sync::{Arc, Mutex};
use num_bigint::BigInt;
use base64::{encode, decode};
use shamir_secret_sharing::ShamirSecretSharing as SSS;

const SHAMIR_SHARES: usize = 3;
const SHAMIR_THRESHOLD: usize = 2;

const CURVE: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";

#[derive(Debug, Clone)]
pub struct KeysAttr {
    keys: Arc<Mutex<Vec<Option<String>>>>,
    sss: SSS,
    recovered_secret: Arc<Mutex<Option<BigInt>>>,
}

#[derive(Debug, Clone)]
pub struct GlobalState {
    signing: KeysAttr,
    topup: KeysAttr
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct TxDetails {
    sighash_string: Vec<String>,
    merkle_root: String,
}

pub fn get_default_global_state() -> GlobalState {
    let sss = SSS {
        threshold: SHAMIR_THRESHOLD,
        share_amount: SHAMIR_SHARES,
        prime: BigInt::parse_bytes(CURVE.as_bytes(), 16).unwrap()
    };
    let keys_attr = KeysAttr {
        keys: Arc::new(Mutex::new(Vec::with_capacity(SHAMIR_SHARES))),
        sss: sss.clone(),
        recovered_secret: Arc::new(Mutex::new(None))
    };

    let global_state = GlobalState {
        signing: keys_attr.clone(),
        topup: keys_attr.clone()
    };

    return global_state;
}

#[post("/sign", format="json", data="<tx_details>")]
pub fn sign(state: &State<GlobalState>, tx_details: Json<TxDetails>) -> String {
    let sign = utils::sign_tx(
        state,
        tx_details.sighash_string.clone(), 
        tx_details.merkle_root.clone(),
    );
    json!({
        "witness": sign
    }).to_string()
}

#[post("/initialize/<key_type>", data = "<share>")]
pub fn initialize(state: &State<GlobalState>, key_type: String, share: String) -> String {
    let mut keys_attr: KeysAttr;
    if key_type == "signing" {
        keys_attr = state.signing.clone();
    } else if key_type == "topup" {
        keys_attr = state.topup.clone();
    } else {
        return json!({
            "status": "bad request, invalid key type",
        }).to_string();
    }

    let mut keys = keys_attr.keys.lock().unwrap();
    if keys.len() < SHAMIR_THRESHOLD {
        keys.push(Some(share.clone()));
    }

    // Check if enough shares have been received to recover the secret
    if keys.len() == SHAMIR_THRESHOLD {

        let mut shares: Vec<(usize, BigInt)> = Vec::new();

        for (index, key) in keys.iter().enumerate() {
            shares.push((index+1, BigInt::parse_bytes(&key.clone().unwrap().as_bytes(), 16).unwrap()));
        }
        let recovered_secret = keys_attr.sss.recover(&shares);
        *keys_attr.recovered_secret.lock().unwrap() = Some(recovered_secret.clone());

        return json!({
            "status": format!("accepted key for {:?}, threshold reached", key_type),
            "shared_keys": keys.len()
        }).to_string();
    }

    json!({
        "status": "accepted",
        "shared_keys": keys.len()
    }).to_string()
}

#[launch]
fn rocket() -> _ {
    let global_state = get_default_global_state();

    rocket::build()
        .attach(AdHoc::on_ignite("Initialize Global State", |rocket| {
            Box::pin(async move {
                rocket.manage(global_state.clone())
            })
        }))
        .mount("/", routes![sign, initialize])
}

#[test]
fn test_sign() {
    let global_state = get_default_global_state();
    *global_state.signing.recovered_secret.lock().unwrap() = BigInt::parse_bytes(b"77822a5eaa0755fdeff332a40e4c30a3184bde3495afebd1c58cbd7771dd091b", 16);
    *global_state.topup.recovered_secret.lock().unwrap() = BigInt::parse_bytes(b"e213cd24a754a2d37d02c1831191321ddaaf7cffebeb68bdd481cbff879fe5c7", 16);

    let rocket = rocket::build()
                    .attach(AdHoc::on_ignite("Initialize Global State", |rocket| {
                        Box::pin(async move {
                            rocket.manage(global_state.clone())
                        })
                    }))
                    .mount("/", routes![sign]);
    let client = Client::new(rocket).expect("valid rocket instance");

    let tx_details = TxDetails {
        sighash_string: vec!["8d0ad2782d8f6e3f63c6f9611841c239630b55061d558abcc6bac53349edac70".to_string()],
        merkle_root: "8d0ad2782d8f6e3f63c6f9611841c239630b55061d558abcc6bac53349edac70".to_string(),
    };

    let response = client.post("/sign")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&tx_details).unwrap())
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
}

#[test]
fn test_initialize() {
    let global_state = get_default_global_state();
    let sss = global_state.signing.sss.clone();

    let rocket = rocket::build()
                    .attach(AdHoc::on_ignite("Initialize Global State", |rocket| {
                        Box::pin(async move {
                            rocket.manage(global_state.clone())
                        })
                    }))
                    .mount("/", routes![initialize]);
    let client = Client::new(rocket).expect("valid rocket instance");

    let secret = BigInt::parse_bytes(b"ffffffffffffffffffffffffffffffffffffff", 16).unwrap();
    let shares = sss.split(secret.clone());

    for i in 0..SHAMIR_THRESHOLD {
        let response = client.post("/initialize/signing")
            .body(shares[i].1.to_str_radix(16))
            .dispatch();

        assert_eq!(response.status(), Status::Ok);
    }

    let global_state = client.rocket().state::<GlobalState>().unwrap();
    let recovered_secret = global_state.signing.recovered_secret.lock().unwrap().clone().unwrap();

    // Compare the recovered secret with the expected value
    assert_eq!(recovered_secret, secret);
}
