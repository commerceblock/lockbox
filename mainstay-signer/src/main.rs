#[macro_use] extern crate rocket;

mod utils;
use rocket::serde::{Deserialize, Serialize};
use rocket::serde::json::{Json};

use rocket::local::blocking::Client;
use rocket::http::{ContentType, Status};
use rocket::serde::json::json;

#[derive(Debug, Deserialize, Serialize)]
#[serde(crate = "rocket::serde")]
pub struct TxDetails {
    sighash_string: Vec<String>,
    merkle_root: String,
}

#[post("/sign", format="json", data="<tx_details>")]
pub fn sign(tx_details: Json<TxDetails>) -> String {
    let sign = utils::sign_tx(
        tx_details.sighash_string.clone(), 
        tx_details.merkle_root.clone(),
    );
    json!({
        "witness": sign
    }).to_string()
}

#[launch]
fn rocket() -> _ {
    rocket::build().mount("/", routes![sign])
}

#[test]
fn test_sign() {
    let rocket = rocket::build().mount("/", routes![sign]);
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
