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
    tx_hex: String,
    value: u64,
    merkle_root: String,
    redeem_script_hex: String
}

#[post("/sign", format="json", data="<tx_details>")]
pub fn sign(tx_details: Json<TxDetails>) -> String {
    let sign = utils::sign_tx(
        tx_details.tx_hex.clone(), 
        tx_details.value, 
        tx_details.merkle_root.clone(), 
        tx_details.redeem_script_hex.clone()
    ).unwrap();
    json!({
        "sign": sign
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
        tx_hex: "0200000001c5167dd8f59fc3ed78fbea5ce574f21739de1d3197a704dc8a3f5e1ef0527304000000006f004730440220049d3138f841b63e96725cb9e86a53a92cd1d9e1b0740f5d4cd2ae0bcab684bf0220208d555c7e24e4c01cf67dfa9161091533e9efd6d1602bb53a49f7195c16b03701255121036bd7943325ed9c9e1a44d98a8b5759c4bf4807df4312810ed5fc09dfb967811951aefdffffff01e4e10f000000000017a91429d13058087ddf2d48de404376fdcb5c4abff4bc8700000000".to_string(),
        value: 10000,
        merkle_root: "8d0ad2782d8f6e3f63c6f9611841c239630b55061d558abcc6bac53349edac70".to_string(),
        redeem_script_hex: "5121027db7837e51888e94c094703030d162c682c8dba312210f44ff440fbd5e5c247351ae".to_string(),
    };

    let response = client.post("/sign")
        .header(ContentType::JSON)
        .body(serde_json::to_string(&tx_details).unwrap())
        .dispatch();

    assert_eq!(response.status(), Status::Ok);
}
