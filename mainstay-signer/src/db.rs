use sled::{Db, IVec};
use serde::{Serialize, Deserialize};
use hex::decode;

#[derive(Debug, Serialize, Deserialize)]
pub struct SealedData {
    pub label: String,
    pub nonce: String,
    pub ciphertext: String,
}

pub fn save_seal_data_to_db(sealed_data: SealedData) {
    let db = sled::open("sled/db").expect("Failed to open Sled database");

    db.insert("label", IVec::from(decode(sealed_data.label).unwrap())).expect("Failed to insert data into Sled database");
    db.insert("nonce", IVec::from(decode(sealed_data.nonce).unwrap())).expect("Failed to insert data into Sled database");
    db.insert("ciphertext", IVec::from(decode(sealed_data.ciphertext).unwrap())).expect("Failed to insert data into Sled database");
}
