use rusqlite::{params, Connection, Result};
use crate::sealing::Sealed;

pub fn save_seal_data_to_db(seal_data: Sealed, label: [u8; 16]) {
    let conn = Connection::open_in_memory().unwrap();

    conn.execute(
        "CREATE TABLE sealed_data (
            id   INTEGER PRIMARY KEY,
            label TEXT NOT NULL,
            nonce TEXT NOT NULL,
            ciphertext TEXT NOT NULL
        )",
        (), // empty list of parameters.
    ).unwrap();

    conn.execute(
        "INSERT INTO person (label, nonce, ciphertext) VALUES (?1, ?2, ?3)",
        (&label, &seal_data.nonce, &seal_data.ciphertext),
    ).unwrap();
}
