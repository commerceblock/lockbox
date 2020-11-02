extern crate arrayvec;
extern crate base64;
extern crate bitcoin;
extern crate bitcoin_hashes;
extern crate chrono;
extern crate hex;
extern crate itertools;
extern crate merkletree;
extern crate rand;
extern crate reqwest;
extern crate rocket;
extern crate rocket_contrib;
extern crate uuid;

extern crate curv;
extern crate electrumx_client;
extern crate kms;
extern crate monotree;
extern crate multi_party_ecdsa;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

#[cfg(test)]
extern crate mockito;

pub mod mocks;

pub mod error;
pub mod structs;
pub mod util;
pub mod ecies;

use bitcoin::secp256k1::{Message, PublicKey, Secp256k1, Signature};

type Result<T> = std::result::Result<T, error::SharedLibError>;

pub type Hash = monotree::Hash;

pub trait Verifiable {
    fn verify_btc(&self, key: &bitcoin::util::key::PublicKey, message: &Message) -> Result<()>;
    fn verify(&self, key: &PublicKey, message: &Message) -> Result<()>;
}

impl Verifiable for Signature {
    fn verify_btc(&self, key: &bitcoin::util::key::PublicKey, message: &Message) -> Result<()> {
        let key = &PublicKey::from_slice(key.to_bytes().as_slice())?;
        self.verify(key, message)
    }

    fn verify(&self, key: &PublicKey, message: &Message) -> Result<()> {
        let secp = Secp256k1::new();
        Ok(secp.verify(message, &self, key)?)
    }
}
