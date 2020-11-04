use super::Result;
use crate::error::SharedLibError;
use crate::Verifiable;

use bitcoin::{
    hashes::{sha256d, Hash},
    secp256k1::{Message, PublicKey, Secp256k1, SecretKey, Signature},
};
use monotree::{
    hasher::{Blake3, Hasher},
    tree::verify_proof,
    {Monotree, Proof},
};

use chrono::{Duration, NaiveDateTime, Utc};
use std::panic;
use std::sync::{Arc, Mutex};
use std::{convert::TryInto, panic::AssertUnwindSafe, str::FromStr};
use uuid::Uuid;

/// Each State in the Chain of States
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct State {
    pub data: String,                      // proof key or address
    pub next_state: Option<StateChainSig>, // signature representing passing of ownership
}
/// Data necessary to create ownership transfer signatures
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default, Hash, Eq)]
pub struct StateChainSig {
    pub purpose: String, // "TRANSFER", "TRANSFER-BATCH" or "WITHDRAW"
    pub data: String,    // proof key, state chain id or address
    sig: String,
}