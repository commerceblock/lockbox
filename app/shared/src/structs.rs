//! Structs
//!
//! Struct definitions used in State entity protocols

use crate::state_chain::{ StateChainSig};
use bitcoin::{Transaction, TxIn, TxOut};
use curv::{cryptographic_primitives::proofs::sigma_dlog::DLogProof, BigInt, FE, GE, PK, SK};
use kms::ecdsa::two_party::party2;
use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::party_two;

use bitcoin::{secp256k1::PublicKey, Address};
use std::fmt;
use uuid::Uuid;

use crate::ecies;
use crate::ecies::{Encryptable, SelfEncryptable};




extern crate sgx_types;
extern crate sgx_urts;
use self::sgx_types::*;

big_array! {
    BigArray;
    +42,
}

/// State Entity protocols
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum Protocol {
    Deposit,
    Transfer,
    Withdraw,
}

// API structs

//Encryptable version of FE
//Secret key is stored as raw bytes
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Default)]
pub struct FESer {
    pub secret_bytes: Vec<u8>,
}

impl FESer {
    pub fn get_fe(&self) -> ecies::Result<FE> {
        let secret = SK::from_slice(&self.secret_bytes)?;
        let mut fe = FE::zero();
        fe.set_element(secret);
        let fe = fe;
        Ok(fe)
    }

    pub fn from_fe(fe_in: &FE) -> Self {
        let sbs = fe_in.get_element().to_string();
        let secret_bytes = hex::decode(&sbs).expect("hex decode error");
        FESer { secret_bytes }
    }

    pub fn new_random() -> Self {
        let fe = FE::new_random();
        Self::from_fe(&fe)
    }
}

/// /info/info return struct
#[derive(Serialize, Deserialize, Debug)]
pub struct StateEntityFeeInfoAPI {
    pub address: String, // Receive address for fee payments
    pub deposit: u64,    // satoshis
    pub withdraw: u64,   // satoshis
}
impl fmt::Display for StateEntityFeeInfoAPI {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Fee address: {},\nDeposit fee: {}\nWithdrawal fee: {}",
            self.address, self.deposit, self.withdraw
        )
    }
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
pub struct KeyGenMsg3 {
    pub shared_key_id: Uuid,
    pub party_two_pdl_first_message: party_two::PDLFirstMessage,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyGenMsg4 {
    pub shared_key_id: Uuid,
    pub party_two_pdl_second_message: party_two::PDLSecondMessage,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignMsg1 {
    pub shared_key_id: Uuid,
    pub eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignMsg2 {
    pub shared_key_id: Uuid,
    pub sign_second_msg_request: SignSecondMsgRequest,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignSecondMsgRequest {
    pub protocol: Protocol,
    pub message: BigInt,
    pub party_two_sign_message: party2::SignMessage,
}

// Deposit algorithm structs

/// Client -> SE
#[derive(Serialize, Deserialize, Debug)]
pub struct DepositMsg1 {
    pub auth: String,
    pub proof_key: String,
}

/// Client -> SE
#[derive(Serialize, Deserialize, Debug)]
pub struct DepositMsg2 {
    pub shared_key_id: Uuid,
}

// Transfer algorithm structs

/// Address generated for State Entity transfer protocol
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Hash)]
pub struct SCEAddress {
    pub tx_backup_addr: Option<Address>,
    pub proof_key: PublicKey,
}
impl Eq for SCEAddress {}

impl SelfEncryptable for SK {
    fn encrypt_with_pubkey(&mut self, pubkey: &ecies::PublicKey) -> ecies::Result<()> {
        let ss = self.to_string();
        let esb = ecies::ecies::encrypt(&pubkey.to_bytes(), ss.as_bytes())?;
        let esk = SK::from_slice(&esb[..])?;
        *self = esk;
        Ok(())
    }

    fn decrypt(&mut self, privkey: &ecies::PrivateKey) -> ecies::Result<()> {
        let ess = self.to_string();
        let sb = ecies::ecies::decrypt(&privkey.to_bytes(), ess.as_bytes())?;
        let sk = SK::from_slice(&sb[..])?;
        *self = sk;
        Ok(())
    }
}

use curv::elliptic::curves::traits::ECScalar;
impl Encryptable for FESer {}
impl SelfEncryptable for FESer {
    fn decrypt(&mut self, privkey: &crate::ecies::PrivateKey) -> ecies::Result<()> {
        let sb_plain = ecies::ecies::decrypt(&privkey.to_bytes(), &self.secret_bytes[..])?;
        self.secret_bytes = sb_plain;
        Ok(())
    }

    fn encrypt_with_pubkey(&mut self, pubkey: &crate::ecies::PublicKey) -> ecies::Result<()> {
        let sb_enc = ecies::ecies::encrypt(&pubkey.to_bytes(), &self.secret_bytes[..])?;
        self.secret_bytes = sb_enc;
        Ok(())
    }
}

/// Sender -> Lockbox
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferMsg1 {
    pub shared_key_id: Uuid,
    pub state_chain_sig: StateChainSig,
}
/// Lockbox -> Sender
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TransferMsg2 {
    pub x1: FESer,
    pub proof_key: ecies::PublicKey,
}
/// Sender -> Receiver
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct TransferMsg3 {
    pub shared_key_id: Uuid,
    pub t1: FESer, // t1 = o1x1
    pub state_chain_sig: StateChainSig,
    pub state_chain_id: Uuid,
    pub tx_backup_psm: PrepareSignTxMsg,
    pub rec_addr: SCEAddress, // receivers state entity address (btc address and proof key)
}

/// Receiver -> Lockbox
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferMsg4 {
    pub shared_key_id: Uuid,
    pub state_chain_id: Uuid,
    pub t2: FE, // t2 = t1*o2_inv = o1*x1*o2_inv
    pub state_chain_sig: StateChainSig,
    pub o2_pub: GE,
    pub tx_backup: Transaction,
    pub batch_data: Option<BatchData>,
}

/// Lockbox -> Receiver
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferMsg5 {
    pub new_shared_key_id: Uuid,
    pub s2_pub: GE,
}

/// Data present if transfer is part of an atomic batch transfer
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct BatchData {
    pub id: Uuid,
    pub commitment: String, // Commitment to transfer input UTXO in case of protocol failure
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KUSendMsg {        // Sent from server to lockbox
    pub user_id: Uuid,
    pub statechain_id: Uuid,
    pub x1: FE,
    pub t2: FESer,
    pub o2_pub: GE,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KUReceiveMsg {      // Sent from lockbox back to server
    pub s2_pub: GE,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KUFinalize {        // Sent from server to lockbox
    pub statechain_id: Uuid,
    pub shared_key_id: Uuid,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KUAttest {      // Sent from lockbox back to server
    pub statechain_id: Uuid,
    pub attestation: String,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct InitECKeyMsg {
    pub data: Vec::<u8>
}

/// by Server before co-signing is performed for validation of tx.
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct PrepareSignTxMsg {
    pub shared_key_id: Uuid,
    pub protocol: Protocol,
    pub tx: Transaction,
    pub input_addrs: Vec<PK>, // pub keys being spent from
    pub input_amounts: Vec<u64>,
    pub proof_key: Option<String>,
}

impl Default for PrepareSignTxMsg {
    fn default() -> Self {
        let default_tx = Transaction {
            version: i32::default(),
            lock_time: u32::default(),
            input: Vec::<TxIn>::default(),
            output: Vec::<TxOut>::default(),
        };

        Self {
            shared_key_id: Uuid::default(),
            protocol: Protocol::Transfer,
            tx: default_tx,
            input_addrs: Vec::<PK>::default(),
            input_amounts: Vec::<u64>::default(),
            proof_key: None,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Default)]
pub struct EnclaveIDMsg {
    pub inner: sgx_enclave_id_t
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::util::keygen::generate_keypair;

    #[test]
    fn test_encrypt_fe_ser() {
        let mut fe_ser = FESer::new_random();
        let fe_ser_clone = fe_ser.clone();
        assert_eq!(fe_ser, fe_ser_clone);
        let (priv_k, pub_k) = generate_keypair();
        fe_ser.encrypt_with_pubkey(&pub_k).unwrap();
        assert_ne!(fe_ser, fe_ser_clone);
        fe_ser.decrypt(&priv_k).unwrap();
        assert_eq!(fe_ser, fe_ser_clone);
    }

    #[test]
    fn test_to_from_fe_ser() {
        let fe_ser = FESer::new_random();
        let _ = fe_ser.get_fe().expect("failed to get fe");
        let fe = FE::new_random();
        let fe_ser = FESer::from_fe(&fe);
        let _ = fe_ser.get_fe().expect("failed to get fe");
    }

}

