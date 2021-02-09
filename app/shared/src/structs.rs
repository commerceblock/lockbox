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

use std::mem::size_of;
use std::convert::From;

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
    secret_bytes: Vec<u8>,
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



// PrepareSignTx structs

/// Struct contains data necessary to caluculate backup tx's input sighash('s). This is required
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
    pub t2: FE,
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

//Attestation
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct EnclaveIDMsg {
    pub inner: sgx_enclave_id_t
}

/*
impl From<sgx_enclave_id_t> for EnclaveIDMsg {
    fn from(v: sgx_enclave_id_t) -> Self {
	let inner = unsafe {std::slice::from_raw_parts(v as *const sgx_enclave_id_t as *const u8, size_of::<sgx_enclave_id_t>()).to_vec()};
	Self {inner}
    }

}


impl Into<sgx_enclave_id_t> for EnclaveIDMsg {
    fn into(self) -> sgx_enclave_id_t {
	let result: &sgx_enclave_id_t = unsafe { &(self.inner) as &sgx_enclave_id_t };
	*result
    }

}
 */

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_dh_msg1_t")]
struct DHMsg1Def {
    #[serde(with = "EC256PublicDef")]
    pub g_a: sgx_ec256_public_t,
    #[serde(with = "TargetInfoDef")]
    pub target: sgx_target_info_t,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_dh_msg2_t")]
struct DHMsg2Def {
    #[serde(with = "EC256PublicDef")]
    pub g_b: sgx_ec256_public_t,
    #[serde(with = "ReportDef")]
    pub report: sgx_report_t,
    #[serde(serialize_with = "<[_]>::serialize")]
    pub cmac: [uint8_t; SGX_DH_MAC_SIZE],
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_dh_msg3_body_t")]
struct DHMsg3BodyDef {
    #[serde(with = "ReportDef")]
    pub report: sgx_report_t,
    pub additional_prop_length: uint32_t,
    #[serde(serialize_with = "<[_]>::serialize")]
    pub additional_prop: [uint8_t; 0],
}


#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_dh_msg3_t")]
pub struct DHMsg3Def {
    #[serde(serialize_with = "<[_]>::serialize")]
    pub cmac: [uint8_t; SGX_DH_MAC_SIZE],
    #[serde(with = "DHMsg3BodyDef")]
    pub msg3_body: sgx_dh_msg3_body_t,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_report_t")]
pub struct ReportDef {
    #[serde(with = "ReportBodyDef")]
    pub body: sgx_report_body_t,
    #[serde(with = "KeyIDDef")]
    pub key_id: sgx_key_id_t,
    #[serde(serialize_with = "<[_]>::serialize")]
    pub mac: sgx_mac_t,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_key_id_t")]
pub struct KeyIDDef {
    #[serde(serialize_with = "<[_]>::serialize")]
    pub id: [uint8_t; SGX_KEYID_SIZE],
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_report_body_t")]
pub struct ReportBodyDef {
    #[serde(with = "CpuSvnDef")]
    pub cpu_svn: sgx_cpu_svn_t,
    pub misc_select: sgx_misc_select_t,
    #[serde(serialize_with = "<[_]>::serialize")]
    pub reserved1: [uint8_t; SGX_REPORT_BODY_RESERVED1_BYTES],
    pub isv_ext_prod_id: sgx_isvext_prod_id_t,
    #[serde(with = "AttributesDef")]
    pub attributes: sgx_attributes_t,
    #[serde(with = "MeasurementDef")]
    pub mr_enclave: sgx_measurement_t,
    #[serde(serialize_with = "<[_]>::serialize")]
    pub reserved2: [uint8_t; SGX_REPORT_BODY_RESERVED2_BYTES],
    #[serde(with = "MeasurementDef")]
    pub mr_signer: sgx_measurement_t,
    #[serde(serialize_with = "<[_]>::serialize")]
    pub reserved3: [uint8_t; SGX_REPORT_BODY_RESERVED3_BYTES],
    #[serde(with = "BigArray")]
    pub config_id: sgx_config_id_t,
    pub isv_prod_id: sgx_prod_id_t,
    pub isv_svn: sgx_isv_svn_t,
    pub config_svn: sgx_config_svn_t,
    #[serde(with = "BigArray")]
    pub reserved4: [uint8_t; SGX_REPORT_BODY_RESERVED4_BYTES],
    #[serde(serialize_with = "<[_]>::serialize")]
    pub isv_family_id: sgx_isvfamily_id_t,
    #[serde(with = "ReportDataDef")]
    pub report_data: sgx_report_data_t,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_report_data_t")]
pub struct ReportDataDef {
    #[serde(with = "BigArray")]
    pub d: [uint8_t; SGX_REPORT_DATA_SIZE],
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_cpu_svn_t")]
pub struct CpuSvnDef {
    #[serde(serialize_with = "<[_]>::serialize")]
    pub svn: [uint8_t; SGX_CPUSVN_SIZE],
}



#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_ec256_public_t")]
struct EC256PublicDef {
    #[serde(serialize_with = "<[_]>::serialize")]
    pub gx: [uint8_t; SGX_ECP256_KEY_SIZE],
    #[serde(serialize_with = "<[_]>::serialize")]
    pub gy: [uint8_t; SGX_ECP256_KEY_SIZE],
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_target_info_t")]
struct TargetInfoDef {
    #[serde(with = "MeasurementDef")]
    pub mr_enclave: sgx_measurement_t,
    #[serde(with = "AttributesDef")]
    pub attributes: sgx_attributes_t,
    pub reserved1: [uint8_t; SGX_TARGET_INFO_RESERVED1_BYTES],
    pub config_svn: sgx_config_svn_t,
    pub misc_select: sgx_misc_select_t,
    pub reserved2: [uint8_t; SGX_TARGET_INFO_RESERVED2_BYTES],
    #[serde(with = "BigArray")]
    pub config_id: sgx_config_id_t,
    #[serde(with = "BigArray")]
    pub reserved3: [uint8_t; SGX_TARGET_INFO_RESERVED3_BYTES],
}

//impl_struct! {
    #[derive(Serialize, Deserialize)]
    #[serde(remote = "sgx_measurement_t")]
    pub struct MeasurementDef {
	#[serde(serialize_with = "<[_]>::serialize")]
        pub m: [uint8_t; SGX_HASH_SIZE],
    }
//}



impl_struct! {
    #[derive(Serialize, Deserialize)]
    #[serde(remote = "sgx_attributes_t")]
    pub struct AttributesDef {
        pub flags: uint64_t,
        pub xfrm: uint64_t,
    }
}

#[derive(Serialize, Deserialize, Default)]
pub struct DHMsg1 {
    #[serde(with = "DHMsg1Def")]
    pub inner: sgx_dh_msg1_t,
}

#[derive(Serialize, Deserialize, Default)]
pub struct DHMsg2 {
    #[serde(with = "DHMsg2Def")]
    pub inner: sgx_dh_msg2_t,
}

#[derive(Serialize, Deserialize, Default)]
pub struct DHMsg3 {
    #[serde(with = "DHMsg3Def")]
    pub inner: sgx_dh_msg3_t,
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

