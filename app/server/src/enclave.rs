
use std::ops::{Deref, DerefMut};
extern crate sgx_types;
extern crate sgx_urts;
use self::sgx_types::*;
use self::sgx_urts::SgxEnclave;
use crate::error::LockboxError;
use crate::shared_lib::structs::{KeyGenMsg2, SignMsg1, SignMsg2, Protocol,
				 SignSecondMsgRequest, KUSendMsg, KUReceiveMsg, KUFinalize, KUAttest};

extern crate bitcoin;
use bitcoin::secp256k1::{Signature, Message, PublicKey, SecretKey, Secp256k1};
pub use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
pub use multi_party_ecdsa_client::protocols::two_party_ecdsa::lindell_2017::party_one::KeyGenSecondMsg as KeyGenSecondMsg_sgx;
pub use multi_party_ecdsa_client::protocols::two_party_ecdsa::lindell_2017::party_one::KeyGenFirstMsg as KeyGenFirstMsg_sgx;
pub use multi_party_ecdsa_client::protocols::two_party_ecdsa::lindell_2017::party_one::CommWitness as CommWitness_sgx;
pub use multi_party_ecdsa_client::protocols::two_party_ecdsa::lindell_2017::party_one::EphKeyGenFirstMsg as EphKeyGenFirstMsg_sgx;
pub use multi_party_ecdsa_client::protocols::two_party_ecdsa::lindell_2017::party_two as party_two_sgx; 
pub use multi_party_ecdsa_client::utilities::zk_pdl_with_slack::PDLwSlackProof as PDLwSlackProof_sgx;
pub use multi_party_ecdsa_client::utilities::zk_pdl_with_slack::PDLwSlackStatement as PDLwSlackStatement_sgx;
pub use multi_party_ecdsa::utilities::zk_pdl_with_slack::{PDLwSlackStatement, PDLwSlackProof};
pub use kms_sgx::ecdsa::two_party::party1::KeyGenParty1Message2 as KeyGenParty1Message2_sgx;
pub use kms_sgx::ecdsa::two_party::party2 as party2_sgx;
use curv::{BigInt, FE, GE, elliptic::curves::traits::{ECPoint, ECScalar},
	   arithmetic::traits::Converter,
	   cryptographic_primitives::proofs::sigma_dlog::{DLogProof,ProveDLog}};
pub use curv_client::cryptographic_primitives::proofs::sigma_dlog::DLogProof as DLogProof_sgx;
pub use curv_client::cryptographic_primitives::proofs::sigma_ec_ddh::ECDDHProof as ECDDHProof_sgx;
pub use curv::cryptographic_primitives::proofs::sigma_ec_ddh::ECDDHProof;
pub use curv_client::GE as GE_sgx;
pub use curv_client::FE as FE_sgx;
pub use curv_client::BigInt as BigInt_sgx;
use uuid::Uuid;
use kms::ecdsa::two_party::*;
use num_bigint_dig::{RandomBits};
use rand::Rng;
use paillier::{Paillier, Randomness, RawPlaintext, KeyGeneration,
	       EncryptWithChosenRandomness, DecryptionKey, EncryptionKey};
use paillier_client::EncryptionKey as EncryptionKey_sgx;
use zk_paillier::zkproofs::{NICorrectKeyProof, RangeProofNi, Response, EncryptedPairs, Proof, CompositeDLogProof};
use zk_paillier_client::zkproofs::NICorrectKeyProof as NICorrectKeyProof_sgx;
use zk_paillier_client::zkproofs::RangeProofNi as RangeProofNi_sgx;
use zk_paillier_client::zkproofs::EncryptedPairs as EncryptedPairs_sgx;
use zk_paillier_client::zkproofs::Proof as Proof_sgx;
use zk_paillier_client::zkproofs::range_proof::Response as Response_sgx;
pub use zk_paillier_client::zkproofs::CompositeDLogProof as CompositeDLogProof_sgx;

use num_traits::{Zero, One, Num};

static ENCLAVE_FILE: &'static str = "/opt/lockbox/bin/enclave.signed.so";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Enclave {
    inner: SgxEnclave
}

impl Deref for Enclave {
     type Target = SgxEnclave;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for Enclave {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

mod party_one_enc {
    use super::*;

    pub struct EphKeyGenFirstMsg_w {
	pub inner: party_one::EphKeyGenFirstMsg
    }
    
    impl Deref for EphKeyGenFirstMsg_w {
	type Target = party_one::EphKeyGenFirstMsg;
	fn deref(&self) -> &Self::Target {
	    &self.inner
	}
    }
    
    impl DerefMut for EphKeyGenFirstMsg_w {
	fn deref_mut(&mut self) -> &mut Self::Target {
	    &mut self.inner
	}
    }

    impl From<&EphKeyGenFirstMsg_sgx> for EphKeyGenFirstMsg_w {
	fn from(item: &EphKeyGenFirstMsg_sgx) -> Self {
	    let d_log_proof = ECDDHProof_w::from(&item.d_log_proof).inner;
	    let public_share = GE_w::from(&item.public_share).inner;
	    let c = GE_w::from(&item.c).inner;

	    Self { inner:  party_one::EphKeyGenFirstMsg{ d_log_proof, public_share, c } }
	}
    }
}

mod party_two_enc {
    use super::*;

    pub struct EphKeyGenFirstMsg_sgx_w {
	pub inner: party_two_sgx::EphKeyGenFirstMsg
    }

    impl Deref for EphKeyGenFirstMsg_sgx_w {
	type Target = party_two_sgx::EphKeyGenFirstMsg;
	fn deref(&self) -> &Self::Target {
	    &self.inner
	}
    }

    impl DerefMut for EphKeyGenFirstMsg_sgx_w {
	fn deref_mut(&mut self) -> &mut Self::Target {
	    &mut self.inner
	}
    }
    
    impl From<&party_two::EphKeyGenFirstMsg> for EphKeyGenFirstMsg_sgx_w {
	fn from(item: &party_two::EphKeyGenFirstMsg) -> Self {
	    let pk_commitment = BigInt_sgx_w::from(&item.pk_commitment).inner;
	    let zk_pok_commitment = BigInt_sgx_w::from(&item.pk_commitment).inner;
	    
	    Self { inner:  party_two_sgx::EphKeyGenFirstMsg{ pk_commitment, zk_pok_commitment } }
	}
    }

    struct EphCommWitness_sgx_w {
	inner: party_two_sgx::EphCommWitness
    }
    
    impl Deref for EphCommWitness_sgx_w {
	type Target = party_two_sgx::EphCommWitness;
	fn deref(&self) -> &Self::Target {
     	    &self.inner
	}
    }
    
    impl DerefMut for EphCommWitness_sgx_w {
	fn deref_mut(&mut self) -> &mut Self::Target {
     	    &mut self.inner
	}
    }
    
    impl From<&party_two::EphCommWitness> for EphCommWitness_sgx_w {
	fn from(item: &party_two::EphCommWitness) -> Self {
	    let pk_commitment_blind_factor = BigInt_sgx_w::from(&item.pk_commitment_blind_factor).inner;
	    let zk_pok_blind_factor = BigInt_sgx_w::from(&item.zk_pok_blind_factor).inner;
	    let public_share = GE_sgx_w::from(&item.public_share).inner;
	    let d_log_proof = ECDDHProof_sgx_w::from(&item.d_log_proof).inner;
	    let c = GE_sgx_w::from(&item.c).inner;
	    
	    Self { inner: party_two_sgx::EphCommWitness { pk_commitment_blind_factor, zk_pok_blind_factor, public_share, d_log_proof, c } }
	    
	}
    }



    pub struct ECDDHProof_sgx_w {
	pub inner: ECDDHProof_sgx
    }

    impl Deref for ECDDHProof_sgx_w {
	type Target = ECDDHProof_sgx;
	fn deref(&self) -> &Self::Target {
	    &self.inner
	}
    }

    impl DerefMut for ECDDHProof_sgx_w {
	fn deref_mut(&mut self) -> &mut Self::Target {
	    &mut self.inner
	}
    }
    
    impl From<&ECDDHProof> for ECDDHProof_sgx_w {
	fn from(item: &ECDDHProof) -> Self {
	    let a1 = GE_sgx_w::from(&item.a1).inner;
	    let a2 = GE_sgx_w::from(&item.a1).inner;
	    let z = FE_sgx_w::from(&item.z).inner;
	    
	    Self { inner:  ECDDHProof_sgx{ a1, a2, z } }
	}
    }

    


    pub struct EphKeyGenSecondMsg_sgx_w {
	pub inner: party_two_sgx::EphKeyGenSecondMsg
    }

    impl Deref for EphKeyGenSecondMsg_sgx_w {
	type Target = party_two_sgx::EphKeyGenSecondMsg;
	fn deref(&self) -> &Self::Target {
	    &self.inner
	}
    }

    impl DerefMut for EphKeyGenSecondMsg_sgx_w {
	fn deref_mut(&mut self) -> &mut Self::Target {
	    &mut self.inner
	}
    }
    
    impl From<&party_two::EphKeyGenSecondMsg> for EphKeyGenSecondMsg_sgx_w {
	fn from(item: &party_two::EphKeyGenSecondMsg) -> Self {
	    let comm_witness = party_two_enc::EphCommWitness_sgx_w::from(&item.comm_witness).inner;
	    
	    Self { inner:  party_two_sgx::EphKeyGenSecondMsg{ comm_witness } }
	}
    }




    pub struct PartialSig_sgx_w {
	pub inner: party_two_sgx::PartialSig
    }

    impl Deref for PartialSig_sgx_w {
	type Target = party_two_sgx::PartialSig;
	fn deref(&self) -> &Self::Target {
	    &self.inner
	}
    }

    impl DerefMut for PartialSig_sgx_w {
	fn deref_mut(&mut self) -> &mut Self::Target {
	    &mut self.inner
	}
    }
    
    impl From<&party_two::PartialSig> for PartialSig_sgx_w {
	fn from(item: &party_two::PartialSig) -> Self {
	    let c3 = BigInt_sgx_w::from(&item.c3).inner;
	    
	    Self { inner:  party_two_sgx::PartialSig{ c3 } }
	}
    }
    
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KUSendMsg_sgx {        // Sent from server to lockbox
    pub user_id: Uuid,
    pub statechain_id: Uuid,
    pub x1: FE_sgx,
    pub t2: FE_sgx,
    pub o2_pub: GE_sgx,
}

pub struct KUSendMsg_sgx_w {
    inner: KUSendMsg_sgx
}

impl From<&KUSendMsg> for KUSendMsg_sgx_w {
    fn from(item: &KUSendMsg) -> Self {

	let user_id = item.user_id;
	let statechain_id = item.statechain_id;
	let x1 = FE_sgx_w::from(&item.x1).inner;
	let t2 = FE_sgx_w::from(&item.t2).inner;
	let o2_pub = GE_sgx_w::from(&item.o2_pub).inner;
	
	Self { inner: KUSendMsg_sgx { user_id, statechain_id, x1, t2, o2_pub } }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KUReceiveMsg_sgx {      // Sent from lockbox back to server
    pub s2_pub: GE_sgx,
}

pub struct KUReceiveMsg_w {
    inner: KUReceiveMsg
}

impl From<&KUReceiveMsg_sgx> for KUReceiveMsg_w {
    fn from(item: &KUReceiveMsg_sgx) -> Self {
	let s2_pub = GE_w::from(&item.s2_pub).inner;
	
	Self { inner: KUReceiveMsg { s2_pub } }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyGenMsg2_sgx {      // Sent from lockbox back to server
    pub shared_key_id: Uuid,
    pub dlog_proof: DLogProof_sgx,
}

pub struct KeyGenMsg2_sgx_w {
    inner: KeyGenMsg2_sgx
}

impl From<&KeyGenMsg2> for KeyGenMsg2_sgx_w {
    fn from(item: &KeyGenMsg2) -> Self {
	let shared_key_id = item.shared_key_id;
	let dlog_proof = DLogProof_sgx_w::from(&item.dlog_proof).inner;
	
	Self { inner: KeyGenMsg2_sgx { shared_key_id, dlog_proof } }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignMsg1_sgx {
    pub shared_key_id: Uuid,
    pub eph_key_gen_first_message_party_two: party_two_sgx::EphKeyGenFirstMsg,
}

pub struct SignMsg1_sgx_w {
    inner: SignMsg1_sgx
}

impl Deref for SignMsg1_sgx_w {
     type Target = SignMsg1_sgx;
     fn deref(&self) -> &Self::Target {
	&self.inner
     }
}

impl DerefMut for SignMsg1_sgx_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
	&mut self.inner
     }
}

impl From<&SignMsg1> for SignMsg1_sgx_w {
    fn from(item: &SignMsg1) -> Self {

	let shared_key_id = item.shared_key_id;
	let eph_key_gen_first_message_party_two =
	    party_two_enc::EphKeyGenFirstMsg_sgx_w::from(&item.eph_key_gen_first_message_party_two).inner;
	
	Self { inner: SignMsg1_sgx { shared_key_id, eph_key_gen_first_message_party_two } }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignMsg2_sgx {
    pub shared_key_id: Uuid,
    pub sign_second_msg_request: SignSecondMsgRequest_sgx,
}

pub struct SignMsg2_sgx_w {
    inner: SignMsg2_sgx
}

impl Deref for SignMsg2_sgx_w {
     type Target = SignMsg2_sgx;
     fn deref(&self) -> &Self::Target {
	&self.inner
     }
}

impl DerefMut for SignMsg2_sgx_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
	&mut self.inner
     }
}

impl From<&SignMsg2> for SignMsg2_sgx_w {
    fn from(item: &SignMsg2) -> Self {

	let shared_key_id = item.shared_key_id;
	let sign_second_msg_request =
	    SignSecondMsgRequest_sgx_w::from(&item.sign_second_msg_request).inner;
	
	Self { inner: SignMsg2_sgx { shared_key_id, sign_second_msg_request } }
    }
}


#[derive(Serialize, Deserialize, Debug)]
pub struct SignSecondMsgRequest_sgx {
    pub protocol: Protocol,
    pub message: BigInt_sgx,
    pub party_two_sign_message: party2_sgx::SignMessage,
}

pub struct SignSecondMsgRequest_sgx_w {
    inner: SignSecondMsgRequest_sgx
}

impl Deref for SignSecondMsgRequest_sgx_w {
     type Target = SignSecondMsgRequest_sgx;
     fn deref(&self) -> &Self::Target {
	&self.inner
     }
}

impl DerefMut for SignSecondMsgRequest_sgx_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
	&mut self.inner
     }
}

impl From<&SignSecondMsgRequest> for SignSecondMsgRequest_sgx_w {
    fn from(item: &SignSecondMsgRequest) -> Self {

	let message = BigInt_sgx_w::from(&item.message).inner;
	let party_two_sign_message = party2_enc::SignMessage_sgx_w::from(&item.party_two_sign_message).inner;
	
	Self { inner: SignSecondMsgRequest_sgx { protocol: item.protocol, message, party_two_sign_message } }
    }
}

mod party2_enc {
    use super::*;

    pub struct SignMessage_sgx_w {
	pub inner: party2_sgx::SignMessage
    }
    
    impl Deref for SignMessage_sgx_w {
	type Target = party2_sgx::SignMessage;
	fn deref(&self) -> &Self::Target {
	    &self.inner
	}
    }
    
    impl DerefMut for SignMessage_sgx_w {
	fn deref_mut(&mut self) -> &mut Self::Target {
	    &mut self.inner
	}
    }
    
    impl From<&party2::SignMessage> for SignMessage_sgx_w {
	fn from(item: &party2::SignMessage) -> Self {
	    let partial_sig = party_two_enc::PartialSig_sgx_w::from(&item.partial_sig).inner;
	    let second_message = party_two_enc::EphKeyGenSecondMsg_sgx_w::from(&item.second_message).inner;
	    
	    Self { inner: party2_sgx::SignMessage { partial_sig, second_message } }
	}
    }

    
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KeyGenFirstMsg{
    pk_commitment: BigInt,
    zk_pok_commitment: BigInt,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KeyGenFirstMsg_w{
    inner: KeyGenFirstMsg
}

impl Deref for KeyGenFirstMsg_w {
     type Target = KeyGenFirstMsg;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for KeyGenFirstMsg_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}


impl From<&KeyGenFirstMsg_sgx> for KeyGenFirstMsg_w {
    fn from(item: &KeyGenFirstMsg_sgx) -> Self {

	let pk_commitment = BigInt_w::from(&item.pk_commitment).inner;
	let zk_pok_commitment = BigInt_w::from(&item.zk_pok_commitment).inner;
	
	let inner = KeyGenFirstMsg {
	    pk_commitment,
	    zk_pok_commitment,
	};

	Self { inner }
    }
}

pub struct KeyGenParty1Message2_w {
    inner: party1::KeyGenParty1Message2
}

impl Deref for KeyGenParty1Message2_w {
     type Target = party1::KeyGenParty1Message2;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for KeyGenParty1Message2_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}


impl From<&KeyGenParty1Message2_sgx> for KeyGenParty1Message2_w {
    fn from(item: &KeyGenParty1Message2_sgx) -> Self {

	let correct_key_proof = NICorrectKeyProof_w::from(&item.correct_key_proof).deref().to_owned(); 

	let composite_dlog_proof = CompositeDLogProof_w::from(&item.composite_dlog_proof).deref().to_owned();

	let pdl_proof = PDLwSlackProof_w::from(&item.pdl_proof).deref().to_owned();

	let pdl_statement = PDLwSlackStatement_w::from(&item.pdl_statement).deref().to_owned();
	
	let inner = party1::KeyGenParty1Message2 {
	    ecdh_second_message: KeyGenSecondMsg_w::from(&item.ecdh_second_message).inner,
	    ek: EncryptionKey_w::from(&item.ek).inner,
	    c_key: BigInt_w::from(&item.c_key).inner,
	    correct_key_proof,
	    composite_dlog_proof,
	    pdl_proof,
	    pdl_statement,
	};
	Self { inner }
    }
}


pub struct NICorrectKeyProof_w {
    inner: NICorrectKeyProof
}

impl Deref for NICorrectKeyProof_w {
     type Target = NICorrectKeyProof;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for NICorrectKeyProof_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&NICorrectKeyProof_sgx> for NICorrectKeyProof_w {
    fn from(item: &NICorrectKeyProof_sgx) -> Self {
	let mut biv = Vec::<BigInt>::new();
	for nbi in &item.sigma_vec {
	    let biw = BigInt_w::from(nbi);
	    biv.push(biw.inner);
	}
	Self { inner: NICorrectKeyProof { sigma_vec: biv } }
    }
}

pub struct CompositeDLogProof_w {
    inner: CompositeDLogProof
}

impl Deref for CompositeDLogProof_w {
     type Target = CompositeDLogProof;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for CompositeDLogProof_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&CompositeDLogProof_sgx> for CompositeDLogProof_w {
    fn from(item: &CompositeDLogProof_sgx) -> Self {
	let x = BigInt_w::from(&item.x).inner;
	let y = BigInt_w::from(&item.y).inner;

	Self { inner: CompositeDLogProof { x, y } }
    }
}

pub struct PDLwSlackProof_w {
    inner: PDLwSlackProof
}

impl Deref for PDLwSlackProof_w {
     type Target = PDLwSlackProof;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for PDLwSlackProof_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&PDLwSlackProof_sgx> for PDLwSlackProof_w {
    fn from(item: &PDLwSlackProof_sgx) -> Self {

	let z = BigInt_w::from(&item.z).inner;
	let u1 = GE_w::from(&item.u1).inner;
	let u2 = BigInt_w::from(&item.u2).inner;
	let u3 = BigInt_w::from(&item.u3).inner;
	let s1 = BigInt_w::from(&item.s1).inner;
	let s2 = BigInt_w::from(&item.s2).inner;
	let s3 = BigInt_w::from(&item.s3).inner;

	Self { inner: PDLwSlackProof { z, u1, u2, u3, s1, s2, s3 } }
    }
}

pub struct PDLwSlackStatement_w {
    inner: PDLwSlackStatement
}

impl Deref for PDLwSlackStatement_w {
     type Target = PDLwSlackStatement;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for PDLwSlackStatement_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&PDLwSlackStatement_sgx> for PDLwSlackStatement_w {
    fn from(item: &PDLwSlackStatement_sgx) -> Self {

	let ciphertext = BigInt_w::from(&item.ciphertext).inner;
	let ek = EncryptionKey_w::from(&item.ek).inner;
	let Q = GE_w::from(&item.Q).inner;
	let G = GE_w::from(&item.G).inner;
	let h1 = BigInt_w::from(&item.h1).inner;
	let h2 = BigInt_w::from(&item.h2).inner;
	let N_tilde = BigInt_w::from(&item.N_tilde).inner;

	Self { inner: PDLwSlackStatement { ciphertext, ek, Q, G, h1, h2, N_tilde } }
    }
}

pub struct RangeProofNi_w {
    inner: RangeProofNi
}

impl Deref for RangeProofNi_w {
     type Target = RangeProofNi;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for RangeProofNi_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&RangeProofNi_sgx> for RangeProofNi_w {
    fn from(item: &RangeProofNi_sgx) -> Self {
	let ek = EncryptionKey_w::from(&item.ek).inner;
	let range = BigInt_w::from(&item.range).inner;
	let ciphertext = BigInt_w::from(&item.ciphertext).inner;
	let encrypted_pairs = EncryptedPairs_w::from(&item.encrypted_pairs).inner;
	let proof = Proof_w::from(&item.proof).inner;
	
	Self { inner: RangeProofNi { ek, range, ciphertext, encrypted_pairs, proof, error_factor: item.error_factor } }
    }
}


pub struct EncryptionKey_w {
    inner: EncryptionKey
}

impl Deref for EncryptionKey_w {
     type Target = EncryptionKey;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for EncryptionKey_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}


impl From<&EncryptionKey_sgx> for EncryptionKey_w {
    fn from(item: &EncryptionKey_sgx) -> Self {
	let n = BigInt_w::from(&item.n).inner;
	let nn = BigInt_w::from(&item.nn).inner;
	Self { inner: EncryptionKey{ n, nn } }
    }
}

pub struct EncryptedPairs_w {
    inner: EncryptedPairs
}

impl Deref for EncryptedPairs_w {
     type Target = EncryptedPairs;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}


impl DerefMut for EncryptedPairs_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}


impl From<&EncryptedPairs_sgx> for EncryptedPairs_w {
    fn from(item: &EncryptedPairs_sgx) -> Self {

	let mut c1 = Vec::<BigInt>::new();
	let mut c2 = Vec::<BigInt>::new();
	
        for c1_r  in &item.c1 {
            let biw = BigInt_w::from(c1_r);
            c1.push(biw.inner);
        }

	for c2_r  in &item.c2 {
            let biw = BigInt_w::from(c2_r);
            c2.push(biw.inner);
        }

	Self { inner: EncryptedPairs { c1, c2 } }
	
    }
}

pub struct Proof_w {
    inner: Proof
}

impl Deref for Proof_w {
     type Target = Proof;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for Proof_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}


impl From<&Proof_sgx> for Proof_w {
    fn from(item: &Proof_sgx) -> Self {
	let mut resp_vec = Vec::<Response>::new();
	for resp in &item.0 {
	    match resp {
		Response_sgx::Open  { w1, r1, w2, r2 } => {
		    let w1 = BigInt_w::from(w1).inner;
		    let r1 = BigInt_w::from(r1).inner;
		    let w2 = BigInt_w::from(w2).inner;
		    let r2 = BigInt_w::from(r2).inner;
		    resp_vec.push(Response::Open{w1,r1,w2,r2});
		},
		Response_sgx::Mask {j, masked_x, masked_r }  => {
		    let masked_x = BigInt_w::from(masked_x).inner;
		    let masked_r = BigInt_w::from(masked_r).inner;
		    resp_vec.push(Response::Mask{j: j.to_owned(), masked_x, masked_r});
		}
	    };
	}
	Self{inner: Proof(resp_vec)}
    }
}

struct KeyGenSecondMsg_w {
    inner: party_one::KeyGenSecondMsg
}

impl Deref for KeyGenSecondMsg_w {
     type Target = party_one::KeyGenSecondMsg;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for KeyGenSecondMsg_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&KeyGenSecondMsg_sgx> for KeyGenSecondMsg_w {
    fn from(item: &KeyGenSecondMsg_sgx) -> Self {
	let comm_witness = CommWitness_w::from(&item.comm_witness).inner;
	Self { inner: party_one::KeyGenSecondMsg { comm_witness } }
    }
}

struct CommWitness_w {
    inner: party_one::CommWitness
}

impl Deref for CommWitness_w {
     type Target = party_one::CommWitness;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for CommWitness_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&CommWitness_sgx> for CommWitness_w {
    fn from(item: &CommWitness_sgx) -> Self {
	let pk_commitment_blind_factor = BigInt_w::from(&item.pk_commitment_blind_factor).inner;
	let zk_pok_blind_factor = BigInt_w::from(&item.zk_pok_blind_factor).inner;
	let public_share = GE_w::from(&item.public_share).inner;
	let d_log_proof = DLogProof_w::from(&item.d_log_proof).inner;

	Self { inner: party_one::CommWitness { pk_commitment_blind_factor, zk_pok_blind_factor, public_share, d_log_proof } }
	
    }
}

struct GE_w {
    inner: GE
}

impl Deref for GE_w {
     type Target = GE;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for GE_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&GE_sgx> for GE_w {
    fn from(item: &GE_sgx) -> Self {
	use curv_client::elliptic::curves::traits::ECPoint;
	use curv::arithmetic::traits::Converter;

	let ser = &item.get_element().serialize_uncompressed();
	let inner: GE = curv::elliptic::curves::traits::ECPoint::from_bytes(
	    &ser[1..ser.len()]
	).unwrap();
	
	Self { inner }
    }
}

struct GE_sgx_w {
    inner: GE_sgx
}

impl Deref for GE_sgx_w {
     type Target = GE_sgx;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for GE_sgx_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&GE> for GE_sgx_w {
    fn from(item: &GE) -> Self {
	use curv::elliptic::curves::traits::ECPoint;
	use curv_client::arithmetic::traits::Converter as Converter_sgx;

	let ser = &item.get_element().serialize_uncompressed();
	let inner: GE_sgx = curv_client::elliptic::curves::traits::ECPoint::from_bytes(
	    &ser[1..ser.len()]
	).unwrap();


	Self { inner }
    }
}


struct FE_w {
    inner: FE
}

impl Deref for FE_w {
     type Target = FE;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for FE_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&FE_sgx> for FE_w {
    fn from(item: &FE_sgx) -> Self {
	use curv_client::elliptic::curves::traits::ECScalar;
	let inner: FE = curv::elliptic::curves::traits::ECScalar::from(
	    &BigInt_w::from(&item.to_big_int()).inner
	);
	Self { inner }
    }
}

struct FE_sgx_w {
    inner: FE_sgx
}

impl Deref for FE_sgx_w {
     type Target = FE_sgx;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for FE_sgx_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&FE> for FE_sgx_w {
    fn from(item: &FE) -> Self {
	use curv::elliptic::curves::traits::ECScalar;
	let inner: FE_sgx = curv_client::elliptic::curves::traits::ECScalar::from(
	    &BigInt_sgx_w::from(&item.to_big_int()).inner
	);
	Self { inner }
    }
}

struct ECDDHProof_w {
    inner: ECDDHProof
}

impl Deref for ECDDHProof_w {
     type Target = ECDDHProof;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for ECDDHProof_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&ECDDHProof_sgx> for ECDDHProof_w {
    fn from(item: &ECDDHProof_sgx) -> Self {
	let a1 = GE_w::from(&item.a1).inner;
	let a2 = GE_w::from(&item.a2).inner;
	let z = FE_w::from(&item.z).inner;
	let inner =  ECDDHProof { a1, a2, z };
	Self { inner }
    }
}


struct ECDDHProof_sgx_w {
    inner: ECDDHProof_sgx
}

impl Deref for ECDDHProof_sgx_w {
     type Target = ECDDHProof_sgx;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for ECDDHProof_sgx_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&ECDDHProof> for ECDDHProof_sgx_w {
    fn from(item: &ECDDHProof) -> Self {
	let a1 = GE_sgx_w::from(&item.a1).inner;
	let a2 = GE_sgx_w::from(&item.a2).inner;
	let z = FE_sgx_w::from(&item.z).inner;
	let inner =  ECDDHProof_sgx { a1, a2, z };
	Self { inner }
    }
}

struct DLogProof_w {
    inner: DLogProof
}

impl Deref for DLogProof_w {
     type Target = DLogProof;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for DLogProof_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&DLogProof_sgx> for DLogProof_w {
    fn from(item: &DLogProof_sgx) -> Self {
	let pk = GE_w::from(&item.pk).inner;
	let pk_t_rand_commitment = GE_w::from(&item.pk_t_rand_commitment).inner;
	let challenge_response = FE_w::from(&item.challenge_response).inner;
	let inner =  DLogProof { pk, pk_t_rand_commitment, challenge_response };
	Self { inner }
    }
}

struct DLogProof_sgx_w {
    inner: DLogProof_sgx
}

impl Deref for DLogProof_sgx_w {
     type Target = DLogProof_sgx;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for DLogProof_sgx_w {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&DLogProof> for DLogProof_sgx_w {
    fn from(item: &DLogProof) -> Self {
	let pk = GE_sgx_w::from(&item.pk).inner;
	let pk_t_rand_commitment = GE_sgx_w::from(&item.pk_t_rand_commitment).inner;
	let challenge_response = FE_sgx_w::from(&item.challenge_response).inner;
	let inner =  DLogProof_sgx { pk, pk_t_rand_commitment, challenge_response };
	Self { inner }
    }
}

pub struct BigInt_w {
    inner: BigInt
}

impl Deref for BigInt_w {
    type Target = BigInt;
    fn deref(&self) -> &Self::Target {
     	&self.inner
    }
}

impl DerefMut for BigInt_w {
    fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
    }
}

impl From<&BigInt_sgx> for BigInt_w {
    fn from(item: &BigInt_sgx) -> Self {
	let item_vec : Vec::<u8> = item.to_signed_bytes_be();
	let inner : BigInt = From::from(item_vec.as_slice());
	Self { inner }
    }
}


pub struct BigInt_sgx_w {
    inner: BigInt_sgx
}

impl Deref for BigInt_sgx_w {
    type Target = BigInt_sgx;
    fn deref(&self) -> &Self::Target {
     	&self.inner
    }
}

impl DerefMut for BigInt_sgx_w {
    fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
    }
}

impl From<&BigInt> for BigInt_sgx_w {
    fn from(item: &BigInt) -> Self {
	let item_vec : Vec<u8> = item.into();
	let inner = BigInt_sgx::from_signed_bytes_be(item_vec.as_slice());
	Self { inner }
    }
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct SignSecondOut {
    inner: Vec<Vec<u8>>
}

impl Enclave {
    pub fn new() -> Result<Self> {
        let mut launch_token: sgx_launch_token_t = [0; 1024];
	let mut launch_token_updated: i32 = 0;
    	// call sgx_create_enclave to initialize an enclave instance
    	// Debug Support: set 2nd parameter to 1
    	let debug = 1;
    	let mut misc_attr = sgx_misc_attribute_t {secs_attr: sgx_attributes_t { flags:0, xfrm:0}, misc_select:0};
    	match SgxEnclave::create(ENCLAVE_FILE,
				 debug,
                       		 &mut launch_token,
                       		 &mut launch_token_updated,
                       		 &mut misc_attr){
	    Ok(v) => Ok(Self{inner:v}),
	    Err(e) => return Err(LockboxError::Generic(e.to_string()).into()),
	}
    }
    
    pub fn say_something(&self, input_string: String) -> Result<String> {
     	let mut retval = sgx_status_t::SGX_SUCCESS;
	
     	let result = unsafe {
            say_something(self.geteid(),
			  &mut retval,
			  input_string.as_ptr() as * const u8,
			  input_string.len())
    	};
	
    	match result {
            sgx_status_t::SGX_SUCCESS => Ok(result.as_str().to_string()),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", result.as_str())).into())
        	
    	}
	
    }
    
    pub fn get_random_sealed_log(&self, rand_size: u32) -> Result<[u8; 8192]> {
     	let sealed_log = [0; 8192];
	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	
	let _result = unsafe {
	    create_sealed_secret_key(self.geteid(), &mut enclave_ret, sealed_log.as_ptr() as * mut u8, 8192);
	};
	
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok(sealed_log),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }

    pub fn verify_sealed_log(&self, sealed_log: [u8; 8192]) -> Result<()> {
     	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	
	let _result = unsafe {
	    verify_sealed_secret_key(self.geteid(), &mut enclave_ret, sealed_log.as_ptr() as * mut u8, 8192);
	};
	
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok(()),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }
    
    pub fn calc_sha256(&self, input_string: String) -> Result<[u8; 32]>{
	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	let mut hash = [0u8;32];
	let _result = unsafe {
	    calc_sha256(self.geteid(), &mut enclave_ret, input_string.as_ptr() as * const u8, input_string.len() as u32, hash.as_ptr() as * mut u8);
	};
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok(hash),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }

    pub fn sk_tweak_mul_assign(&self, sealed_log1: [u8; 8192], sealed_log2: [u8; 8192]) -> Result<[u8; 8192]> {
     	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	
	let _result = unsafe {
	    sk_tweak_add_assign(self.geteid(), &mut enclave_ret, sealed_log1.as_ptr() as * mut u8, 8192, sealed_log2.as_ptr() as * mut u8, 8192);
	};
	
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok((sealed_log1)),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }

    pub fn sk_tweak_add_assign(&self, sealed_log1: [u8; 8192], sealed_log2: [u8; 8192]) -> Result<[u8; 8192]> {
     	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	
	let _result = unsafe {
	    sk_tweak_mul_assign(self.geteid(), &mut enclave_ret, sealed_log1.as_ptr() as * mut u8, 8192, sealed_log2.as_ptr() as * mut u8, 8192);
	};
	
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok((sealed_log1)),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }

    pub fn sign(&self, message: &Message, sealed_log: &[u8; 8192]) -> Result<Signature> {
     	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;


	let sig = [0u8;64];
	
	let _result = unsafe {
	    sign(self.geteid(), &mut enclave_ret,
	    message.as_ptr(),  sealed_log.as_ptr() as *mut u8, sig.as_ptr() as *mut u8);
	};

	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => match Signature::from_compact(&sig){
		Ok(v) => Ok(v),
		Err(e) => Err(e.into()),
	    },
            _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }

    pub fn get_public_key(&self, sealed_log: &[u8; 8192]) -> Result<PublicKey> {
     	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;

	let mut public_key = [0u8;33];
	
	let _result = unsafe {
	    get_public_key(self.geteid(), &mut enclave_ret,
	    sealed_log.as_ptr() as *mut u8, public_key.as_mut_ptr());
	};

	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => {
		match PublicKey::from_slice(&public_key){
		    Ok(v) => Ok(v),
		    Err(e) => Err(e.into()),
		}
	    },
            _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into()),
	}
    }

    pub fn first_message(&self, sealed_log_in: &mut [u8; 8192]) -> Result<(party_one::KeyGenFirstMsg, [u8;8192])>
    {
     	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	let mut sealed_log_out = [0u8; 8192];
	let mut plain_ret = [0u8;256];

	let _result = unsafe {
	    first_message(self.geteid(), &mut enclave_ret,
			  sealed_log_in.as_mut_ptr() as *mut u8,
			  sealed_log_out.as_mut_ptr() as *mut u8,
			  plain_ret.as_mut_ptr() as *mut u8);	    
	};

	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => {
		let c = plain_ret[0].clone();
		let c = &[c];
		let nc_str = std::str::from_utf8(c).unwrap();
		let nc = nc_str.parse::<usize>().unwrap();
		let size_str = std::str::from_utf8(&plain_ret[1..(nc+1)]).unwrap();
		let size = size_str.parse::<usize>().unwrap();
		let mut msg_str = std::str::from_utf8(&plain_ret[(nc+1)..(size+nc+1)]).unwrap().to_string();
		let kg1m_sgx : KeyGenFirstMsg_sgx  = serde_json::from_str(&msg_str).unwrap();
		let kg1m_loc : KeyGenFirstMsg = KeyGenFirstMsg_w::from(&kg1m_sgx).inner;
		let kg1m = party_one::KeyGenFirstMsg{ pk_commitment: kg1m_loc.pk_commitment, zk_pok_commitment: kg1m_loc.zk_pok_commitment };
		Ok((kg1m, sealed_log_out))
	    },
	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into()),
	}	
    }

    pub fn first_message_transfer(&self, sealed_log_in: &mut [u8; 8192]) -> Result<(party_one::KeyGenFirstMsg, [u8;8192])>
    {
     	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	let mut sealed_log_out = [0u8; 8192];
	let mut plain_ret = [0u8;256];

	let _result = unsafe {
	    first_message_transfer(self.geteid(), &mut enclave_ret,
			  sealed_log_in.as_mut_ptr() as *mut u8,
			  sealed_log_out.as_mut_ptr() as *mut u8,
			  plain_ret.as_mut_ptr() as *mut u8);	    
	};

	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => {
		let c = plain_ret[0].clone();
		let c = &[c];
		let nc_str = std::str::from_utf8(c).unwrap();
		let nc = nc_str.parse::<usize>().unwrap();
		let size_str = std::str::from_utf8(&plain_ret[1..(nc+1)]).unwrap();
		let size = size_str.parse::<usize>().unwrap();
		let mut msg_str = std::str::from_utf8(&plain_ret[(nc+1)..(size+nc+1)]).unwrap().to_string();
		let kg1m_sgx : KeyGenFirstMsg_sgx  = serde_json::from_str(&msg_str).unwrap();
		let kg1m_loc : KeyGenFirstMsg = KeyGenFirstMsg_w::from(&kg1m_sgx).inner;
		let kg1m = party_one::KeyGenFirstMsg{ pk_commitment: kg1m_loc.pk_commitment, zk_pok_commitment: kg1m_loc.zk_pok_commitment };
		Ok((kg1m, sealed_log_out))
	    },
	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into()),
	}	
    }

    pub fn second_message(&self, sealed_log_in: &mut [u8; 8192], key_gen_msg_2: &KeyGenMsg2)
	-> Result<(party1::KeyGenParty1Message2,  [u8;8192])>{
	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	let mut sealed_log_out = [0u8; 8192];
	let mut plain_ret = [0u8;480000];

	println!("converting KeyGenMsg2 to SGX");
	let key_gen_msg2_sgx = &KeyGenMsg2_sgx_w::from(key_gen_msg_2).inner;
	println!("converting KeyGenMsg2_sgx to string");
	let msg_2_str = serde_json::to_string(key_gen_msg2_sgx).unwrap();
	
	let _result = unsafe{
	    println!("doing second message");
	    second_message(self.geteid(), &mut enclave_ret,
			   sealed_log_in.as_mut_ptr() as *mut u8,
			   sealed_log_out.as_mut_ptr() as *mut u8,
			   msg_2_str.as_ptr() as * const u8,
			   msg_2_str.len(),
			   plain_ret.as_mut_ptr() as *mut u8)
	};

	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => {
		let c = plain_ret[0].clone();
		let c = &[c];
		let nc_str = std::str::from_utf8(c).unwrap();
		let nc = nc_str.parse::<usize>().unwrap();
		let size_str = std::str::from_utf8(&plain_ret[1..(nc+1)]).unwrap();
		let size = size_str.parse::<usize>().unwrap();
		let mut msg_str = std::str::from_utf8(&plain_ret[(nc+1)..(size+nc+1)]).unwrap().to_string();
		let kgm2_sgx : KeyGenParty1Message2_sgx  = serde_json::from_str(&msg_str).unwrap();
		let kgm2 : party1::KeyGenParty1Message2 = KeyGenParty1Message2_w::from(&kgm2_sgx).inner;
		Ok((kgm2, sealed_log_out))
	    },
	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into()),
	}
	
    }

    
    pub fn sign_first(&self, sealed_log_in: &mut [u8; 8192], sign_msg1: &SignMsg1)
	-> Result<Option<(party_one::EphKeyGenFirstMsg, [u8;8192])>> {
	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	let mut sealed_log_out = [0u8; 8192];
	let mut plain_ret = [0u8;480000];

	let sign_msg1_sgx = SignMsg1_sgx_w::from(sign_msg1).inner;
	
	
	let sign_msg1_str = serde_json::to_string(&sign_msg1_sgx).unwrap();
	
	let _result = unsafe {
	    sign_first(self.geteid(), &mut enclave_ret,
		       sealed_log_in.as_mut_ptr() as *mut u8,
                       sealed_log_out.as_mut_ptr() as *mut u8,
		       sign_msg1_str.as_ptr() as * const u8,
		       sign_msg1_str.len(),
	    	       plain_ret.as_mut_ptr() as *mut u8)
	};

	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => {
		let c = plain_ret[0].clone();
		let c = &[c];
		let nc_str = std::str::from_utf8(c).unwrap();
		let nc = nc_str.parse::<usize>().unwrap();
		let size_str = std::str::from_utf8(&plain_ret[1..(nc+1)]).unwrap();
		let size = size_str.parse::<usize>().unwrap();
		let mut msg_str = std::str::from_utf8(&plain_ret[(nc+1)..(size+nc+1)]).unwrap().to_string();
		let ekg1m_sgx : EphKeyGenFirstMsg_sgx  = serde_json::from_str(&msg_str).unwrap();
		let ekg1m : party_one::EphKeyGenFirstMsg = party_one_enc::EphKeyGenFirstMsg_w::from(&ekg1m_sgx).inner;
		Ok(Some((ekg1m, sealed_log_out)))
	    },
	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into()),
	}	
    }

    pub fn sign_second(&self, sealed_log_in: &mut [u8; 8192], sign_msg2: &SignMsg2)
		       -> Result<(Vec<Vec<u8>>, [u8;8192])>
    {
	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	let mut sealed_log_out = [0u8; 8192];
	let mut plain_ret = [0u8;480000];

	println!("converting signmsg2 to sgx");
	let sign_msg2_sgx = SignMsg2_sgx_w::from(sign_msg2).inner;
	println!("signmsg2_sgx to string");
	let sign_msg2_str = serde_json::to_string(&sign_msg2_sgx).unwrap();

	println!("sign second in enclave:");
	let _result = unsafe {
	    sign_second(self.geteid(), &mut enclave_ret,
			sealed_log_in.as_mut_ptr() as *mut u8,
			sealed_log_out.as_mut_ptr() as *mut u8,
			sign_msg2_str.as_ptr() as * const u8,
			sign_msg2_str.len(),
	    		plain_ret.as_mut_ptr() as *mut u8)
	};

	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => {
		println!("sign_second success");
		let c = plain_ret[0].clone();
		let c = &[c];
		let nc_str = std::str::from_utf8(c).unwrap();
		let nc = nc_str.parse::<usize>().unwrap();
		let size_str = std::str::from_utf8(&plain_ret[1..(nc+1)]).unwrap();
		let size = size_str.parse::<usize>().unwrap();
		let mut msg_str = std::str::from_utf8(&plain_ret[(nc+1)..(size+nc+1)]).unwrap().to_string();
		let output : SignSecondOut  = serde_json::from_str(&msg_str).unwrap();
		Ok((output.inner, sealed_log_out))
//		Ok((Vec::<Vec::<u8>>::new(), [0u8;8192]))
	    },
	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into()),
	}	
	
    }


    pub fn keyupdate_first(&self, sealed_log_in: &mut [u8; 8192], receiver_msg: &KUSendMsg)
	-> Result<(KUReceiveMsg, [u8;8192])> {
	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	let mut sealed_log_out = [0u8; 8192];
	let mut plain_ret = [0u8;8192];

	let receiver_msg_sgx = KUSendMsg_sgx_w::from(receiver_msg).inner;
		
	let receiver_msg_str = serde_json::to_string(&receiver_msg_sgx).unwrap();
	
	let _result = unsafe {
	    keyupdate_first(self.geteid(), &mut enclave_ret,
		       sealed_log_in.as_mut_ptr() as *mut u8,
                       sealed_log_out.as_mut_ptr() as *mut u8,
		       receiver_msg_str.as_ptr() as * const u8,
		       receiver_msg_str.len(),
	    	       plain_ret.as_mut_ptr() as *mut u8)
	};

	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => {
		let c = plain_ret[0].clone();
		let c = &[c];
		let nc_str = std::str::from_utf8(c).unwrap();
		let nc = nc_str.parse::<usize>().unwrap();
		let size_str = std::str::from_utf8(&plain_ret[1..(nc+1)]).unwrap();
		let size = size_str.parse::<usize>().unwrap();
		let mut msg_str = std::str::from_utf8(&plain_ret[(nc+1)..(size+nc+1)]).unwrap().to_string();
		let ku_receive_msg_sgx : KUReceiveMsg_sgx  = serde_json::from_str(&msg_str).unwrap();
		let ku_receive_msg : KUReceiveMsg = KUReceiveMsg_w::from(&ku_receive_msg_sgx).inner;
		Ok((ku_receive_msg, sealed_log_out))
	    },
	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into()),
	}	
    }


    
    pub fn destroy(&self) {
     	unsafe {
	    sgx_destroy_enclave(self.geteid());
	}
    }

}

extern {
    fn say_something(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     some_string: *const u8, len: usize) -> sgx_status_t;


    fn create_sealed_secret_key(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
            sealed_log: * mut u8, sealed_log_size: u32 );

    fn verify_sealed_secret_key(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
				sealed_log: * mut u8, sealed_log_size: u32);

    fn calc_sha256(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		   input_str: * const u8, len: u32, hash: * mut u8) -> sgx_status_t;

    fn sk_tweak_add_assign(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
			   sealed_log1: * mut u8, sealed_log1_size: u32,
			   sealed_log2: * mut u8, sealed_log2_size: u32) -> sgx_status_t;

    fn sk_tweak_mul_assign(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
			   sealed_log1: * mut u8, sealed_log1_size: u32,
			   sealed_log2: * mut u8, sealed_log2_size: u32) -> sgx_status_t;


    fn sign(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
	    some_message: * const u8,  sk_sealed_log: *mut u8, sig: *mut u8) -> sgx_status_t;

    fn get_public_key(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		      sk_sealed_log: *mut u8, public_key: *mut u8) -> sgx_status_t;

    fn first_message(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		     sealed_log_in: *mut u8,
		     sealed_log_out: *mut u8,
		     key_gen_first_msg: *mut u8);

    fn first_message_transfer(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		     sealed_log_in: *mut u8,
		     sealed_log_out: *mut u8,
		     key_gen_first_msg: *mut u8);

    fn second_message(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		      sealed_log_in: *mut u8,
		      sealed_log_out: *mut u8,
		      msg2_str: *const u8,
		      len: usize,
    		      plain_out: *mut u8);

    fn sign_first(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		  sealed_log_in: *mut u8,
                  sealed_log_out: *mut u8,
		  sign_msg1: *const u8,
		  len: usize,
		  plain_out: *mut u8,
    );

    fn sign_second(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		   sealed_log_in: *mut u8,
                   sealed_log_out: *mut u8,
		   sign_msg2: *const u8,
		   len: usize,
		   plain_out: *mut u8,
    );

    fn keyupdate_first(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		  sealed_log_in: *mut u8,
                  sealed_log_out: *mut u8,
		  receiver_msg: *const u8,
		  len: usize,
		  plain_out: *mut u8,
    );

    fn keyupdate_second(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		   sealed_log_in: *mut u8,
                   sealed_log_out: *mut u8,
		   sign_msg2: *const u8,
		   len: usize,
		   plain_out: *mut u8,
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    pub static BACKUP_TX_NOT_SIGNED: &str = "{\"version\":2,\"lock_time\":0,\"input\":[{\"previous_output\":\"faaaa0920fbaefae9c98a57cdace0deffa96cc64a651851bdd167f397117397c:0\",\"script_sig\":\"\",\"sequence\":4294967295,\"witness\":[]}],\"output\":[{\"value\":9000,\"script_pubkey\":\"00148fc32525487d2cb7323c960bdfb0a5ee6a364738\"}]}";
    pub static BACKUP_TX_SIGNED: &str = "{\"version\":2,\"lock_time\":0,\"input\":[{\"previous_output\":\"faaaa0920fbaefae9c98a57cdace0deffa96cc64a651851bdd167f397117397c:0\",\"script_sig\":\"\",\"sequence\":4294967295,\"witness\":[[48,68,2,32,45,42,91,77,252,143,55,65,154,96,191,149,204,131,88,79,80,161,231,209,234,229,217,100,28,99,48,148,136,194,204,98,2,32,90,111,183,68,74,24,75,120,179,80,20,183,60,198,127,106,102,64,37,193,174,226,199,118,237,35,96,236,45,94,203,49,1],[2,242,131,110,175,215,21,123,219,179,199,144,85,14,163,42,19,197,97,249,41,130,243,139,15,17,51,185,147,228,100,122,213]]}],\"output\":[{\"value\":9000,\"script_pubkey\":\"00148fc32525487d2cb7323c960bdfb0a5ee6a364738\"}]}";
    pub static STATE_CHAIN: &str = "{\"chain\":[{\"data\":\"026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e\",\"next_state\":null}]}";
    pub static STATE_CHAIN_SIG: &str = "{ \"purpose\": \"TRANSFER\", \"data\": \"024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766\", \"sig\": \"3045022100e1171094db96e68392bb2a72695dc7cbce86db7be9d2e943444b6fa08877eec9022036dc63a3b2536d8e2327e0f44ff990f18e6166dce66d87bdcb57f825158a507c\"}";

    #[test]
    fn test_new() {
       let enc = Enclave::new().unwrap();
       enc.destroy();
    }

    #[test]
    fn test_say_something() {
       let enc = Enclave::new().unwrap();
       let _ = enc.say_something("From test_say_something. ".to_string()).unwrap();
       enc.destroy();
    }

    #[test]
    fn test_get_random_sealed_log() {
       let enc = Enclave::new().unwrap();
       let _rsd = enc.get_random_sealed_log(100).unwrap();
       enc.destroy();
    }

    #[test]
    fn test_verify_sealed_log() {
       let enc = Enclave::new().unwrap();
       let rsd = enc.get_random_sealed_log(1020).unwrap();
       enc.verify_sealed_log(rsd).unwrap();
       enc.destroy();
    }

    #[test]
    fn test_calc_sha256() {
	let enc = Enclave::new().unwrap();
	let hash = enc.calc_sha256("test string".to_string()).unwrap();
	let expected_hash: [u8;32] = [213, 87, 156, 70, 223, 204, 127, 24, 32, 112, 19, 230, 91, 68, 228, 203, 78, 44, 34, 152, 244, 172, 69, 123, 168, 248, 39, 67, 243, 30, 147, 11];
	assert_eq!(hash, expected_hash);
	enc.destroy();
    }

    #[test]
    fn test_sk_tweak_add_assign() {
	let enc = Enclave::new().unwrap();
	let rsd1 = enc.get_random_sealed_log(32).unwrap();
	let rsd2 = enc.get_random_sealed_log(32).unwrap();

	let rsd = enc.sk_tweak_add_assign(rsd1, rsd2).unwrap();

	enc.destroy();
    }

    #[test]
    fn test_sk_tweak_mul_assign() {
	let enc = Enclave::new().unwrap();
	let rsd1 = enc.get_random_sealed_log(32).unwrap();
	let rsd2 = enc.get_random_sealed_log(32).unwrap();

	let rsd = enc.sk_tweak_mul_assign(rsd1, rsd2).unwrap();
	
	enc.destroy();
    }

    #[test]
    fn test_sign_verify() {
	let enc = Enclave::new().unwrap();
	let rsd1 = enc.get_random_sealed_log(32).unwrap();
	let msg_data : [u8;32] = [214, 88, 152, 71, 224, 205, 127, 22, 31, 115, 20, 230, 91, 68, 228, 203, 78, 44, 34, 152, 244, 172, 69, 123, 168, 248, 39, 67, 243, 30, 147, 11];
	let message = Message::from_slice(&msg_data).unwrap();
	let signature = enc.sign(&message, &rsd1).unwrap();
	let pubkey = enc.get_public_key(&rsd1).unwrap();

	let secp = Secp256k1::new();
	secp.verify(&message, &signature, &pubkey).unwrap();

	let msg_data_wrong : [u8;32] = [213, 88, 152, 71, 224, 205, 127, 22, 31, 115, 20, 230, 91, 68, 228, 203, 78, 44, 34, 152, 244, 172, 69, 123, 168, 248, 39, 67, 243, 30, 147, 11];
	let message_wrong = Message::from_slice(&msg_data_wrong).unwrap();
	match secp.verify(&message_wrong, &signature, &pubkey){
	    Ok(_) => assert!(false, "expected Err: Incorrect Signature"),
	    Err(e) => assert!(e.to_string().contains("signature failed verification"), format!("{} does not contain \"signature failed verification\"", e)),
	}

	enc.destroy();
    }

    #[test]
    fn test_first_message() {
	let enc = Enclave::new().unwrap();
	let mut rsd1 = enc.get_random_sealed_log(32).unwrap();
	enc.verify_sealed_log(rsd1).unwrap();
	let (kg1m, sealed_log_out) = enc.first_message(&mut rsd1).unwrap();
    }

    #[test]
    fn test_second_message() {
	let enc = Enclave::new().unwrap();
	let mut rsd1 = enc.get_random_sealed_log(32).unwrap();
	enc.verify_sealed_log(rsd1).unwrap();
	let (kg1m, mut sealed_log_out) = enc.first_message(&mut rsd1).unwrap();

	let wallet_secret_key: FE = ECScalar::new_random();

	let pk_commitment = &kg1m.pk_commitment;
	let zk_pok_commitment = &kg1m.zk_pok_commitment;
	
	let (kg_party_two_first_message, kg_ec_key_pair_party2) =
	    MasterKey2::key_gen_first_message_predefined(&wallet_secret_key);

	let shared_key_id = &Uuid::new_v4();
	
	let key_gen_msg2 = KeyGenMsg2 {
            shared_key_id: *shared_key_id,
            dlog_proof: kg_party_two_first_message.d_log_proof,
	};
		
	let kgm2str = serde_json::to_string(&key_gen_msg2).unwrap();
	let kgm_2 : KeyGenMsg2 = serde_json::from_str(&kgm2str).unwrap();

	assert!(kgm2str.len() > 0);
	
	enc.second_message(&mut sealed_log_out, &kgm_2).unwrap();
    }

    #[test]
    fn test_convert_bigint() {
	use num_bigint_dig::{ToBigInt, Sign};
	
	let n1 : u64 = 123;
	let n2 : u64 = 456;
	let ns = n1 + n2;
	let ns2 = ns + 1;
	
	let nbi1 : BigInt_sgx = From::from(n1);
	let nbi2 : BigInt_sgx = From::from(n2);
	let nbis = nbi1 + nbi2;

	
	let wbi1 = BigInt_w { inner: From::from(n1) };
	let wbi2 = BigInt_w { inner: From::from(n2) };
	let wbis : BigInt_w  = From::from(&nbis);
	let wbis2 = BigInt_w { inner: wbi1.deref() + wbi2.deref() };

	assert!(wbis.deref() == wbis2.deref(), format!("{:?} does not equal {:?}", wbis.deref(), wbis2.deref()));
	
    }

    #[test]
    fn test_convert_bigint_sgx() {
	use num_bigint_dig::{ToBigInt, Sign};
	
	let n1 : u64 = 123;
	let n2 : u64 = 456;
	let ns = n1 + n2;
	let ns2 = ns + 1;
	
	let nbi1 : BigInt = From::from(n1);
	let nbi2 : BigInt = From::from(n2);
	let nbis = nbi1 + nbi2;

	
	let wbi1 = BigInt_sgx_w { inner: From::from(n1) };
	let wbi2 = BigInt_sgx_w { inner: From::from(n2) };
	let wbis : BigInt_sgx_w  = From::from(&nbis);
	let wbis2 = BigInt_sgx_w { inner: wbi1.deref() + wbi2.deref() };

	assert!(wbis.deref() == wbis2.deref(), format!("{:?} does not equal {:?}", wbis.deref(), wbis2.deref()));
    }

    #[test]
    fn test_convert_negative_bigint_sgx() {
	use num_bigint_dig::{ToBigInt, Sign};
	
	let n1 : i64 = 123;
	let n2 : i64 = -456;
	let ns = n1 + n2;
	let ns2 = ns + 1;
	
	let nbi1 : BigInt = From::from(n1);
	let nbi2 : BigInt = From::from(n2);
	let nbis = nbi1 + nbi2;

	
	let wbi1 = BigInt_sgx_w { inner: From::from(n1) };
	let wbi2 = BigInt_sgx_w { inner: From::from(n2) };
	let wbis : BigInt_sgx  = From::from(ns);
	let wbis2 = BigInt_sgx_w { inner: wbi1.deref() + wbi2.deref() };

	assert!(&wbis == wbis2.deref(), format!("{:?} does not equal {:?}", &wbis, wbis2.deref()));
    }

    use curv::elliptic::curves::traits::ECPoint as ECPoint_sgx;
    
    #[test]
    fn test_convert_ge() {
	let ge1: GE = GE::generator() * FE::new_random();
	let ge2: GE = GE::generator() * FE::new_random();
	let s1 = ge1 + ge2;
	
	let ge1_sgx = GE_sgx_w::from(&ge1).inner;
	let ge2_sgx = GE_sgx_w::from(&ge2).inner;
	let s1_sgx = ge1_sgx + ge2_sgx;

	let ge1_2 = GE_w::from(&ge1_sgx).inner;
	let ge2_2 = GE_w::from(&ge2_sgx).inner;
	let s1_2 = GE_w::from(&s1_sgx).inner;


	assert_eq!(ge1.get_element(), ge1_2.get_element());
	assert_eq!(ge2.get_element(), ge2_2.get_element());
	assert_eq!(s1.get_element(), s1_2.get_element());
    }

    #[test]
    fn test_sign() {
	use bitcoin::{Transaction, hashes::sha256d};
	
	let enc = Enclave::new().unwrap();
	let mut rsd1 = enc.get_random_sealed_log(32).unwrap();
	enc.verify_sealed_log(rsd1).unwrap();



	let (kg_party_one_first_message, mut sealed_log_out) = enc.first_message(&mut rsd1).unwrap();

	let wallet_secret_key: FE = ECScalar::new_random();

	let pk_commitment = &kg_party_one_first_message.pk_commitment;
	let zk_pok_commitment = &kg_party_one_first_message.zk_pok_commitment;
	
	let (kg_party_two_first_message, kg_ec_key_pair_party2) =
	    MasterKey2::key_gen_first_message_predefined(&wallet_secret_key);

	let shared_key_id = Uuid::new_v4();
	let tx_backup: Transaction = serde_json::from_str(&BACKUP_TX_NOT_SIGNED).unwrap();


	let hexhash = r#"
                "0000000000000000000000000000000000000000000000000000000000000000"
            "#;
        let sig_hash: sha256d::Hash = serde_json::from_str(&hexhash.to_string()).unwrap();

	let (eph_key_gen_first_message_party_two, eph_comm_witness, eph_ec_key_pair_party2) =
            MasterKey2::sign_first_message();


	let key_gen_msg2 = KeyGenMsg2 {
            shared_key_id: shared_key_id.clone(),
            dlog_proof: kg_party_two_first_message.d_log_proof,
	};
		
	let kgm2str = serde_json::to_string(&key_gen_msg2).unwrap();
	let kgm_2 : KeyGenMsg2 = serde_json::from_str(&kgm2str).unwrap();

	assert!(kgm2str.len() > 0);
	
	let (kg_party_one_second_message, mut sealed_log_2) = enc.second_message(&mut sealed_log_out, &kgm_2).unwrap();

	let key_gen_second_message = MasterKey2::key_gen_second_message(
            &kg_party_one_first_message,
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

	
	let sign_msg1 = SignMsg1 {
            shared_key_id: shared_key_id,
            eph_key_gen_first_message_party_two: eph_key_gen_first_message_party_two,
        };

	
	let (ekg1m, mut sign_first_sealed) = enc.sign_first(&mut sealed_log_2, &sign_msg1).unwrap();
	

	let message = BigInt::from(0);
	
	let party_two_sign_message = master_key.sign_second_message(
            &eph_ec_key_pair_party2,
            eph_comm_witness.clone(),
            &ekg1m,
            &message,
	);
	

        let sign_msg2 = SignMsg2 {
            shared_key_id: shared_key_id,
            sign_second_msg_request: SignSecondMsgRequest {
                protocol: Protocol::Deposit,
                message: BigInt::from(0),
                party_two_sign_message,
            },
        };
	

	println!("sign second:");
        let (return_msg, return_sealed) = enc.sign_second(&mut sign_first_sealed, &sign_msg2).unwrap();
	
    }
    
}



