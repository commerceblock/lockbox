use std::ops::{Deref, DerefMut};
extern crate sgx_types;
extern crate sgx_urts;
use self::sgx_types::*;
use self::sgx_urts::SgxEnclave;
use crate::error::LockboxError;
use crate::shared_lib::structs::*;

extern crate bitcoin;
use bitcoin::secp256k1::{Signature, Message, PublicKey};
pub use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
pub use multi_party_ecdsa_client::protocols::two_party_ecdsa::lindell_2017::party_one::KeyGenSecondMsg as KeyGenSecondMsgSgx;
pub use multi_party_ecdsa_client::protocols::two_party_ecdsa::lindell_2017::party_one::KeyGenFirstMsg as KeyGenFirstMsgSgx;
pub use multi_party_ecdsa_client::protocols::two_party_ecdsa::lindell_2017::party_one::CommWitness as CommWitnessSgx;
pub use multi_party_ecdsa_client::protocols::two_party_ecdsa::lindell_2017::party_one::EphKeyGenFirstMsg as EphKeyGenFirstMsgSgx;
pub use multi_party_ecdsa_client::protocols::two_party_ecdsa::lindell_2017::party_two as party_two_sgx; 
pub use multi_party_ecdsa_client::utilities::zk_pdl_with_slack::PDLwSlackProof as PDLwSlackProofSgx;
pub use multi_party_ecdsa_client::utilities::zk_pdl_with_slack::PDLwSlackStatement as PDLwSlackStatementSgx;
pub use multi_party_ecdsa::utilities::zk_pdl_with_slack::{PDLwSlackStatement, PDLwSlackProof};
pub use kms_sgx::ecdsa::two_party::party1::KeyGenParty1Message2 as KeyGenParty1Message2Sgx;
pub use kms_sgx::ecdsa::two_party::party2 as party2_sgx;
use curv::{BigInt, FE, GE, elliptic::curves::traits::{ECPoint, ECScalar},
	   cryptographic_primitives::proofs::sigma_dlog::{DLogProof}};
pub use curv_client::cryptographic_primitives::proofs::sigma_dlog::DLogProof as DLogProofSgx;
pub use curv_client::cryptographic_primitives::proofs::sigma_ec_ddh::ECDDHProof as ECDDHProofSgx;
pub use curv::cryptographic_primitives::proofs::sigma_ec_ddh::ECDDHProof;
pub use curv_client::GE as GESgx;
pub use curv_client::FE as FESgx;
pub use curv_client::BigInt as BigIntSgx;
use uuid::Uuid;
use kms::ecdsa::two_party::*;
use paillier::EncryptionKey;
use paillier_client::EncryptionKey as EncryptionKeySgx;
use zk_paillier::zkproofs::{NICorrectKeyProof, RangeProofNi, Response, EncryptedPairs, Proof, CompositeDLogProof};
use zk_paillier_client::zkproofs::NICorrectKeyProof as NICorrectKeyProofSgx;
use zk_paillier_client::zkproofs::RangeProofNi as RangeProofNiSgx;
use zk_paillier_client::zkproofs::EncryptedPairs as EncryptedPairsSgx;
use zk_paillier_client::zkproofs::Proof as ProofSgx;
use zk_paillier_client::zkproofs::range_proof::Response as ResponseSgx;
pub use zk_paillier_client::zkproofs::CompositeDLogProof as CompositeDLogProofSgx;

static ENCLAVE_FILE: &'static str = "/opt/lockbox/bin/enclave.signed.so";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

//Shared encryption key for enclaves
pub const EC_KEY_SEALED_SIZE: usize = 592;
pub type ec_key_sealed = [u8; EC_KEY_SEALED_SIZE];

pub const EC_LOG_SIZE: usize = 8192;
pub type ec_log = [u8; EC_LOG_SIZE];

pub struct Enclave {
    inner: SgxEnclave,
    ec_key: Option<ec_key_sealed>
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


#[derive(Clone)]
pub struct SgxReport(sgx_report_t);

impl Deref for SgxReport {
    type Target = sgx_report_t;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

/*
impl Serialize for SgxReport {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where S: Serializer
    {
        // Any implementation of Serialize.
    }
}

impl DeSerialize for SgxReport {
    fn deserialize<D>(&self, deserializer: D) -> Result<Self, D::Error>
    where D: Deserializer
    {
        // Any implementation of Serialize.
    }
}
 */



mod party_one_enc {
    use super::*;

    pub struct EphKeyGenFirstMsgW {
	pub inner: party_one::EphKeyGenFirstMsg
    }
    
    impl Deref for EphKeyGenFirstMsgW {
	type Target = party_one::EphKeyGenFirstMsg;
	fn deref(&self) -> &Self::Target {
	    &self.inner
	}
    }
    
    impl DerefMut for EphKeyGenFirstMsgW {
	fn deref_mut(&mut self) -> &mut Self::Target {
	    &mut self.inner
	}
    }

    impl From<&EphKeyGenFirstMsgSgx> for EphKeyGenFirstMsgW {
	fn from(item: &EphKeyGenFirstMsgSgx) -> Self {
	    let d_log_proof = ECDDHProofW::from(&item.d_log_proof).inner;
	    let public_share = GEW::from(&item.public_share).inner;
	    let c = GEW::from(&item.c).inner;

	    Self { inner:  party_one::EphKeyGenFirstMsg{ d_log_proof, public_share, c } }
	}
    }
}

mod party_two_enc {
    use super::*;

    pub struct EphKeyGenFirstMsgSgxW {
	pub inner: party_two_sgx::EphKeyGenFirstMsg
    }

    impl Deref for EphKeyGenFirstMsgSgxW {
	type Target = party_two_sgx::EphKeyGenFirstMsg;
	fn deref(&self) -> &Self::Target {
	    &self.inner
	}
    }

    impl DerefMut for EphKeyGenFirstMsgSgxW {
	fn deref_mut(&mut self) -> &mut Self::Target {
	    &mut self.inner
	}
    }
    
    impl From<&party_two::EphKeyGenFirstMsg> for EphKeyGenFirstMsgSgxW {
	fn from(item: &party_two::EphKeyGenFirstMsg) -> Self {
	    let pk_commitment = BigIntSgxW::from(&item.pk_commitment).inner;
	    let zk_pok_commitment = BigIntSgxW::from(&item.pk_commitment).inner;
	    
	    Self { inner:  party_two_sgx::EphKeyGenFirstMsg{ pk_commitment, zk_pok_commitment } }
	}
    }

    struct EphCommWitnessSgxW {
	inner: party_two_sgx::EphCommWitness
    }
    
    impl Deref for EphCommWitnessSgxW {
	type Target = party_two_sgx::EphCommWitness;
	fn deref(&self) -> &Self::Target {
     	    &self.inner
	}
    }
    
    impl DerefMut for EphCommWitnessSgxW {
	fn deref_mut(&mut self) -> &mut Self::Target {
     	    &mut self.inner
	}
    }
    
    impl From<&party_two::EphCommWitness> for EphCommWitnessSgxW {
	fn from(item: &party_two::EphCommWitness) -> Self {
	    let pk_commitment_blind_factor = BigIntSgxW::from(&item.pk_commitment_blind_factor).inner;
	    let zk_pok_blind_factor = BigIntSgxW::from(&item.zk_pok_blind_factor).inner;
	    let public_share = GESgxW::from(&item.public_share).inner;
	    let d_log_proof = ECDDHProofSgxW::from(&item.d_log_proof).inner;
	    let c = GESgxW::from(&item.c).inner;
	    
	    Self { inner: party_two_sgx::EphCommWitness { pk_commitment_blind_factor, zk_pok_blind_factor, public_share, d_log_proof, c } }
	    
	}
    }



    pub struct ECDDHProofSgxW {
	pub inner: ECDDHProofSgx
    }

    impl Deref for ECDDHProofSgxW {
	type Target = ECDDHProofSgx;
	fn deref(&self) -> &Self::Target {
	    &self.inner
	}
    }

    impl DerefMut for ECDDHProofSgxW {
	fn deref_mut(&mut self) -> &mut Self::Target {
	    &mut self.inner
	}
    }
    
    impl From<&ECDDHProof> for ECDDHProofSgxW {
	fn from(item: &ECDDHProof) -> Self {
	    let a1 = GESgxW::from(&item.a1).inner;
	    let a2 = GESgxW::from(&item.a1).inner;
	    let z = FESgxW::from(&item.z).inner;
	    
	    Self { inner:  ECDDHProofSgx{ a1, a2, z } }
	}
    }

    


    pub struct EphKeyGenSecondMsgSgxW {
	pub inner: party_two_sgx::EphKeyGenSecondMsg
    }

    impl Deref for EphKeyGenSecondMsgSgxW {
	type Target = party_two_sgx::EphKeyGenSecondMsg;
	fn deref(&self) -> &Self::Target {
	    &self.inner
	}
    }

    impl DerefMut for EphKeyGenSecondMsgSgxW {
	fn deref_mut(&mut self) -> &mut Self::Target {
	    &mut self.inner
	}
    }
    
    impl From<&party_two::EphKeyGenSecondMsg> for EphKeyGenSecondMsgSgxW {
	fn from(item: &party_two::EphKeyGenSecondMsg) -> Self {
	    let comm_witness = party_two_enc::EphCommWitnessSgxW::from(&item.comm_witness).inner;
	    
	    Self { inner:  party_two_sgx::EphKeyGenSecondMsg{ comm_witness } }
	}
    }




    pub struct PartialSigSgxW {
	pub inner: party_two_sgx::PartialSig
    }

    impl Deref for PartialSigSgxW {
	type Target = party_two_sgx::PartialSig;
	fn deref(&self) -> &Self::Target {
	    &self.inner
	}
    }

    impl DerefMut for PartialSigSgxW {
	fn deref_mut(&mut self) -> &mut Self::Target {
	    &mut self.inner
	}
    }
    
    impl From<&party_two::PartialSig> for PartialSigSgxW {
	fn from(item: &party_two::PartialSig) -> Self {
	    let c3 = BigIntSgxW::from(&item.c3).inner;
	    
	    Self { inner:  party_two_sgx::PartialSig{ c3 } }
	}
    }
    
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KUSendMsgSgx {        // Sent from server to lockbox
    pub user_id: Uuid,
    pub statechain_id: Uuid,
    pub x1: FESgx,
    pub t2: FESgx,
    pub o2_pub: GESgx,
}

pub struct KUSendMsgSgxW {
    inner: KUSendMsgSgx
}

impl From<&KUSendMsg> for KUSendMsgSgxW {
    fn from(item: &KUSendMsg) -> Self {

	let user_id = item.user_id;
	let statechain_id = item.statechain_id;
	let x1 = FESgxW::from(&item.x1).inner;
	let t2 = FESgxW::from(&item.t2).inner;
	let o2_pub = GESgxW::from(&item.o2_pub).inner;
	
	Self { inner: KUSendMsgSgx { user_id, statechain_id, x1, t2, o2_pub } }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KUReceiveMsgSgx {      // Sent from lockbox back to server
    pub s2_pub: GESgx,
}

pub struct KUReceiveMsgW {
    inner: KUReceiveMsg
}

impl From<&KUReceiveMsgSgx> for KUReceiveMsgW {
    fn from(item: &KUReceiveMsgSgx) -> Self {
	let s2_pub = GEW::from(&item.s2_pub).inner;
	
	Self { inner: KUReceiveMsg { s2_pub } }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KeyGenMsg2Sgx {      // Sent from lockbox back to server
    pub shared_key_id: Uuid,
    pub dlog_proof: DLogProofSgx,
}

pub struct KeyGenMsg2SgxW {
    inner: KeyGenMsg2Sgx
}

impl From<&KeyGenMsg2> for KeyGenMsg2SgxW {
    fn from(item: &KeyGenMsg2) -> Self {
	let shared_key_id = item.shared_key_id;
	let dlog_proof = DLogProofSgxW::from(&item.dlog_proof).inner;
	
	Self { inner: KeyGenMsg2Sgx { shared_key_id, dlog_proof } }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignMsg1Sgx {
    pub shared_key_id: Uuid,
    pub eph_key_gen_first_message_party_two: party_two_sgx::EphKeyGenFirstMsg,
}

pub struct SignMsg1SgxW {
    inner: SignMsg1Sgx
}

impl Deref for SignMsg1SgxW {
     type Target = SignMsg1Sgx;
     fn deref(&self) -> &Self::Target {
	&self.inner
     }
}

impl DerefMut for SignMsg1SgxW {
     fn deref_mut(&mut self) -> &mut Self::Target {
	&mut self.inner
     }
}

impl From<&SignMsg1> for SignMsg1SgxW {
    fn from(item: &SignMsg1) -> Self {

	let shared_key_id = item.shared_key_id;
	let eph_key_gen_first_message_party_two =
	    party_two_enc::EphKeyGenFirstMsgSgxW::from(&item.eph_key_gen_first_message_party_two).inner;
	
	Self { inner: SignMsg1Sgx { shared_key_id, eph_key_gen_first_message_party_two } }
    }
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignMsg2Sgx {
    pub shared_key_id: Uuid,
    pub sign_second_msg_request: SignSecondMsgRequestSgx,
}

pub struct SignMsg2SgxW {
    inner: SignMsg2Sgx
}

impl Deref for SignMsg2SgxW {
     type Target = SignMsg2Sgx;
     fn deref(&self) -> &Self::Target {
	&self.inner
     }
}

impl DerefMut for SignMsg2SgxW {
     fn deref_mut(&mut self) -> &mut Self::Target {
	&mut self.inner
     }
}

impl From<&SignMsg2> for SignMsg2SgxW {
    fn from(item: &SignMsg2) -> Self {

	let shared_key_id = item.shared_key_id;
	let sign_second_msg_request =
	    SignSecondMsgRequestSgxW::from(&item.sign_second_msg_request).inner;
	
	Self { inner: SignMsg2Sgx { shared_key_id, sign_second_msg_request } }
    }
}


#[derive(Serialize, Deserialize, Debug)]
pub struct SignSecondMsgRequestSgx {
    pub protocol: Protocol,
    pub message: BigIntSgx,
    pub party_two_sign_message: party2_sgx::SignMessage,
}

pub struct SignSecondMsgRequestSgxW {
    inner: SignSecondMsgRequestSgx
}

impl Deref for SignSecondMsgRequestSgxW {
     type Target = SignSecondMsgRequestSgx;
     fn deref(&self) -> &Self::Target {
	&self.inner
     }
}

impl DerefMut for SignSecondMsgRequestSgxW {
     fn deref_mut(&mut self) -> &mut Self::Target {
	&mut self.inner
     }
}

impl From<&SignSecondMsgRequest> for SignSecondMsgRequestSgxW {
    fn from(item: &SignSecondMsgRequest) -> Self {

	let message = BigIntSgxW::from(&item.message).inner;
	let party_two_sign_message = party2_enc::SignMessageSgxW::from(&item.party_two_sign_message).inner;
	
	Self { inner: SignSecondMsgRequestSgx { protocol: item.protocol, message, party_two_sign_message } }
    }
}

mod party2_enc {
    use super::*;

    pub struct SignMessageSgxW {
	pub inner: party2_sgx::SignMessage
    }
    
    impl Deref for SignMessageSgxW {
	type Target = party2_sgx::SignMessage;
	fn deref(&self) -> &Self::Target {
	    &self.inner
	}
    }
    
    impl DerefMut for SignMessageSgxW {
	fn deref_mut(&mut self) -> &mut Self::Target {
	    &mut self.inner
	}
    }
    
    impl From<&party2::SignMessage> for SignMessageSgxW {
	fn from(item: &party2::SignMessage) -> Self {
	    let partial_sig = party_two_enc::PartialSigSgxW::from(&item.partial_sig).inner;
	    let second_message = party_two_enc::EphKeyGenSecondMsgSgxW::from(&item.second_message).inner;
	    
	    Self { inner: party2_sgx::SignMessage { partial_sig, second_message } }
	}
    }

    
}

//#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
//pub struct KeyGenFirstMsg{
//    pk_commitment: BigInt,
//    zk_pok_commitment: BigInt,
//}

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyGenFirstMsgW{
    inner: party_one::KeyGenFirstMsg
}

impl Deref for KeyGenFirstMsgW {
     type Target = party_one::KeyGenFirstMsg;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for KeyGenFirstMsgW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}


impl From<&KeyGenFirstMsgSgx> for KeyGenFirstMsgW {
    fn from(item: &KeyGenFirstMsgSgx) -> Self {

	let pk_commitment = BigIntW::from(&item.pk_commitment).inner;
	let zk_pok_commitment = BigIntW::from(&item.zk_pok_commitment).inner;
	
	let inner = party_one::KeyGenFirstMsg {
	    pk_commitment,
	    zk_pok_commitment,
	};

	Self { inner }
    }
}

pub struct KeyGenParty1Message2W {
    inner: party1::KeyGenParty1Message2
}

impl Deref for KeyGenParty1Message2W {
     type Target = party1::KeyGenParty1Message2;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for KeyGenParty1Message2W {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}


impl From<&KeyGenParty1Message2Sgx> for KeyGenParty1Message2W {
    fn from(item: &KeyGenParty1Message2Sgx) -> Self {

	let correct_key_proof = NICorrectKeyProofW::from(&item.correct_key_proof).deref().to_owned(); 

	let composite_dlog_proof = CompositeDLogProofW::from(&item.composite_dlog_proof).deref().to_owned();

	let pdl_proof = PDLwSlackProofW::from(&item.pdl_proof).deref().to_owned();

	let pdl_statement = PDLwSlackStatementW::from(&item.pdl_statement).deref().to_owned();
	
	let inner = party1::KeyGenParty1Message2 {
	    ecdh_second_message: KeyGenSecondMsgW::from(&item.ecdh_second_message).inner,
	    ek: EncryptionKeyW::from(&item.ek).inner,
	    c_key: BigIntW::from(&item.c_key).inner,
	    correct_key_proof,
	    composite_dlog_proof,
	    pdl_proof,
	    pdl_statement,
	};
	Self { inner }
    }
}


pub struct NICorrectKeyProofW {
    inner: NICorrectKeyProof
}

impl Deref for NICorrectKeyProofW {
     type Target = NICorrectKeyProof;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for NICorrectKeyProofW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&NICorrectKeyProofSgx> for NICorrectKeyProofW {
    fn from(item: &NICorrectKeyProofSgx) -> Self {
	let mut biv = Vec::<BigInt>::new();
	for nbi in &item.sigma_vec {
	    let biw = BigIntW::from(nbi);
	    biv.push(biw.inner);
	}
	Self { inner: NICorrectKeyProof { sigma_vec: biv } }
    }
}

pub struct CompositeDLogProofW {
    inner: CompositeDLogProof
}

impl Deref for CompositeDLogProofW {
     type Target = CompositeDLogProof;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for CompositeDLogProofW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&CompositeDLogProofSgx> for CompositeDLogProofW {
    fn from(item: &CompositeDLogProofSgx) -> Self {
	let x = BigIntW::from(&item.x).inner;
	let y = BigIntW::from(&item.y).inner;

	Self { inner: CompositeDLogProof { x, y } }
    }
}

pub struct PDLwSlackProofW {
    inner: PDLwSlackProof
}

impl Deref for PDLwSlackProofW {
     type Target = PDLwSlackProof;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for PDLwSlackProofW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&PDLwSlackProofSgx> for PDLwSlackProofW {
    fn from(item: &PDLwSlackProofSgx) -> Self {

	let z = BigIntW::from(&item.z).inner;
	let u1 = GEW::from(&item.u1).inner;
	let u2 = BigIntW::from(&item.u2).inner;
	let u3 = BigIntW::from(&item.u3).inner;
	let s1 = BigIntW::from(&item.s1).inner;
	let s2 = BigIntW::from(&item.s2).inner;
	let s3 = BigIntW::from(&item.s3).inner;

	Self { inner: PDLwSlackProof { z, u1, u2, u3, s1, s2, s3 } }
    }
}

pub struct PDLwSlackStatementW {
    inner: PDLwSlackStatement
}

impl Deref for PDLwSlackStatementW {
     type Target = PDLwSlackStatement;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for PDLwSlackStatementW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&PDLwSlackStatementSgx> for PDLwSlackStatementW {
    #[allow(non_snake_case)]
    fn from(item: &PDLwSlackStatementSgx) -> Self {

	let ciphertext = BigIntW::from(&item.ciphertext).inner;
	let ek = EncryptionKeyW::from(&item.ek).inner;
	let Q = GEW::from(&item.Q).inner;
	let G = GEW::from(&item.G).inner;
	let h1 = BigIntW::from(&item.h1).inner;
	let h2 = BigIntW::from(&item.h2).inner;
	let N_tilde = BigIntW::from(&item.N_tilde).inner;

	Self { inner: PDLwSlackStatement { ciphertext, ek, Q, G, h1, h2, N_tilde } }
    }
}

pub struct RangeProofNiW {
    inner: RangeProofNi
}

impl Deref for RangeProofNiW {
     type Target = RangeProofNi;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for RangeProofNiW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&RangeProofNiSgx> for RangeProofNiW {
    fn from(item: &RangeProofNiSgx) -> Self {
	let ek = EncryptionKeyW::from(&item.ek).inner;
	let range = BigIntW::from(&item.range).inner;
	let ciphertext = BigIntW::from(&item.ciphertext).inner;
	let encrypted_pairs = EncryptedPairsW::from(&item.encrypted_pairs).inner;
	let proof = ProofW::from(&item.proof).inner;
	
	Self { inner: RangeProofNi { ek, range, ciphertext, encrypted_pairs, proof, error_factor: item.error_factor } }
    }
}


pub struct EncryptionKeyW {
    inner: EncryptionKey
}

impl Deref for EncryptionKeyW {
     type Target = EncryptionKey;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for EncryptionKeyW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}


impl From<&EncryptionKeySgx> for EncryptionKeyW {
    fn from(item: &EncryptionKeySgx) -> Self {
	let n = BigIntW::from(&item.n).inner;
	let nn = BigIntW::from(&item.nn).inner;
	Self { inner: EncryptionKey{ n, nn } }
    }
}

pub struct EncryptedPairsW {
    inner: EncryptedPairs
}

impl Deref for EncryptedPairsW {
     type Target = EncryptedPairs;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}


impl DerefMut for EncryptedPairsW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}


impl From<&EncryptedPairsSgx> for EncryptedPairsW {
    fn from(item: &EncryptedPairsSgx) -> Self {

	let mut c1 = Vec::<BigInt>::new();
	let mut c2 = Vec::<BigInt>::new();
	
        for c1_r  in &item.c1 {
            let biw = BigIntW::from(c1_r);
            c1.push(biw.inner);
        }

	for c2_r  in &item.c2 {
            let biw = BigIntW::from(c2_r);
            c2.push(biw.inner);
        }

	Self { inner: EncryptedPairs { c1, c2 } }
	
    }
}

pub struct ProofW {
    inner: Proof
}

impl Deref for ProofW {
     type Target = Proof;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for ProofW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}


impl From<&ProofSgx> for ProofW {
    fn from(item: &ProofSgx) -> Self {
	let mut resp_vec = Vec::<Response>::new();
	for resp in &item.0 {
	    match resp {
		ResponseSgx::Open  { w1, r1, w2, r2 } => {
		    let w1 = BigIntW::from(w1).inner;
		    let r1 = BigIntW::from(r1).inner;
		    let w2 = BigIntW::from(w2).inner;
		    let r2 = BigIntW::from(r2).inner;
		    resp_vec.push(Response::Open{w1,r1,w2,r2});
		},
		ResponseSgx::Mask {j, masked_x, masked_r }  => {
		    let masked_x = BigIntW::from(masked_x).inner;
		    let masked_r = BigIntW::from(masked_r).inner;
		    resp_vec.push(Response::Mask{j: j.to_owned(), masked_x, masked_r});
		}
	    };
	}
	Self{inner: Proof(resp_vec)}
    }
}

struct KeyGenSecondMsgW {
    inner: party_one::KeyGenSecondMsg
}

impl Deref for KeyGenSecondMsgW {
     type Target = party_one::KeyGenSecondMsg;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for KeyGenSecondMsgW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&KeyGenSecondMsgSgx> for KeyGenSecondMsgW {
    fn from(item: &KeyGenSecondMsgSgx) -> Self {
	let comm_witness = CommWitnessW::from(&item.comm_witness).inner;
	Self { inner: party_one::KeyGenSecondMsg { comm_witness } }
    }
}

struct CommWitnessW {
    inner: party_one::CommWitness
}

impl Deref for CommWitnessW {
     type Target = party_one::CommWitness;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for CommWitnessW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&CommWitnessSgx> for CommWitnessW {
    fn from(item: &CommWitnessSgx) -> Self {
	let pk_commitment_blind_factor = BigIntW::from(&item.pk_commitment_blind_factor).inner;
	let zk_pok_blind_factor = BigIntW::from(&item.zk_pok_blind_factor).inner;
	let public_share = GEW::from(&item.public_share).inner;
	let d_log_proof = DLogProofW::from(&item.d_log_proof).inner;

	Self { inner: party_one::CommWitness { pk_commitment_blind_factor, zk_pok_blind_factor, public_share, d_log_proof } }
	
    }
}

struct GEW {
    inner: GE
}

impl Deref for GEW {
     type Target = GE;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for GEW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&GESgx> for GEW {
    fn from(item: &GESgx) -> Self {
	use curv_client::elliptic::curves::traits::ECPoint;

	let ser = &item.get_element().serialize_uncompressed();
	let inner: GE = curv::elliptic::curves::traits::ECPoint::from_bytes(
	    &ser[1..ser.len()]
	).unwrap();
	
	Self { inner }
    }
}

struct GESgxW {
    inner: GESgx
}

impl Deref for GESgxW {
     type Target = GESgx;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for GESgxW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&GE> for GESgxW {
    fn from(item: &GE) -> Self {

	let ser = &item.get_element().serialize_uncompressed();
	let inner: GESgx = curv_client::elliptic::curves::traits::ECPoint::from_bytes(
	    &ser[1..ser.len()]
	).unwrap();


	Self { inner }
    }
}


struct FEW {
    inner: FE
}

impl Deref for FEW {
     type Target = FE;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for FEW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&FESgx> for FEW {
    fn from(item: &FESgx) -> Self {
	use curv_client::elliptic::curves::traits::ECScalar;
	let inner: FE = curv::elliptic::curves::traits::ECScalar::from(
	    &BigIntW::from(&item.to_big_int()).inner
	);
	Self { inner }
    }
}

struct FESgxW {
    inner: FESgx
}

impl Deref for FESgxW {
     type Target = FESgx;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for FESgxW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&FE> for FESgxW {
    fn from(item: &FE) -> Self {
	let inner: FESgx = curv_client::elliptic::curves::traits::ECScalar::from(
	    &BigIntSgxW::from(&item.to_big_int()).inner
	);
	Self { inner }
    }
}

struct ECDDHProofW {
    inner: ECDDHProof
}

impl Deref for ECDDHProofW {
     type Target = ECDDHProof;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for ECDDHProofW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&ECDDHProofSgx> for ECDDHProofW {
    fn from(item: &ECDDHProofSgx) -> Self {
	let a1 = GEW::from(&item.a1).inner;
	let a2 = GEW::from(&item.a2).inner;
	let z = FEW::from(&item.z).inner;
	let inner =  ECDDHProof { a1, a2, z };
	Self { inner }
    }
}


struct ECDDHProofSgxW {
    inner: ECDDHProofSgx
}

impl Deref for ECDDHProofSgxW {
     type Target = ECDDHProofSgx;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for ECDDHProofSgxW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&ECDDHProof> for ECDDHProofSgxW {
    fn from(item: &ECDDHProof) -> Self {
	let a1 = GESgxW::from(&item.a1).inner;
	let a2 = GESgxW::from(&item.a2).inner;
	let z = FESgxW::from(&item.z).inner;
	let inner =  ECDDHProofSgx { a1, a2, z };
	Self { inner }
    }
}

struct DLogProofW {
    inner: DLogProof
}

impl Deref for DLogProofW {
     type Target = DLogProof;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for DLogProofW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&DLogProofSgx> for DLogProofW {
    fn from(item: &DLogProofSgx) -> Self {
	let pk = GEW::from(&item.pk).inner;
	let pk_t_rand_commitment = GEW::from(&item.pk_t_rand_commitment).inner;
	let challenge_response = FEW::from(&item.challenge_response).inner;
	let inner =  DLogProof { pk, pk_t_rand_commitment, challenge_response };
	Self { inner }
    }
}

struct DLogProofSgxW {
    inner: DLogProofSgx
}

impl Deref for DLogProofSgxW {
     type Target = DLogProofSgx;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for DLogProofSgxW {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl From<&DLogProof> for DLogProofSgxW {
    fn from(item: &DLogProof) -> Self {
	let pk = GESgxW::from(&item.pk).inner;
	let pk_t_rand_commitment = GESgxW::from(&item.pk_t_rand_commitment).inner;
	let challenge_response = FESgxW::from(&item.challenge_response).inner;
	let inner =  DLogProofSgx { pk, pk_t_rand_commitment, challenge_response };
	Self { inner }
    }
}

pub struct BigIntW {
    inner: BigInt
}

impl Deref for BigIntW {
    type Target = BigInt;
    fn deref(&self) -> &Self::Target {
     	&self.inner
    }
}

impl DerefMut for BigIntW {
    fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
    }
}

impl From<&BigIntSgx> for BigIntW {
    fn from(item: &BigIntSgx) -> Self {
	let item_vec : Vec::<u8> = item.to_signed_bytes_be();
	let inner : BigInt = From::from(item_vec.as_slice());
	Self { inner }
    }
}


pub struct BigIntSgxW {
    inner: BigIntSgx
}

impl Deref for BigIntSgxW {
    type Target = BigIntSgx;
    fn deref(&self) -> &Self::Target {
     	&self.inner
    }
}

impl DerefMut for BigIntSgxW {
    fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
    }
}

impl From<&BigInt> for BigIntSgxW {
    fn from(item: &BigInt) -> Self {
	
	let item_vec : Vec<u8> = item.into();
	let sign;
	if (item > &BigInt::zero()) {
	    sign = num_bigint_dig::Sign::Plus;
	} else if (item < &BigInt::zero()) {
	    sign = num_bigint_dig::Sign::Minus;
	} else {
	    sign = num_bigint_dig::Sign::NoSign
	};
	let inner = BigIntSgx::from_bytes_be(sign,item_vec.as_slice());
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
	    Ok(v) => Ok(Self{inner:v, ec_key: None}),
	    Err(e) => return Err(LockboxError::Generic(e.to_string()).into()),
	}
    }

    pub fn get_ec_key(&self) -> &Option<ec_key_sealed> {
	&self.ec_key
    }

    pub fn set_ec_key(&mut self, key: Option<ec_key_sealed>) {
	self.ec_key = key;
    }
    
    //  pub fn dh_init_session() -> Result<> {
    //  }

    pub fn test_create_session(&self) -> Result<()> {
	let mut retval = sgx_status_t::SGX_SUCCESS;

	let result = unsafe {
            test_create_session(self.geteid(),
				&mut retval)
    	};

	match result {
            sgx_status_t::SGX_SUCCESS => Ok(()),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", result.as_str())).into())
    	}
    }

    pub fn test_sc_encrypt_unencrypt(&self) -> Result<()> {
	let mut retval = sgx_status_t::SGX_SUCCESS;

	let result = unsafe {
            test_sc_encrypt_unencrypt(self.geteid(),
				      &mut retval)
    	};

	match result {
            sgx_status_t::SGX_SUCCESS => Ok(()),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", result.as_str())).into())
    	}
    }

    pub fn test_encrypt_unencrypt_io(&self) -> Result<()> {
	let mut retval = sgx_status_t::SGX_SUCCESS;
	let mut data_out = [0; 64];

	println!("encrypt to out...");
	let result = unsafe {
            test_encrypt_to_out(self.geteid(),
				&mut retval,
				data_out.as_ptr() as *mut u8)
    	};

	match result {
            sgx_status_t::SGX_SUCCESS => (),
       	    _ => return Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed - test_encrypt_to_out {}!", result.as_str())).into())
    	};

	
	println!("test in to decrypt...");
	let result = unsafe {
            test_in_to_decrypt(self.geteid(),
				&mut retval,
			       data_out.as_ptr() as *const u8,
			       64)
    	};

	match result {
            sgx_status_t::SGX_SUCCESS => Ok(()),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed - test_in_to_decrypt{}!", result.as_str())).into())
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

    
    

    pub fn session_request(&self, id_msg: &EnclaveIDMsg) -> Result<DHMsg1> {
	let mut retval = sgx_status_t::SGX_SUCCESS;
	let mut dh_msg1 = [0u8;1500];

//	let mut session_ptr: usize = 0;
	let src_enclave_id = id_msg.inner;

	println!("enclave trait - doing say something");
	
	let mut input_string = String::from("enclave - session request say something");
     	let result = unsafe {
            say_something(self.geteid(),
			  &mut retval,
			  input_string.as_ptr() as * const u8,
			  input_string.len())
    	};

	println!("enclave trait - finished doing say something");

	match retval {
	    sgx_status_t::SGX_SUCCESS  =>(),
	    _ => return Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed - say something {}!", retval.as_str())).into()),
	};
	
	println!("enclave trait - doing session request");
     	let result = unsafe {
            session_request(self.geteid(),
			    &mut retval,
			    src_enclave_id,
			    dh_msg1.as_mut_ptr() as *mut u8)
		//,
		//	    &mut session_ptr);
    	};
	println!("enclave trait - finished doing session request");

	match retval {
	    sgx_status_t::SGX_SUCCESS  => {
		println!("dh_msg1: {:?}\n", dh_msg1);
		let c = dh_msg1[0].clone();
		let c = &[c];
		let nc_str = std::str::from_utf8(c).unwrap();
		println!("nc_str: {}\n", nc_str);
		let nc = nc_str.parse::<usize>().unwrap();
		let size_str = std::str::from_utf8(&dh_msg1[1..(nc+1)]).unwrap();
		let size = size_str.parse::<usize>().unwrap();
		let msg_str = std::str::from_utf8(&dh_msg1[(nc+1)..(size+nc+1)]).unwrap().to_string();
		let dh_msg1 : DHMsg1  = serde_json::from_str(&msg_str).unwrap();
		Ok(dh_msg1)
	    },
	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed -  session_request {}!", retval.as_str())).into()),
	}
    }

    pub fn exchange_report(&self, ep_msg: &shared_lib::structs::ExchangeReportMsg) -> Result<DHMsg3> {
	let mut retval = sgx_status_t::SGX_SUCCESS;


	let mut dh_msg3_arr = [0u8;1500];
//	let mut session_ptr: usize = ep_msg.session_ptr;
	let src_enclave_id = ep_msg.src_enclave_id;
	let dh_msg2_str = serde_json::to_string(&ep_msg.dh_msg2).unwrap();

     	let result = unsafe {
            exchange_report(self.geteid(),
			    &mut retval,
			    src_enclave_id,
			    dh_msg2_str.as_ptr() as * const u8,
			    dh_msg2_str.len(),
			    dh_msg3_arr.as_mut_ptr() as *mut u8)
		//,
		//	    &mut session_ptr);
    	};

	match retval {
	    sgx_status_t::SGX_SUCCESS  => {
		let c = dh_msg3_arr[0].clone();
		let c = &[c];
		let nc_str = std::str::from_utf8(c).unwrap();
		let nc = nc_str.parse::<usize>().unwrap();
		let size_str = std::str::from_utf8(&dh_msg3_arr[1..(nc+1)]).unwrap();
		let size = size_str.parse::<usize>().unwrap();
		let msg_str = std::str::from_utf8(&dh_msg3_arr[(nc+1)..(size+nc+1)]).unwrap().to_string();
		let dh_msg3 : DHMsg3  = serde_json::from_str(&msg_str).unwrap();
		Ok(dh_msg3)
	    },
	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", retval.as_str())).into()),
	}
    }
    
    pub fn proc_msg1(&self, dh_msg1: &DHMsg1) -> Result<DHMsg2> {
	let mut retval = sgx_status_t::SGX_SUCCESS;


	let mut dh_msg2_arr = [0u8;1700];
	let dh_msg1_str = serde_json::to_string(dh_msg1).unwrap();

     	let result = unsafe {
            proc_msg1(self.geteid(),
		      &mut retval,
		      dh_msg1_str.as_ptr() as * const u8,
		      dh_msg1_str.len(),
		      dh_msg2_arr.as_mut_ptr() as *mut u8);
    	};

	match retval {
	    sgx_status_t::SGX_SUCCESS  => {
		let c = dh_msg2_arr[0].clone();
		let c = &[c];
		let nc_str = std::str::from_utf8(c).unwrap();
		let nc = nc_str.parse::<usize>().unwrap();
		let size_str = std::str::from_utf8(&dh_msg2_arr[1..(nc+1)]).unwrap();
		let size = size_str.parse::<usize>().unwrap();
		let msg_str = std::str::from_utf8(&dh_msg2_arr[(nc+1)..(size+nc+1)]).unwrap().to_string();
		let dh_msg2 : DHMsg2  = serde_json::from_str(&msg_str).unwrap();
		Ok(dh_msg2)
	    },
	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", retval.as_str())).into()),
	}
    }

    pub fn proc_msg3(&self, dh_msg3: &DHMsg3) -> Result<ec_key_sealed> {
	let mut sealed_log = [0; EC_KEY_SEALED_SIZE];
	let mut retval = sgx_status_t::SGX_SUCCESS;

	let dh_msg3_str = serde_json::to_string(dh_msg3).unwrap();

     	let result = unsafe {
            proc_msg3(self.geteid(),
		      &mut retval,
		      dh_msg3_str.as_ptr() as * const u8,
		      dh_msg3_str.len(),
		      sealed_log.as_ptr() as * mut u8)
    	};

	match retval {
	    sgx_status_t::SGX_SUCCESS  => Ok(sealed_log),
	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", retval.as_str())).into()),
	}
    }
    
    pub fn get_self_report(&self) -> Result<sgx_report_t> {
     	let mut retval = sgx_status_t::SGX_SUCCESS;
	let mut ret_report: sgx_report_t = sgx_report_t::default();
	
     	let result = unsafe {
            get_self_report(self.geteid(),
			    &mut retval,
			    &mut ret_report as *mut sgx_report_t)
    	};
	
    	match result {
            sgx_status_t::SGX_SUCCESS => Ok(ret_report),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", result.as_str())).into())
    	}
    }
    
    pub fn get_random_sealed_log(&self) -> Result<[u8; 8192]> {
     	let sealed_log = [0; 8192];
	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	
	let _result = unsafe {
	    create_sealed_random_bytes32(self.geteid(), &mut enclave_ret, sealed_log.as_ptr() as * mut u8, 8192);
	};
	
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok(sealed_log),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }

    pub fn verify_sealed_log(&self, sealed_log: [u8; 8192]) -> Result<()> {
     	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	
	let _result = unsafe {
	    verify_sealed_bytes32(self.geteid(), &mut enclave_ret, sealed_log.as_ptr() as * mut u8, 8192);
	};
	
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok(()),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }

    pub fn set_ec_key_enclave(&self, sealed_log: ec_key_sealed) -> Result<()> {
	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	
	let _result = unsafe {
	    set_ec_key(self.geteid(), &mut enclave_ret, sealed_log.as_ptr() as * mut u8, 8192);
	};
	
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok(()),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }

    pub fn get_random_sealed_fe_log(&self) -> Result<[u8; 8192]> {
     	let sealed_log = [0; 8192];
	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	
	let _result = unsafe {
	    create_sealed_random_fe(self.geteid(), &mut enclave_ret, sealed_log.as_ptr() as * mut u8, 8192);
	};
	
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok(sealed_log),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }

    pub fn get_random_ec_fe_log(&self) -> Result<[u8; 8192]> {
	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	let mut ec_log = [0u8; 8192];
	
	let _result = unsafe {
	    create_ec_random_fe(self.geteid(), &mut enclave_ret, ec_log.as_mut_ptr() as * mut u8);
	};
	
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok(ec_log),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }

    pub fn verify_sealed_fe_log(&self, sealed_log: [u8; 8192]) -> Result<()> {
     	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	
	let _result = unsafe {
	    verify_sealed_fe(self.geteid(), &mut enclave_ret, sealed_log.as_ptr() as * mut u8, 8192);
	};
	
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok(()),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }

    pub fn verify_ec_fe_log(&self, ec_log: ec_log) -> Result<()> {
     	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	
	let _result = unsafe {
	    verify_ec_fe(self.geteid(), &mut enclave_ret, ec_log.as_ptr() as * mut u8);
	};
	
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok(()),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }
    
    pub fn calc_sha256(&self, input_string: String) -> Result<[u8; 32]>{
	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	let hash = [0u8;32];
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
		let msg_str = std::str::from_utf8(&plain_ret[(nc+1)..(size+nc+1)]).unwrap().to_string();
		let kg1m_sgx : KeyGenFirstMsgSgx  = serde_json::from_str(&msg_str).unwrap();
		let kg1m : party_one::KeyGenFirstMsg = KeyGenFirstMsgW::from(&kg1m_sgx).inner;
		//let kg1m = party_one::KeyGenFirstMsg{ pk_commitment: kg1m_loc.pk_commitment, zk_pok_commitment: kg1m_loc.zk_pok_commitment };
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
		let msg_str = std::str::from_utf8(&plain_ret[(nc+1)..(size+nc+1)]).unwrap().to_string();
		let kg1m_sgx : KeyGenFirstMsgSgx  = serde_json::from_str(&msg_str).unwrap();
		let kg1m : party_one::KeyGenFirstMsg = KeyGenFirstMsgW::from(&kg1m_sgx).inner;
//		let kg1m =
		    //party_one::KeyGenFirstMsg{ pk_commitment: kg1m_loc.pk_commitment, zk_pok_commitment: kg1m_loc.zk_pok_commitment };
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

	let key_gen_msg2_sgx = &KeyGenMsg2SgxW::from(key_gen_msg_2).inner;
	let msg_2_str = serde_json::to_string(key_gen_msg2_sgx).unwrap();
	
	let _result = unsafe{
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
		let msg_str = std::str::from_utf8(&plain_ret[(nc+1)..(size+nc+1)]).unwrap().to_string();
		let kgm2_sgx : KeyGenParty1Message2Sgx  = serde_json::from_str(&msg_str).unwrap();
		let kgm2 : party1::KeyGenParty1Message2 = KeyGenParty1Message2W::from(&kgm2_sgx).inner;
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

	let sign_msg1_sgx = SignMsg1SgxW::from(sign_msg1).inner;
	
	
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
		let msg_str = std::str::from_utf8(&plain_ret[(nc+1)..(size+nc+1)]).unwrap().to_string();
		let ekg1m_sgx : EphKeyGenFirstMsgSgx  = serde_json::from_str(&msg_str).unwrap();
		let ekg1m : party_one::EphKeyGenFirstMsg = party_one_enc::EphKeyGenFirstMsgW::from(&ekg1m_sgx).inner;
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

	let sign_msg2_sgx = SignMsg2SgxW::from(sign_msg2).inner;
	let sign_msg2_str = serde_json::to_string(&sign_msg2_sgx).unwrap();

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
		let c = plain_ret[0].clone();
		let c = &[c];
		let nc_str = std::str::from_utf8(c).unwrap();
		let nc = nc_str.parse::<usize>().unwrap();
		let size_str = std::str::from_utf8(&plain_ret[1..(nc+1)]).unwrap();
		let size = size_str.parse::<usize>().unwrap();
		let msg_str = std::str::from_utf8(&plain_ret[(nc+1)..(size+nc+1)]).unwrap().to_string();
		let output : SignSecondOut  = serde_json::from_str(&msg_str).unwrap();
		Ok((output.inner, sealed_log_out))
	    },
	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into()),
	}	
	
    }


    pub fn keyupdate_first(&self, sealed_log_in: &mut [u8; 8192], receiver_msg: &KUSendMsg)
	-> Result<(KUReceiveMsg, [u8;8192])> {
	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	let mut sealed_log_out = [0u8; 8192];
	let mut plain_ret = [0u8;8192];

	let receiver_msg_sgx = KUSendMsgSgxW::from(receiver_msg).inner;
		
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
		let msg_str = std::str::from_utf8(&plain_ret[(nc+1)..(size+nc+1)]).unwrap().to_string();
		let ku_receive_msg_sgx : KUReceiveMsgSgx  = serde_json::from_str(&msg_str).unwrap();
		let ku_receive_msg : KUReceiveMsg = KUReceiveMsgW::from(&ku_receive_msg_sgx).inner;
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
    fn test_sc_encrypt_unencrypt(eid: sgx_enclave_id_t, retval: *mut sgx_status_t)
				 -> sgx_status_t;

    fn test_encrypt_to_out(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
			   encrypt_out: * mut u8)
				     -> sgx_status_t;

    fn test_in_to_decrypt(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
			  data_in: *const u8, data_len: usize)
			   -> sgx_status_t;
    
    fn test_create_session(eid: sgx_enclave_id_t, retval: *mut sgx_status_t)
			   -> sgx_status_t;

    fn init_session(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
    		    p_report: *mut sgx_report_t)
			   -> sgx_status_t;
    
    fn say_something(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     some_string: *const u8, len: usize) -> sgx_status_t;

    fn get_self_report(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		       p_report: *mut sgx_report_t) -> sgx_status_t;

    fn create_sealed_random_bytes32(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
            sealed_log: * mut u8, sealed_log_size: u32 );

    fn verify_sealed_bytes32(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
			     sealed_log: * mut u8, sealed_log_size: u32);

    fn set_ec_key(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
			     sealed_log: * mut u8, sealed_log_size: u32);

    fn create_sealed_random_fe(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
            sealed_log: * mut u8, sealed_log_size: u32 );

    fn verify_sealed_fe(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
			sealed_log: * mut u8, sealed_log_size: u32);

    fn create_ec_random_fe(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
            ec_log: * mut u8);

    fn verify_ec_fe(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
				ec_log: * mut u8);

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


    fn session_request(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
    		       src_enclave_id: sgx_enclave_id_t,
    		       dh_msg1: *mut u8);
    //,
    //		       session_pointer: *mut usize);

    fn exchange_report(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		       src_enclave_id: sgx_enclave_id_t, dh_msg2: *const u8,
		       msg2_len: size_t,
		       dh_msg3: *mut u8);
    //,
//		       session_ptr: *mut usize);

    fn proc_msg1(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		 dh_msg1: *const u8,
		 msg1_len: size_t,
		 dh_msg2: *mut u8);

    fn proc_msg3(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		 dh_msg3: *const u8,
		 msg3_len: size_t,
		 sealed_log: *mut u8);

    
//    public uint32_t end_session(sgx_enclave_id_t src_enclave_id, [user_check]size_t* session_ptr);
}

#[cfg(test)]
mod tests {
    use super::*;
    use bitcoin::secp256k1::Secp256k1;

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
    fn test_self_report() {
	let enc = Enclave::new().unwrap();
	let _report = enc.get_self_report().unwrap();
	enc.destroy();
    }

    #[test]
    fn test_get_random_sealed_log() {
       let enc = Enclave::new().unwrap();
       let _rsd = enc.get_random_sealed_log().unwrap();
       enc.destroy();
    }

    #[test]
    fn test_verify_sealed_log() {
       let enc = Enclave::new().unwrap();
       let rsd = enc.get_random_sealed_log().unwrap();
       enc.verify_sealed_log(rsd).unwrap();
       enc.destroy();
    }

    #[test]
    fn test_get_random_sealed_fe_log() {
       let enc = Enclave::new().unwrap();
       let _rsd = enc.get_random_sealed_fe_log().unwrap();
       enc.destroy();
    }

    #[test]
    fn test_verify_sealed_fe_log() {
       let enc = Enclave::new().unwrap();
       let rsd = enc.get_random_sealed_fe_log().unwrap();
       enc.verify_sealed_fe_log(rsd).unwrap();
       enc.destroy();
    }

    #[test]
    fn test_get_random_ec_fe_log() {
       let enc = Enclave::new().unwrap();
       let _rsd = enc.get_random_ec_fe_log().unwrap();
       enc.destroy();
    }

    #[test]
    fn test_verify_ec_fe_log() {
       let enc = Enclave::new().unwrap();
       let rsd = enc.get_random_ec_fe_log().unwrap();
       enc.verify_ec_fe_log(rsd).unwrap();
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
	let rsd1 = enc.get_random_sealed_log().unwrap();
	let rsd2 = enc.get_random_sealed_log().unwrap();

	let _rsd = enc.sk_tweak_add_assign(rsd1, rsd2).unwrap();

	enc.destroy();
    }

    #[test]
    fn test_sk_tweak_mul_assign() {
	let enc = Enclave::new().unwrap();
	let rsd1 = enc.get_random_sealed_log().unwrap();
	let rsd2 = enc.get_random_sealed_log().unwrap();

	let _rsd = enc.sk_tweak_mul_assign(rsd1, rsd2).unwrap();
	
	enc.destroy();
    }

    #[test]
    fn test_sign_verify() {
	let enc = Enclave::new().unwrap();
	let rsd1 = enc.get_random_sealed_log().unwrap();
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
	let mut rsd1 = enc.get_random_sealed_fe_log().unwrap();
	enc.verify_sealed_fe_log(rsd1).unwrap();
	let (_kg1m, _sealed_log_out) = enc.first_message(&mut rsd1).unwrap();
    }

    #[test]
    fn test_second_message() {
	let enc = Enclave::new().unwrap();
	let mut rsd1 = enc.get_random_sealed_fe_log().unwrap();
	enc.verify_sealed_fe_log(rsd1).unwrap();
	let (_kg1m, mut sealed_log_out) = enc.first_message(&mut rsd1).unwrap();

	let wallet_secret_key: FE = ECScalar::new_random();
	
	let (kg_party_two_first_message, _kg_ec_key_pair_party2) =
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
	
	let n1 : u64 = 123;
	let n2 : u64 = 456;
	
	let nbi1 : BigIntSgx = From::from(n1);
	let nbi2 : BigIntSgx = From::from(n2);
	let nbis = nbi1 + nbi2;
	
	let wbi1 = BigIntW { inner: From::from(n1) };
	let wbi2 = BigIntW { inner: From::from(n2) };
	let wbis : BigIntW  = From::from(&nbis);
	let wbis2 = BigIntW { inner: wbi1.deref() + wbi2.deref() };

	assert!(wbis.deref() == wbis2.deref(), format!("{:?} does not equal {:?}", wbis.deref(), wbis2.deref()));
	
    }

    #[test]
    fn test_convert_bigint_sgx() {
	
	let n1 : u64 = 123;
	let n2 : u64 = 456;
	
	let nbi1 : BigInt = From::from(n1);
	let nbi2 : BigInt = From::from(n2);
	let nbis = nbi1 + nbi2;

	
	let wbi1 = BigIntSgxW { inner: From::from(n1) };
	let wbi2 = BigIntSgxW { inner: From::from(n2) };
	let wbis : BigIntSgxW  = From::from(&nbis);
	let wbis2 = BigIntSgxW { inner: wbi1.deref() + wbi2.deref() };

	assert!(wbis.deref() == wbis2.deref(), format!("{:?} does not equal {:?}", wbis.deref(), wbis2.deref()));
    }

    #[test]
    fn test_convert_negative_bigint_sgx() {
	
	let n1 : i64 = 123;
	let n2 : i64 = -456;
	let ns = n1 + n2;
	
	
	let wbi1 = BigIntSgxW { inner: From::from(n1) };
	let wbi2 = BigIntSgxW { inner: From::from(n2) };
	let wbis : BigIntSgx  = From::from(ns);
	let wbis2 = BigIntSgxW { inner: wbi1.deref() + wbi2.deref() };

	assert!(&wbis == wbis2.deref(), format!("{:?} does not equal {:?}", &wbis, wbis2.deref()));
    }

    use curv::elliptic::curves::traits::ECPoint as ECPointSgx;
    
    #[test]
    fn test_convert_ge() {
	let ge1: GE = GE::generator() * FE::new_random();
	let ge2: GE = GE::generator() * FE::new_random();
	let s1 = ge1 + ge2;
	
	let ge1_sgx = GESgxW::from(&ge1).inner;
	let ge2_sgx = GESgxW::from(&ge2).inner;
	let s1_sgx = ge1_sgx + ge2_sgx;

	let ge1_2 = GEW::from(&ge1_sgx).inner;
	let ge2_2 = GEW::from(&ge2_sgx).inner;
	let s1_2 = GEW::from(&s1_sgx).inner;


	assert_eq!(ge1.get_element(), ge1_2.get_element());
	assert_eq!(ge2.get_element(), ge2_2.get_element());
	assert_eq!(s1.get_element(), s1_2.get_element());
    }

    #[test]
    fn test_sign() {
	
	let enc = Enclave::new().unwrap();
	let mut rsd1 = enc.get_random_sealed_fe_log().unwrap();
	enc.verify_sealed_fe_log(rsd1).unwrap();



	let (kg_party_one_first_message, mut sealed_log_out) = enc.first_message(&mut rsd1).unwrap();

	let wallet_secret_key: FE = ECScalar::new_random();

	let (kg_party_two_first_message, kg_ec_key_pair_party2) =
	    MasterKey2::key_gen_first_message_predefined(&wallet_secret_key);

	let shared_key_id = Uuid::new_v4();

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

	
	let (ekg1m, mut sign_first_sealed) = enc.sign_first(&mut sealed_log_2, &sign_msg1).unwrap().unwrap();
	

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
	

        let (_return_msg, _return_sealed) = enc.sign_second(&mut sign_first_sealed, &sign_msg2).unwrap();
	
    }

/*
    #[test]
    fn test_session_request() {
	let enc = Enclave::new().unwrap();
	let id_msg = EnclaveIDMsg{ inner: enc.geteid() };
	enc.session_request(&id_msg).unwrap();
    }

    #[test]
    fn test_test_create_session() {
	let enc = Enclave::new().unwrap();
	enc.test_create_session().unwrap();
    }
     */

    #[test]
    fn test_sc_encrypt_unencrypt() {
	let enc = Enclave::new().unwrap();
	enc.test_sc_encrypt_unencrypt().unwrap();
    }

    #[test]
    fn test_encrypt_unencrypt_io() {
	let enc = Enclave::new().unwrap();
	enc.test_encrypt_unencrypt_io().unwrap();
    }
}



