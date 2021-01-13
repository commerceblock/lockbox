// Licensed to the Apache Software Foundation secretkey(ASF) under only
// more contributor license agreements.  See the NOTICE file
// distributed with this work for additional information
// regarding copyright ownership.  The ASF licenses this file
// to you under the Apache License, Version 2.0 (the
// "License"); you may not use this file except in compliance
// with the License.  You may obtain a copy of the License at
//
//   http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing,
// software distributed under the License is distributed on an
// "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
// KIND, either express or implied.  See the License for the
// specific language governing permissions and limitations
// under the License..

#![crate_name = "lockbox_enclave"]
#![crate_type = "staticlib"]

#![cfg_attr(not(target_env = "sgx"), no_std)]
#![cfg_attr(target_env = "sgx", feature(rustc_private))]

extern crate sgx_types;
extern crate sgx_tseal;
extern crate sgx_tcrypto;
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;
extern crate libsecp256k1 as libsecp256k1;
extern crate secp256k1_sgx as secp256k1;
extern crate curv;
extern crate zeroize;
extern crate num_integer as integer;
extern crate num_traits;
extern crate uuid;
extern crate paillier;
extern crate zk_paillier;
//extern crate shared_lib;
//use shared_lib::structs::*;

use secp256k1::{Secp256k1, VerifyOnly};
use secp256k1::key::{SecretKey, PublicKey};
use sgx_types::*;
use sgx_tcrypto::*;  
use std::string::String;
use sgx_types::marker::ContiguousMemory;
use std::vec::Vec;
use std::io::{self, Write};
use std::slice;
use std::convert::{TryFrom, TryInto};
use sgx_rand::{Rng, StdRng};
use sgx_tseal::{SgxSealedData};
use std::ops::{Deref, DerefMut};
use std::default::Default;
use curv::{BigInt, FE, GE, PK};
use curv::elliptic::curves::traits::{ECScalar, ECPoint};
use curv::elliptic::curves::secp256_k1::{SK, get_context_all};
use curv::arithmetic_sgx::traits::{Samplable, Converter};
use curv::cryptographic_primitives_sgx::proofs::sigma_ec_ddh::*;
use curv::cryptographic_primitives_sgx::proofs::sigma_dlog::*;
use curv::cryptographic_primitives_sgx::proofs::ProofError;
use curv::cryptographic_primitives_sgx::hashing::{hash_sha256::HSha256, traits::Hash};
use curv::cryptographic_primitives_sgx::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives_sgx::commitments::traits::Commitment;
use curv::cryptographic_primitives_sgx::twoparty::dh_key_exchange::EcKeyPair;
use curv::elliptic::curves::traits::*;
use curv::arithmetic_sgx::traits::*;
use zeroize::Zeroize;
use integer::Integer;
use uuid::Uuid;
use paillier::{Paillier, Randomness, RawPlaintext, KeyGeneration,
	       EncryptWithChosenRandomness, DecryptionKey, EncryptionKey};
use zk_paillier::zkproofs::{NICorrectKeyProof, RangeProofNi, CompositeDLogProof, DLogStatement};
use num_traits::{One, Pow};


#[macro_use]
extern crate serde_derive;
extern crate serde_cbor;

const SECURITY_BITS: usize = 256;

// A sample struct to show the usage of serde + seal
// This struct could not be used in sgx_seal directly because it is
// **not** continuous in memory. The `vec` is the bad member.
// However, it is serializable. So we can serialize it first and
// put convert the Vec<u8> to [u8] then put [u8] to sgx_seal API!
#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct RandDataSerializable {
    key: u32,
    rand: [u8; 16],
    vec: Vec<u8>,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyGenMsg2 {
    pub shared_key_id: Uuid,
    pub dlog_proof: DLogProof,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct CommWitness {
    pub pk_commitment_blind_factor: BigInt,
    pub zk_pok_blind_factor: BigInt,
    pub public_share: GE,
    pub d_log_proof: DLogProof,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenSecondMsg {
    pub comm_witness: CommWitness,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EphEcKeyPair {
    pub public_share: GE,
    secret_share: FE,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct EphKeyGenFirstMsg {
    pub d_log_proof: ECDDHProof,
    pub public_share: GE,
    pub c: GE, //c = secret_share * base_point2                                                                                                                                                                                                                                          
}

#[derive(Serialize, Deserialize, Clone, Default, Debug, PartialEq)]
struct Bytes32{
    inner: [u8; 32]
}

impl TryFrom<(* mut u8, u32)> for Bytes32 {
    type Error = sgx_status_t;
    fn try_from(item: (* mut u8, u32)) -> Result<Self, Self::Error> {
	let opt = from_sealed_log_for_slice::<u8>(item.0, item.1);
	let sealed_data = match opt {
            Some(x) => x,
            None => {
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
            },
	};
	let unsealed_data = SgxSealable::try_from_sealed(&sealed_data)?;
	Self::try_from(unsealed_data)
    }
}

impl From<* const u8> for Bytes32 {
    fn from(item: * const u8) -> Self {
	let inner_slice = unsafe { slice::from_raw_parts(item, 32) };
	let inner: [u8;32] = inner_slice.try_into().unwrap();
	Self{inner}
    }
}


impl Deref for Bytes32 {
     type Target = [u8; 32];
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for Bytes32 {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

impl Bytes32 {
    fn new_random() -> SgxResult<Bytes32> {
	let mut rand = match StdRng::new() {
            Ok(rng) => rng,
            Err(_) => { return Err(sgx_status_t::SGX_ERROR_UNEXPECTED); },
	};
	let mut key = [0u8; 32];
	rand.fill_bytes(&mut key);
	Ok(Self{inner: key})
    }
}

//#[derive(Serialize, Deserialize, Clone, Default, Debug)]
//struct Serializable32([u8; 32])

#[derive(Clone, Debug, Default)]
pub struct SgxSealable {
    inner: Vec<u8>
}

impl SgxSealable {
    fn to_sealed(&self) -> SgxResult<SgxSealedData<[u8]>> {
	let aad: [u8; 0] = [0_u8; 0];
	SgxSealedData::<[u8]>::seal_data(&aad, self.deref().as_slice())
    }

    fn try_from_sealed(sd: &SgxSealedData<[u8]>) -> SgxResult<Self> {
	sd.unseal_data().map(|x|Self{inner: x.get_decrypt_txt().to_vec()})
    }

    #[inline]
    pub const fn size() -> usize {
	8192
    }
}

impl Deref for SgxSealable {
     type Target = Vec<u8>;
     fn deref(&self) -> &Self::Target {
     	&self.inner
     }
}

impl DerefMut for SgxSealable {
     fn deref_mut(&mut self) -> &mut Self::Target {
     	&mut self.inner
     }
}

#[derive(Clone, Debug)]
pub struct SgxSealedLog {
    inner: [u8; Self::size()]
}

impl SgxSealedLog{
    #[inline]
    pub const fn size() -> usize {
	8192
    }
}

impl Default for SgxSealedLog {
    fn default() -> Self {
	Self{inner: [0;Self::size()]}
    }
}

impl Deref for SgxSealedLog {
    type Target = [u8; Self::size()];
     fn deref(&self) -> &Self::Target {
        &self.inner
     }
}

impl DerefMut for SgxSealedLog {
     fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
     }
}


impl TryFrom<SgxSealable> for SgxSealedLog {
    type Error = sgx_status_t;
    fn try_from(item: SgxSealable) -> Result<Self, Self::Error> {
	println!("Sealing data");
	let sealed_data = match item.to_sealed(){
	    Ok(v) => v,
	    Err(e) => return Err(e)
	};
	let mut sealed_log  = Self::default();

	println!("To sealed log");
	let opt = to_sealed_log_for_slice(&sealed_data, (*sealed_log).as_mut_ptr(), Self::size() as u32);
	if opt.is_none() {
            return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
	}
	println!("Got sealed log");
	Ok(sealed_log)
    }
}

impl TryFrom<RandDataSerializable> for SgxSealable {
    type Error = sgx_status_t;
    fn try_from(item: RandDataSerializable) -> Result<Self, Self::Error> {
	let encoded_vec = match serde_cbor::to_vec(&item){
	    Ok(v) => v,
	    Err(e) => {
		println!("error: {:?}",e);
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)

	    }
	};
	let res = Self{inner: encoded_vec};
	Ok(res)
    }
}

impl TryFrom<SgxSealable> for RandDataSerializable {
    type Error = sgx_status_t;
    fn try_from(item: SgxSealable) -> Result<Self, Self::Error> {

	match serde_cbor::from_slice(&item){
	    Ok(v) => Ok(v),
	    Err(_e) => {
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
	    }
	}
    }
}


impl TryFrom<Bytes32> for SgxSealable {
    type Error = sgx_status_t;
    fn try_from(item: Bytes32) -> Result<Self, Self::Error> {
	let encoded_vec = match serde_cbor::to_vec(&item){
	    Ok(v) => v,
	    Err(e) => {
		println!("error: {:?}",e);
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)

	    }
	};
	let res = Self{ inner: encoded_vec };
	Ok(res)
    }
}

impl TryFrom<SgxSealable> for Bytes32 {
    type Error = sgx_status_t;
    fn try_from(item: SgxSealable) -> Result<Self, Self::Error> {
	match serde_cbor::from_slice(&item){
	    Ok(v) => Ok(v),
	    Err(_e) => {
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
	    }
	}
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Party1Private {
    x1: FE,
    paillier_priv: DecryptionKey,
    c_key_randomness: BigInt,
}

#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
pub struct KeyGenFirstMsg{
    pk_commitment: BigInt,
    zk_pok_commitment: BigInt,
}

impl KeyGenFirstMsg {
    pub fn create_commitments() -> (KeyGenFirstMsg, CommWitness, EcKeyPair) {
        let base: GE = ECPoint::generator();

        let mut secret_share: FE = ECScalar::new_random();

        let public_share = base.scalar_mul(&secret_share.get_element());

	let d_log_proof = DLogProof::prove(&secret_share);
        // we use hash based commitment                                                                                                                                                                                                                                                  
        let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
        let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &public_share.bytes_compressed_to_big_int(),
            &pk_commitment_blind_factor,
        );

	let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
        let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
            &d_log_proof
                .pk_t_rand_commitment
                .bytes_compressed_to_big_int(),
            &zk_pok_blind_factor,
	);
        let ec_key_pair = EcKeyPair {
            public_share,
            secret_share,
        };
        secret_share.zeroize();
        (
            KeyGenFirstMsg {
                pk_commitment,
                zk_pok_commitment,
            },
            CommWitness {
                pk_commitment_blind_factor,
                zk_pok_blind_factor,
                public_share: ec_key_pair.public_share,
                d_log_proof,
            },
            ec_key_pair,
        )
    }
}


impl TryFrom<KeyGenFirstMsg> for SgxSealable {
    type Error = sgx_status_t;
    fn try_from(item: KeyGenFirstMsg) -> Result<Self, Self::Error> {
        let encoded_vec = match serde_cbor::to_vec(&item){
            Ok(v) => v,
            Err(e) => {
                println!("error: {:?}",e);
                return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)

            }
        };
        let res = Self{inner: encoded_vec};
        Ok(res)
    }
}

impl TryFrom<SgxSealable> for KeyGenFirstMsg {
    type Error = sgx_status_t;
    fn try_from(item: SgxSealable) -> Result<Self, Self::Error> {

        match serde_cbor::from_slice(&item){
            Ok(v) => Ok(v),
            Err(_e) => {
                return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
            }
        }
    }
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct FirstMessageSealed {
    comm_witness: CommWitness,
    ec_key_pair: EcKeyPair,
}

impl TryFrom<(* mut u8, u32)> for FirstMessageSealed {
    type Error = sgx_status_t;
    fn try_from(item: (* mut u8, u32)) -> Result<Self, Self::Error> {
	let opt = from_sealed_log_for_slice::<u8>(item.0, item.1);
	let sealed_data = match opt {
            Some(x) => x,
            None => {
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
            },
	};
	let unsealed_data = SgxSealable::try_from_sealed(&sealed_data)?;
	Self::try_from(unsealed_data)
    }
}

impl TryFrom<FirstMessageSealed> for SgxSealable {
    type Error = sgx_status_t;
    fn try_from(item: FirstMessageSealed) -> Result<Self, Self::Error> {
        let encoded_vec = match serde_cbor::to_vec(&item){
            Ok(v) => v,
            Err(e) => {
                println!("error: {:?}",e);
                return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)

            }
        };
        let res = Self{inner: encoded_vec};
        Ok(res)
    }
}

impl TryFrom<SgxSealable> for FirstMessageSealed {
    type Error = sgx_status_t;
    fn try_from(item: SgxSealable) -> Result<Self, Self::Error> {

        match serde_cbor::from_slice(&item){
            Ok(v) => Ok(v),
            Err(_e) => {
                return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
            }
        }
    }
}

#[derive(Serialize, Deserialize)]
pub struct SecondMessageSealed {
    paillier_key_pair: PaillierKeyPair,
    party_one_private: Party1Private,
    master_key: MasterKey1,
}

impl TryFrom<(* mut u8, u32)> for SecondMessageSealed {
    type Error = sgx_status_t;
    fn try_from(item: (* mut u8, u32)) -> Result<Self, Self::Error> {
	let opt = from_sealed_log_for_slice::<u8>(item.0, item.1);
	let sealed_data = match opt {
            Some(x) => x,
            None => {
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
            },
	};
	let unsealed_data = SgxSealable::try_from_sealed(&sealed_data)?;
	Self::try_from(unsealed_data)
    }
}

impl TryFrom<SecondMessageSealed> for SgxSealable {
    type Error = sgx_status_t;
    fn try_from(item: SecondMessageSealed) -> Result<Self, Self::Error> {
        let encoded_vec = match serde_cbor::to_vec(&item){
            Ok(v) => v,
            Err(e) => {
                println!("error: {:?}",e);
                return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)

            }
        };
        let res = Self{inner: encoded_vec};
        Ok(res)
    }
}

impl TryFrom<SgxSealable> for SecondMessageSealed {
    type Error = sgx_status_t;
    fn try_from(item: SgxSealable) -> Result<Self, Self::Error> {

        match serde_cbor::from_slice(&item){
            Ok(v) => Ok(v),
            Err(_e) => {
                return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
            }
        }
    }
}


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignFirstSealed {
    ec_key_pair: EphEcKeyPair
}

impl TryFrom<(* mut u8, u32)> for SignFirstSealed {
    type Error = sgx_status_t;
    fn try_from(item: (* mut u8, u32)) -> Result<Self, Self::Error> {
	let opt = from_sealed_log_for_slice::<u8>(item.0, item.1);
	let sealed_data = match opt {
            Some(x) => x,
            None => {
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
            },
	};
	let unsealed_data = SgxSealable::try_from_sealed(&sealed_data)?;
	Self::try_from(unsealed_data)
    }
}

impl TryFrom<SignFirstSealed> for SgxSealable {
    type Error = sgx_status_t;
    fn try_from(item: SignFirstSealed) -> Result<Self, Self::Error> {
        let encoded_vec = match serde_cbor::to_vec(&item){
            Ok(v) => v,
            Err(e) => {
                println!("error: {:?}",e);
                return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)

            }
        };
        let res = Self{inner: encoded_vec};
        Ok(res)
    }
}

impl TryFrom<SgxSealable> for SignFirstSealed {
    type Error = sgx_status_t;
    fn try_from(item: SgxSealable) -> Result<Self, Self::Error> {

        match serde_cbor::from_slice(&item){
            Ok(v) => Ok(v),
            Err(_e) => {
                return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
            }
        }
    }
}


/*
#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct SignSecondSealed {
    sign_second_input: ECDSASignSecondInput,
    ec_key_pair: EphEcKeyPair,
}

impl TryFrom<(* mut u8, u32)> for SignSecondSealed {
    type Error = sgx_status_t;
    fn try_from(item: (* mut u8, u32)) -> Result<Self, Self::Error> {
	let opt = from_sealed_log_for_slice::<u8>(item.0, item.1);
	let sealed_data = match opt {
            Some(x) => x,
            None => {
		return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
            },
	};
	let unsealed_data = SgxSealable::try_from_sealed(&sealed_data)?;
	Self::try_from(unsealed_data)
    }
}

impl TryFrom<SignSecondSealed> for SgxSealable {
    type Error = sgx_status_t;
    fn try_from(item: SignSecondSealed) -> Result<Self, Self::Error> {
        let encoded_vec = match serde_cbor::to_vec(&item){
            Ok(v) => v,
            Err(e) => {
                println!("error: {:?}",e);
                return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)

            }
        };
        let res = Self{inner: encoded_vec};
        Ok(res)
    }
}

impl TryFrom<SgxSealable> for SignSecondSealed {
    type Error = sgx_status_t;
    fn try_from(item: SgxSealable) -> Result<Self, Self::Error> {

        match serde_cbor::from_slice(&item){
            Ok(v) => Ok(v),
            Err(_e) => {
                return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
            }
        }
    }
}*/


#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct PaillierKeyPair {
    pub ek: EncryptionKey,
    dk: DecryptionKey,
    pub encrypted_share: BigInt,
    randomness: BigInt,
}

impl PaillierKeyPair {
    pub fn pdl_proof(
        party1_private: &Party1Private,
	paillier_key_pair: &PaillierKeyPair,
    ) -> (PDLwSlackStatement, PDLwSlackProof, CompositeDLogProof) {
        let (n_tilde, h1, h2, xhi) = generate_h1_h2_n_tilde();
        let dlog_statement = DLogStatement {
            N: n_tilde,
            g: h1,
            ni: h2,
        };
        let composite_dlog_proof = CompositeDLogProof::prove(&dlog_statement, &xhi);
	
        // Generate PDL with slack statement, witness and proof                                                                                                                                                                                                                          
	let pdl_w_slack_statement = PDLwSlackStatement {
            ciphertext: paillier_key_pair.encrypted_share.clone(),
            ek: paillier_key_pair.ek.clone(),
	    Q: GE::generator() * &party1_private.x1,
	    G: GE::generator(),
            h1: dlog_statement.g.clone(),
            h2: dlog_statement.ni.clone(),
            N_tilde: dlog_statement.N.clone(),
        };
        let pdl_w_slack_witness = PDLwSlackWitness {
            x: party1_private.x1.clone(),
            r: party1_private.c_key_randomness.clone(),
            dk: party1_private.paillier_priv.clone(),
        };
        let pdl_w_slack_proof = PDLwSlackProof::prove(&pdl_w_slack_witness, &pdl_w_slack_statement);
        (
            pdl_w_slack_statement,
            pdl_w_slack_proof,
            composite_dlog_proof,
        )
    }
}
pub fn generate_h1_h2_n_tilde() -> (BigInt, BigInt, BigInt, BigInt) {
    //note, should be safe primes:                                                                                                                                                                                                                                                       
    // let (ek_tilde, dk_tilde) = Paillier::keypair_safe_primes().keys();;                                                                                                                                                                                                               
    let (ek_tilde, dk_tilde) = Paillier::keypair().keys();
    let one: BigInt = One::one();
    let phi = (&dk_tilde.p - &one) * (&dk_tilde.q - &one);
    let h1 = BigInt::sample_below(&phi);
    let xhi = BigInt::sample(SECURITY_BITS);
    let h2 = BigInt::mod_pow(&h1, &(-&xhi), &ek_tilde.n);

    (ek_tilde.n, h1, h2, xhi)
}


#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PDLwSlackStatement {
    pub ciphertext: BigInt,
    pub ek: EncryptionKey,
    pub Q: GE,
    pub G: GE,
    pub h1: BigInt,
    pub h2: BigInt,
    pub N_tilde: BigInt,
}
#[derive(Clone)]
pub struct PDLwSlackWitness {
    pub x: FE,
    pub r: BigInt,
    pub dk: DecryptionKey,
}


#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PDLwSlackProof {
    pub z: BigInt,
    pub u1: GE,
    pub u2: BigInt,
    pub u3: BigInt,
    pub s1: BigInt,
    pub s2: BigInt,
    pub s3: BigInt,
}

pub fn commitment_unknown_order(
    h1: &BigInt,
    h2: &BigInt,
    N_tilde: &BigInt,
    x: &BigInt,
    r: &BigInt,
) -> BigInt {
    let h1_x = BigInt::mod_pow(h1, &x, &N_tilde);
    let h2_r = BigInt::mod_pow(h2, &r, &N_tilde);
    let com = BigInt::mod_mul(&h1_x, &h2_r, &N_tilde);
    com
}


impl PDLwSlackProof {
    pub fn prove(witness: &PDLwSlackWitness, statement: &PDLwSlackStatement) -> Self {
        let q3 = FE::q().pow(3 as u32);
        let q_N_tilde = FE::q() * &statement.N_tilde;
        let q3_N_tilde = &q3 * &statement.N_tilde;

        let alpha = BigInt::sample_below(&q3);
        let one = One::one();
        let beta = BigInt::sample_range(&one, &(&statement.ek.n - &one));
        let rho = BigInt::sample_below(&q_N_tilde);
        let gamma = BigInt::sample_below(&q3_N_tilde);
	let one: BigInt = One::one();

        let z = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &witness.x.to_big_int(),
            &rho,
        );
        let u1 = &statement.G * &ECScalar::from(&alpha);
        let u2 = commitment_unknown_order(
            &(&statement.ek.n + one),
            &beta,
            &statement.ek.nn,
            &alpha,
            &statement.ek.n,
        );
        let u3 = commitment_unknown_order(
            &statement.h1,
            &statement.h2,
            &statement.N_tilde,
            &alpha,
            &gamma,
        );

        let e = HSha256::create_hash(&[
            &statement.G.bytes_compressed_to_big_int(),
            &statement.Q.bytes_compressed_to_big_int(),
            &statement.ciphertext,
            &z,
            &u1.bytes_compressed_to_big_int(),
            &u2,
            &u3,
        ]);

        let s1 = &e * witness.x.to_big_int() + alpha;
        let s2 = commitment_unknown_order(&witness.r, &beta, &statement.ek.n, &e, &One::one());
        let s3 = &e * rho + gamma;

        PDLwSlackProof {
            z,
            u1,
            u2,
            u3,
            s1,
            s2,
            s3,
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
pub struct KeyGenParty1Message2 {
    pub ecdh_second_message: KeyGenSecondMsg,
    pub ek: EncryptionKey,
    pub c_key: BigInt,
    pub correct_key_proof: NICorrectKeyProof,
    pub pdl_statement: PDLwSlackStatement,
    pub pdl_proof: PDLwSlackProof,
    pub composite_dlog_proof: CompositeDLogProof,
}

#[derive(Serialize, Deserialize)]
pub struct MasterKey1 {
    pub public: Party1Public,
    pub private: Party1Private,
    chain_code: BigInt,
}

impl MasterKey1 {
 pub fn set_master_key(
        chain_code: &BigInt,
        party_one_private: Party1Private,
        party_one_public_ec_key: &GE,
        party2_first_message_public_share: &GE,
        paillier_key_pair: PaillierKeyPair,
    ) -> MasterKey1 {
        let party1_public = Party1Public {
            q: compute_pubkey(&party_one_private, party2_first_message_public_share),
            p1: party_one_public_ec_key.clone(),
            p2: party2_first_message_public_share.clone(),
            paillier_pub: paillier_key_pair.ek.clone(),
            c_key: paillier_key_pair.encrypted_share.clone(),
        };

        MasterKey1 {
            public: party1_public,
            private: party_one_private,
            chain_code: chain_code.clone(),
        }
    }
}

#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct Party1Public {
    pub q: GE,
    pub p1: GE,
    pub p2: GE,
    pub paillier_pub: EncryptionKey,
    pub c_key: BigInt,
}

pub fn compute_pubkey(party_one_private: &Party1Private, other_share_public_share: &GE) -> GE {
    other_share_public_share * &party_one_private.x1
}

#[no_mangle]
pub extern "C" fn say_something(some_string: *const u8, some_len: usize) -> sgx_status_t {

    let str_slice = unsafe { slice::from_raw_parts(some_string, some_len) };
    let _ = io::stdout().write(str_slice);

    // A sample &'static string
    let rust_raw_string = "This is a in-Enclave ";
    // An array
    let word:[u8;4] = [82, 117, 115, 116];
    // An vector
    let word_vec:Vec<u8> = vec![32, 115, 116, 114, 105, 110, 103, 33];

    // Construct a string from &'static string
    let mut hello_string = String::from(rust_raw_string);

    // Iterate on word array
    for c in word.iter() {
        hello_string.push(*c as char);
    }

    // Rust style convertion
    hello_string += String::from_utf8(word_vec).expect("Invalid UTF-8")
                                               .as_str();

    // Ocall to normal world for output
    println!("{}", &hello_string);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn create_sealed_secret_key(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {

    let mut data = match Bytes32::new_random(){
	Ok(v) => v,
	Err(e) => return e,
    };

    let sealable = match SgxSealable::try_from(data){
	Ok(x) => x,
	Err(ret) => return ret
    };

    let sealed_data = match sealable.to_sealed(){
	Ok(x) => x,
        Err(ret) => return ret
    };
    
    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log, sealed_log_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    println!("{:?}", sealed_log);

    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn verify_sealed_secret_key(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {

    let data = match Bytes32::try_from((sealed_log, sealed_log_size)) {
	Ok(v) => v,
	Err(e) => return e
    };
    
    println!("{:?}", data);

    sgx_status_t::SGX_SUCCESS
}

/// A Ecall function takes a string and output its SHA256 digest.
///
/// # Parameters
///
/// **input_str**
///
/// A raw pointer to the string to be calculated.
///
/// **some_len**
///
/// An unsigned int indicates the length of input string
///
/// **hash**
///
/// A const reference to [u8;32] array, which is the destination buffer which contains the SHA256 digest, caller allocated.
///
/// # Return value
///
/// **SGX_SUCCESS** on success. The SHA256 digest is stored in the destination buffer.
///
/// # Requirements
///
/// Caller allocates the input buffer and output buffer.
///
/// # Errors
///
/// **SGX_ERROR_INVALID_PARAMETER**
///
/// Indicates the parameter is invalid
#[no_mangle]
pub extern "C" fn calc_sha256(input_str: *const u8,
                              some_len: usize,
                              hash: &mut [u8;32]) -> sgx_status_t {

    println!("calc_sha256 invoked!");

    // First, build a slice for input_str
    let input_slice = unsafe { slice::from_raw_parts(input_str, some_len) };

    // slice::from_raw_parts does not guarantee the length, we need a check
    if input_slice.len() != some_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    println!("Input string len = {}, input len = {}", input_slice.len(), some_len);

    // Second, convert the vector to a slice and calculate its SHA256
    let result = rsgx_sha256_slice(&input_slice);

    // Third, copy back the result
    match result {
        Ok(output_hash) => *hash = output_hash,
        Err(x) => return x
    }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn generate_keypair(input_str: *const u8) -> sgx_status_t {

    let mut rand = match StdRng::new() {
        Ok(rng) => rng,
        Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };
    let mut rands = [0u8;32];
    rand.fill_bytes(&mut rands);

    let privkey = match libsecp256k1::SecretKey::parse(&rands){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };

    let pubkey = libsecp256k1::PublicKey::from_secret_key(&privkey);

    /*
    let (privkey, pubkey) = match secp256k1.generate_keypair(&mut thread_rng()){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };
*/
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn sk_tweak_add_assign(sealed_log1: * mut u8, sealed_log1_size: u32, sealed_log2: * mut u8, sealed_log2_size: u32) -> sgx_status_t {

    let data1 = match Bytes32::try_from((sealed_log1, sealed_log1_size)) {
	Ok(v) => v,
	Err(e) => return e
    };
    
    let mut sk1 = match libsecp256k1::SecretKey::parse(&data1){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    let data1_test = Bytes32{inner: sk1.serialize()};

    assert_eq!(data1, data1_test);

    let data2 = match Bytes32::try_from((sealed_log2, sealed_log2_size)) {
	Ok(v) => v,
	Err(e) => return e
    };

    let sk2 = match libsecp256k1::SecretKey::parse(&data2){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    
    println!("{:?}, {:?}", sk1, sk2);

    match sk1.tweak_add_assign(&sk2){
	Ok(v) => (),
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };


    let sealable = match SgxSealable::try_from(Bytes32{inner: sk1.serialize()}){
        Ok(x) => x,
        Err(ret) => return ret
    };

    let sealed_data = match sealable.to_sealed(){
        Ok(x) => x,
        Err(ret) => return ret
    };

    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log1, sealed_log1_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn sk_tweak_mul_assign(sealed_log1: * mut u8, sealed_log1_size: u32, sealed_log2: * mut u8, sealed_log2_size: u32) -> sgx_status_t {

    let data1 = match Bytes32::try_from((sealed_log1, sealed_log1_size)) {
	Ok(v) => v,
	Err(e) => return e
    };

    let mut sk1 = match libsecp256k1::SecretKey::parse(&data1){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    let data1_test = Bytes32{inner: sk1.serialize()};

    assert_eq!(data1, data1_test);

    let data2 = match Bytes32::try_from((sealed_log2, sealed_log2_size)) {
	Ok(v) => v,
	Err(e) => return e
    };

    let sk2 = match libsecp256k1::SecretKey::parse(&data2){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    
    println!("{:?}, {:?}", sk1, sk2);

    match sk1.tweak_mul_assign(&sk2){
	Ok(v) => (),
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    let sealable = match SgxSealable::try_from(Bytes32{inner: sk1.serialize()}){
        Ok(x) => x,
        Err(ret) => return ret
    };

    let sealed_data = match sealable.to_sealed(){
        Ok(x) => x,
        Err(ret) => return ret
    };

    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log1, sealed_log1_size);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn sign(some_message: &[u8;32], sk_sealed_log: * mut u8, sig: &mut[u8; 64]) -> sgx_status_t {

    let message = libsecp256k1::Message::parse(some_message);

    let sk_bytes = match Bytes32::try_from((sk_sealed_log, SgxSealedLog::size() as u32)) {
        Ok(v) => v,
        Err(e) => return e
    };

    let sk = match libsecp256k1::SecretKey::parse(&sk_bytes){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    let (signature, _recoveryId) = libsecp256k1::sign(&message, &sk);

    *sig = signature.serialize();

    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn get_public_key(sealed_log: * mut u8, public_key: &mut[u8;33]) -> sgx_status_t {

    let data = match Bytes32::try_from((sealed_log, SgxSealedLog::size() as u32)) {
	Ok(v) => v,
	Err(e) => return e
    };

    let mut sk = match libsecp256k1::SecretKey::parse(&data){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    
    *public_key = libsecp256k1::PublicKey::from_secret_key(&sk).serialize_compressed();
    
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn first_message(sealed_log_in: * mut u8, sealed_log_out: * mut u8,
				key_gen_first_msg: &mut [u8;128]) -> sgx_status_t {

    println!("first message");
    
    let data = match Bytes32::try_from((sealed_log_in, SgxSealedLog::size() as u32)) {
        Ok(v) => v,
	Err(e) => return e
    };

    let mut sk = match SK::from_slice(&get_context_all(), data.deref()){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };

    let mut secret_share: FE = ECScalar::<SK>::zero();
    secret_share.set_element(sk);
    
    //let sk_bigint = secret_share.to_big_int();
    let q_third = FE::q();
//    assert!(sk_bigint < q_third.div_floor(&BigInt::from(3)));
    let base: GE = ECPoint::generator();
    let element = secret_share.get_element().clone();
    let public_share = base.scalar_mul(&element);
    
    let d_log_proof = DLogProof::prove(&secret_share);

    let pk_commitment_blind_factor = BigInt::sample(SECURITY_BITS);
    let pk_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
        &public_share.bytes_compressed_to_big_int(),
        &pk_commitment_blind_factor,
    );
    
    let zk_pok_blind_factor = BigInt::sample(SECURITY_BITS);
    let zk_pok_commitment = HashCommitment::create_commitment_with_user_defined_randomness(
        &d_log_proof
            .pk_t_rand_commitment
            .bytes_compressed_to_big_int(),
        &zk_pok_blind_factor,
    );

    let ec_key_pair = EcKeyPair {
        public_share,
        secret_share,
    };
    secret_share.zeroize();

    let key_gen_first_message = KeyGenFirstMsg {
        pk_commitment,
        zk_pok_commitment,
    };

    let pk_commitment_string = key_gen_first_message.pk_commitment.to_hex();
    let zk_pok_commitment_string = key_gen_first_message.zk_pok_commitment.to_hex();

    let key_gen_first_message_str = format!("{}{}",pk_commitment_string,zk_pok_commitment_string);
    
    println!("bignum slice len: {}", pk_commitment_string.len());
    println!("bignum slice len: {}", zk_pok_commitment_string.len());
    
    let comm_witness = CommWitness {
        pk_commitment_blind_factor,
        zk_pok_blind_factor,
        public_share: ec_key_pair.public_share,
        d_log_proof,
    };

    let first_message_sealed = FirstMessageSealed { comm_witness, ec_key_pair };
    
    let sealable = match SgxSealable::try_from(first_message_sealed){
	Ok(x) => x,
	Err(ret) => return ret
    };

    let sealed_data = match sealable.to_sealed(){
	Ok(x) => x,
        Err(ret) => return ret
    };

    
    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log_out, SgxSealedLog::size() as u32);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    
    
  //  let encoded_key_gen_first_message = match serde_cbor::to_vec(&key_gen_first_message){
//	Ok(v) => v,
//	Err(e) => {
//	    println!("error: {:?}",e);
//	    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
//		
//	}
//    };

//    *msg_size = encoded_key_gen_first_message.len().to_be_bytes();
  //  let kg1m_slice = encoded_key_gen_first_message.as_slice();


//    println!("kg1m slice len: {}", kg1m_slice.len());

    println!("{:?}", sealed_log_out);
    println!("keygen msg: {:?}", key_gen_first_message_str.as_str());
    
    *key_gen_first_msg = match key_gen_first_message_str.into_bytes().as_slice().try_into(){
	Ok(x) => x,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    };

    

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn second_message(sealed_log_in: * mut u8, sealed_log_out: * mut u8,
				 msg2_str: *const u8, len: usize,
				 kg_party_one_second_message: &mut [u8;480000] 
//				 kg_party_one_second_message: &mut [u8;128]
) -> sgx_status_t {

    println!("second message");

    let str_slice = unsafe { slice::from_raw_parts(msg2_str, len) };
    println!("got str slice: {:?}", str_slice);
//    let _ = io::stdout().write(str_slice);

    let key_gen_msg2: KeyGenMsg2 = match std::str::from_utf8(&str_slice) {
	Ok(v) =>{
	    println!("str from str slice: {}", v);
	    match serde_json::from_str(v){
		Ok(v) => v,
		Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	    }
	},
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    };

    println!("got key_gen_msg_2");
    
    let user_id = key_gen_msg2.shared_key_id;

    let party2_public: GE = key_gen_msg2.dlog_proof.pk.clone();

    println!("getting first message sealed");
    let data = match FirstMessageSealed::try_from((sealed_log_in, SgxSealedLog::size() as u32)) {
        Ok(v) => v,
	Err(e) => return e
    };

    let comm_witness = data.comm_witness;
    let comm_witness_public_share = comm_witness.public_share.clone();
    let ec_key_pair = &data.ec_key_pair;

    println!("get dlog proof");
    let key_gen_second_message = match DLogProof::verify(&key_gen_msg2.dlog_proof){
	Ok(v) => KeyGenSecondMsg { comm_witness },
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    };
    println!("get encoded vec");
    let encoded_vec = match serde_cbor::to_vec(&key_gen_second_message){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };

    let ev_len = encoded_vec.len();
    println!("keygen 2nd msg: {:?}", encoded_vec);
    println!("keygen 2nd msg len: {}", ev_len);

    let (ek, dk) = Paillier::keypair().keys();
    let randomness = Randomness::sample(&ek);

    let encrypted_share = Paillier::encrypt_with_chosen_randomness(
        &ek,
        RawPlaintext::from(ec_key_pair.secret_share.to_big_int()),
        &randomness,
    ).0.into_owned();
    
    let party_one_private = Party1Private {
            x1: ec_key_pair.secret_share,
            paillier_priv: dk.clone(),
            c_key_randomness: randomness.0.clone(),
    };

    let paillier_context = PaillierKeyPair{ ek, dk, encrypted_share, randomness: randomness.0};

    let correct_key_proof = NICorrectKeyProof::proof(&paillier_context.dk);

/*
    let (kg_party_one_second_message, paillier_key_pair, party_one_private): (
            party1::KeyGenParty1Message2, //public
            party_one::PaillierKeyPair,   //private
            party_one::Party1Private,     //private
    ) =(
            KeyGenParty1Message2 {
                ecdh_second_message: key_gen_second_message,
                ek: paillier_key_pair.ek.clone(),
                c_key: paillier_key_pair.encrypted_share.clone(),
                correct_key_proof,
                range_proof,
            },
            paillier_key_pair,
            party_one_private,
        );
     */

    let (pdl_statement, pdl_proof, composite_dlog_proof) =
            PaillierKeyPair::pdl_proof(&party_one_private, &paillier_context);

    let second_message =  KeyGenParty1Message2 {
        ecdh_second_message: key_gen_second_message,
        ek: paillier_context.ek.clone(),
        c_key: paillier_context.encrypted_share.clone(),
        correct_key_proof,
	pdl_statement,
	pdl_proof,
	composite_dlog_proof,
	};     


    let plain_str = match serde_json::to_string(&second_message){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    };

    let len = plain_str.len();
    let mut plain_str_sized=format!("{}", len);
    let mut plain_str_sized=format!("{}{}", plain_str_sized.len(), plain_str_sized);
    println!("************ second msg plain len: {}", len);
    plain_str_sized.push_str(&plain_str);

    let mut plain_bytes=plain_str_sized.into_bytes();
    plain_bytes.resize(480000,0);
    
    *kg_party_one_second_message  = match plain_bytes.as_slice().try_into(){
	Ok(x) => x,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    };
    
    //    *kg_party_one_second_message =
    //match plain_str_slice.as_mut_ptr();
    
//    println!("second message plain slice: {}", len_out);
    
/*
	MasterKey1::key_gen_second_message(
            comm_witness,
            &ec_key_pair,
            &key_gen_msg2.dlog_proof,
        );
*/

    let master_key = MasterKey1::set_master_key(
            &BigInt::from(0),
            party_one_private.clone(),
            &comm_witness_public_share,
            &party2_public,
            paillier_context.clone(),
    );
    
    let second_message_sealed =  SecondMessageSealed {
        paillier_key_pair: paillier_context,
        party_one_private,
	master_key
    };

    println!("get sealable");
    let sealable = match SgxSealable::try_from(second_message_sealed){
	Ok(x) => x,
	Err(ret) => return ret
    };

    println!("get sealed");
    let sealed_data = match sealable.to_sealed(){
	Ok(x) => x,
        Err(ret) => return ret
    };

//    println!("sealed data size: {}", sealed_data.deref().len());

    println!("get sealed log");
    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log_out, SgxSealedLog::size() as u32);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }


    //*key_gen_first_msg = match key_gen_first_message_str.into_bytes().as_slice().try_into(){
//        Ok(x) => x,
//        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
//    };
    
//key_gen_second_message

    //let comm_witness_string = key_gen_second_message.comm_witness.to_hex();
//    let kg_second_message_str = format!("{}",comm_witness_string);

   // println!("{:?}", sealed_log_out);
//    println!("keygen 2nd msg: {}", kg_second_message_str.as_str());
//    println!("keygen 2nd msg len: {}", kg_second_message_str.len());

  //  let kg2m_vec = match serde_cbor::to_vec(&key_gen_second_message){
//	Ok(v) => v,
//	Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED
  //  };
    
//    *kg_party_one_second_msg = match kg_second_message_str.into_bytes().as_slice().try_into(){
//	Ok(x) => x,
//	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
//    };

    
    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn sign_first(sealed_log_in: * mut u8, sealed_log_out: * mut u8,
			     msg2_str: *const u8, len: usize,
			     sign_party_one_first_message: &mut [u8;480000]) -> sgx_status_t {


//    let db = &self.database;
    
    let base: GE = ECPoint::generator();
    let secret_share: FE = ECScalar::new_random();
    let public_share = &base * &secret_share;
    let h: GE = GE::base_point2();
    let w = ECDDHWitness {
        x: secret_share.clone(),
    };
    let c = &h * &secret_share;
    let delta = ECDDHStatement {
        g1: base.clone(),
        h1: public_share.clone(),
        g2: h.clone(),
        h2: c.clone(),
    };
    let d_log_proof = ECDDHProof::prove(&w, &delta);
    let ec_key_pair = EphEcKeyPair {
        public_share: public_share.clone(),
        secret_share,
    };
    
    let (sign_party_one_first_msg, eph_ec_key_pair_party1) :
    //(multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::
    (EphKeyGenFirstMsg, EphEcKeyPair) =
	(
            EphKeyGenFirstMsg {
		d_log_proof,
		public_share,
		c,
            },
            ec_key_pair,
	);

    let plain_str = match serde_json::to_string(&sign_party_one_first_msg){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    };

    let len = plain_str.len();
    let mut plain_str_sized=format!("{}", len);
    let mut plain_str_sized=format!("{}{}", plain_str_sized.len(), plain_str_sized);
    println!("************ second msg plain len: {}", len);
    plain_str_sized.push_str(&plain_str);

    let mut plain_bytes=plain_str_sized.into_bytes();
    plain_bytes.resize(480000,0);
    
    *sign_party_one_first_message  = match plain_bytes.as_slice().try_into(){
	Ok(x) => x,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    };

    let sign_first_sealed =  SignFirstSealed {
        ec_key_pair: eph_ec_key_pair_party1
    };

    println!("get sealable");
    let sealable = match SgxSealable::try_from(sign_first_sealed){
	Ok(x) => x,
	Err(ret) => return ret
    };

    println!("get sealed");
    let sealed_data = match sealable.to_sealed(){
	Ok(x) => x,
        Err(ret) => return ret
    };

//    println!("sealed data size: {}", sealed_data.deref().len());

    println!("get sealed log");
    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log_out, SgxSealedLog::size() as u32);
    if opt.is_none() {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }
	
//    Ok(sign_party_one_first_message)
    sgx_status_t::SGX_SUCCESS
	
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct sign_second_out {
    inner: Vec<Vec<u8>>
}


#[no_mangle]
pub extern "C" fn sign_second(firstMessageSealed: * mut u8, masterKeySealed: * mut u8, sealed_log_out: * mut u8,
			      eph_key_gen_first_msg: * const u8,
			      plain_out: *const u8, len: usize) -> sgx_status_t {

/*
    println!("getting first message sealed");
    let data = match FirstMessageSealed::try_from((sealed_log_in, SgxSealedLog::size() as u32)) {
        Ok(v) => v,
        Err(e) => return e
    };


    // Get 2P-Ecdsa data
    let ssi: ECDSASignSecondInput = db.get_ecdsa_sign_second_input(user_id)?;

    let signature;
    match ssi.shared_key.sign_second_message(
        &sign_msg2.sign_second_msg_request.party_two_sign_message,
        &ssi.eph_key_gen_first_message_party_two,
        &ssi.eph_ec_key_pair_party1,
                &sign_msg2.sign_second_msg_request.message,
    ) {
        Ok(sig) => signature = sig,
        Err(_) => {
            return Err(SEError::SigningError(String::from(
                "Signature validation failed.",
            )))
        }
    };
    
            // Make signature witness
            let mut r_vec = BigInt::to_vec(&signature.r);
            if r_vec.len() != 32 {
                // Check corrcet length of conversion to Signature
                let mut temp = vec![0; 32 - r_vec.len()];
                temp.extend(r_vec);
                r_vec = temp;
            }
            let mut s_vec = BigInt::to_vec(&signature.s);
            if s_vec.len() != 32 {
                // Check corrcet length of conversion to Signature
                let mut temp = vec![0; 32 - s_vec.len()];
                temp.extend(s_vec);
                s_vec = temp;
            }
            let mut v = r_vec;
            v.extend(s_vec);
            let mut sig_vec = Signature::from_compact(&v[..])?.serialize_der().to_vec();
            sig_vec.push(01);
            let pk_vec = ssi.shared_key.public.q.get_element().serialize().to_vec();
            let witness = vec![sig_vec, pk_vec];
            ws = witness;
        }

        // Get transaction which is being signed.
        let mut tx: Transaction = match sign_msg2.sign_second_msg_request.protocol {
            Protocol::Withdraw => db.get_tx_withdraw(user_id)?,
            _ => db.get_user_backup_tx(user_id)?,
        };

        // Add signature to tx
        tx.input[0].witness = ws.clone();

        match sign_msg2.sign_second_msg_request.protocol {
            Protocol::Withdraw => {
                // Store signed withdraw tx in UserSession DB object
                db.update_tx_withdraw(user_id, tx)?;

                info!("WITHDRAW: Tx signed and stored. User ID: {}", user_id);
                // Do not return withdraw tx witness until /withdraw/confirm is complete
                ws = vec![];
            }
            _ => {
                // Store signed backup tx in UserSession DB object
                db.update_user_backup_tx(&user_id, tx)?;
                info!(
                    "DEPOSIT/TRANSFER: Backup Tx signed and stored. User: {}",
                    user_id
                );
            }
        };

        Ok(ws)
    }
*/
    sgx_status_t::SGX_SUCCESS
}


fn to_sealed_log_for_slice<T: Copy + ContiguousMemory>(sealed_data: &SgxSealedData<[T]>, sealed_log: * mut u8, sealed_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        sealed_data.to_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}

fn from_sealed_log_for_slice<'a, T: Copy + ContiguousMemory>(sealed_log: * mut u8, sealed_log_size: u32) -> Option<SgxSealedData<'a, [T]>> {
    unsafe {
        SgxSealedData::<[T]>::from_raw_sealed_data_t(sealed_log as * mut sgx_sealed_data_t, sealed_log_size)
    }
}


