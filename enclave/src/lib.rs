
// Licensed to the Apache Software Foundation secret key(ASF) under only
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
extern crate sgx_tse;
extern crate sgx_tdh;
extern crate sgx_trts;
use sgx_tdh::{SgxDhMsg1, SgxDhMsg2, SgxDhMsg3, SgxDhInitiator, SgxDhResponder};
use sgx_trts::trts::{rsgx_raw_is_outside_enclave, rsgx_lfence, rsgx_raw_is_within_enclave};
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
extern crate subtle;
extern crate ecies;
#[macro_use]
extern crate serde_big_array;
extern crate lazy_static;
extern crate hex;

use secp256k1::Secp256k1;
use sgx_types::*;
use sgx_tcrypto::*;  
use std::string::String;
use sgx_types::marker::ContiguousMemory;
use std::vec::Vec;
use std::io::{self, Write};
use std::slice;
use std::convert::{TryFrom, TryInto};
use std::mem;
use sgx_rand::{Rng, StdRng};
use sgx_tseal::{SgxSealedData};
use std::ops::{Deref, DerefMut};
use std::default::Default;
use curv::{BigInt, FE, GE};

use curv::elliptic::curves::traits::{ECScalar, ECPoint};
use curv::arithmetic_sgx::traits::{Samplable, Converter};
use curv::cryptographic_primitives_sgx::proofs::sigma_ec_ddh::*;
use curv::cryptographic_primitives_sgx::proofs::sigma_dlog::*;
use curv::cryptographic_primitives_sgx::hashing::{hash_sha256::HSha256, traits::Hash};
use curv::cryptographic_primitives_sgx::commitments::hash_commitment::HashCommitment;
use curv::cryptographic_primitives_sgx::commitments::traits::Commitment;
use curv::cryptographic_primitives_sgx::twoparty::dh_key_exchange::EcKeyPair;
use curv::arithmetic_sgx::traits::*;
use zeroize::Zeroize;
use integer::Integer;
use uuid::Uuid;
use paillier::{Paillier, Randomness, RawPlaintext, KeyGeneration,
	       EncryptWithChosenRandomness, DecryptionKey, EncryptionKey, Decrypt, RawCiphertext};
use zk_paillier::zkproofs::{NICorrectKeyProof,CompositeDLogProof, DLogStatement};
use num_traits::{One, Pow};
use core::ptr;
use std::string::ToString;

extern crate attestation;
use attestation::types::*;
use attestation::err::*;
use attestation::func::*;

use std::boxed::Box;
use lazy_static::lazy_static;

use std::sync::SgxMutex as Mutex;

#[macro_use]
extern crate serde_derive;
extern crate serde_cbor;

const SECURITY_BITS: usize = 256;

pub const EC_LOG_SIZE: usize = 8192;
pub type EcLog = [u8; EC_LOG_SIZE];

pub const EC_LOG_SIZE_LG: usize = 32400;
pub type EcLogLg = [u8; EC_LOG_SIZE_LG];

//Using lazy_static in order to be able to use a heap-allocated
//static variable requiring runtime executed code
lazy_static!{
    static ref INITIATOR: Mutex<SgxDhInitiator> = Mutex::new(SgxDhInitiator::init_session());
    static ref RESPONDER: Mutex<SgxDhResponder> = Mutex::new(SgxDhResponder::init_session());
    static ref SESSIONINFO: Mutex<DhSessionInfo> = Mutex::new(DhSessionInfo::default());
    static ref SESSIONKEY: Mutex<sgx_align_key_128bit_t> = Mutex::new(sgx_align_key_128bit_t::default());
    static ref ECKEY: Mutex<sgx_align_key_128bit_t> = Mutex::new(sgx_align_key_128bit_t::default());
    static ref INITIALIZED: Mutex<bool> = Mutex::new(false);
}

big_array! {
    BigArray;
    +42,
}

fn test_vec() -> Vec<u8>{
    vec![123, 34, 105, 110, 110, 101, 114, 34, 58, 34, 57, 50, 53, 48, 98, 52, 48, 98, 57, 55, 53, 49, 97, 57, 50, 50, 51, 57, 56, 50, 50, 56, 50, 52, 98, 49, 52, 56, 97, 55, 54, 54, 52, 48, 102, 100, 100, 56, 98, 49, 50, 53, 51, 97, 97, 102, 100, 50, 99, 100, 50, 101, 56, 49, 53, 50, 53, 49, 98, 99, 98, 51, 102, 49, 34, 125]
}

fn verify_peer_enclave_trust(peer_enclave_identity: &sgx_dh_session_enclave_identity_t )-> u32 {

    if peer_enclave_identity.isv_prod_id != 0 || peer_enclave_identity.attributes.flags & SGX_FLAGS_INITTED == 0 {
        // || peer_enclave_identity->attributes.xfrm !=3)// || peer_enclave_identity->mr_signer != xx //TODO: To be hardcoded with values to check
        ATTESTATION_STATUS::ENCLAVE_TRUST_ERROR as u32
    } else {
        ATTESTATION_STATUS::SUCCESS as u32
    }
}

#[no_mangle]
pub extern "C" fn test_enclave_init() {
    let cb = Callback{
        verify: verify_peer_enclave_trust,
    };
    init(cb);
}

#[no_mangle]
pub extern "C" fn test_create_session() -> u32 {
    create_session() as u32
}


#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn test_close_session() -> u32 {
    close_session() as u32
}


pub fn create_session() -> ATTESTATION_STATUS {

    let mut dh_msg1: SgxDhMsg1 = SgxDhMsg1::default(); //Diffie-Hellman Message 1
    let mut dh_msg2: SgxDhMsg2 = SgxDhMsg2::default(); //Diffie-Hellman Message 2
    let mut dh_aek: sgx_align_key_128bit_t = sgx_align_key_128bit_t::default(); // Session Key
    let mut responder_identity: sgx_dh_session_enclave_identity_t = sgx_dh_session_enclave_identity_t::default();
    let ret = 0;


    let status = unsafe { session_request_ocall(&mut dh_msg1) };
    if status != sgx_status_t::SGX_SUCCESS {
        return ATTESTATION_STATUS::ATTESTATION_SE_ERROR;
    }
    let err = ATTESTATION_STATUS::from_repr(ret).unwrap();
    if err != ATTESTATION_STATUS::SUCCESS{
        return err;
    }

    let status = match INITIATOR.lock() {
	Ok(mut r) => r.proc_msg1(&dh_msg1, &mut dh_msg2),
	Err(_) => return ATTESTATION_STATUS::ATTESTATION_ERROR
    };
    
    if status.is_err() {
        return ATTESTATION_STATUS::ATTESTATION_ERROR;
    }

    let mut dh_msg3_raw = sgx_dh_msg3_t::default();
    let status = sgx_status_t::SGX_SUCCESS;
//    unsafe { exchange_report_ocall(&mut ret, src_enclave_id, dest_enclave_id, &mut dh_msg2, &mut dh_msg3_raw as *mut sgx_dh_msg3_t) };
    if status != sgx_status_t::SGX_SUCCESS {
        return ATTESTATION_STATUS::ATTESTATION_SE_ERROR;
    }
    if ret != ATTESTATION_STATUS::SUCCESS as u32 {
        return ATTESTATION_STATUS::from_repr(ret).unwrap();
    }

    let dh_msg3_raw_len = mem::size_of::<sgx_dh_msg3_t>() as u32 + dh_msg3_raw.msg3_body.additional_prop_length;
    let dh_msg3 = unsafe{ SgxDhMsg3::from_raw_dh_msg3_t(&mut dh_msg3_raw, dh_msg3_raw_len ) };
    if dh_msg3.is_none() {
        return ATTESTATION_STATUS::ATTESTATION_SE_ERROR;
    }
    let dh_msg3 = dh_msg3.unwrap();

    let status = match INITIATOR.lock() {
	Ok(mut r) => r.proc_msg3(&dh_msg3, &mut dh_aek.key, &mut responder_identity),
	Err(_) => return ATTESTATION_STATUS::ATTESTATION_ERROR,
    };
    
    if status.is_err() {
        return ATTESTATION_STATUS::ATTESTATION_ERROR;
    }

    /*
    let cb = get_callback();
    if cb.is_some() {
        let ret = (cb.unwrap().verify)(&responder_identity);
        if ret != ATTESTATION_STATUS::SUCCESS as u32{
            return ATTESTATION_STATUS::INVALID_SESSION;
        }
    }
     */

    ATTESTATION_STATUS::SUCCESS 
}

fn eckey_status() -> bool {
    match ECKEY.lock() {
        Ok(key) => key.key != sgx_align_key_128bit_t::default().key,
        Err(_) => false
    }
}

fn is_initialized() -> SgxResult<bool> {
    let result = INITIALIZED.lock().map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)?.clone();
    Ok(result)
}


fn set_initialized() -> SgxResult<()> {
    let mut i = INITIALIZED.lock().map_err(|_| sgx_status_t::SGX_ERROR_UNEXPECTED)?;
    *i = true;
    Ok(())
}

fn session_request_safe(src_enclave_id: sgx_enclave_id_t,
			dh_msg1: &mut [u8;1700]
    //,
//			session_ptr: &mut usize
) -> ATTESTATION_STATUS {
    match is_initialized() { 
        Ok(true) => return ATTESTATION_STATUS::INVALID_SESSION,
        Ok(false) => (),
        Err(_) => return ATTESTATION_STATUS::INVALID_SESSION,
    };
    let mut dh_msg1_inner = SgxDhMsg1::default();

    let mut responder = SgxDhResponder::init_session();
    let status = responder.gen_msg1(&mut dh_msg1_inner);
    
    if status.is_err() {
        return ATTESTATION_STATUS::INVALID_SESSION;
    }

    match serde_json::to_string(& DHMsg1 { inner: dh_msg1_inner } ) {
	    Ok(v) => {
	        let len = v.len();
	        let mut v_sized=format!("{}", len);
            v_sized=format!("{}{}", v_sized.len(), v_sized);
            v_sized.push_str(&v);
            let mut v_bytes=v_sized.into_bytes();
            v_bytes.resize(1700,0);
            *dh_msg1 = match v_bytes.as_slice().try_into(){
                Ok(r) => r,
                Err(_) => return ATTESTATION_STATUS::INVALID_SESSION
            };
        },
	    Err(_) => return ATTESTATION_STATUS::INVALID_SESSION
    };

    match SESSIONINFO.lock() {
	Ok(mut session_info) => {
	    session_info.enclave_id = src_enclave_id;
	    session_info.session.session_status = DhSessionStatus::InProgress(responder);
    	ATTESTATION_STATUS::SUCCESS
	    //	    let ptr = Box::into_raw(Box::new(session_info));
        //	    *session_ptr = ptr as * mut _ as usize;
	},
	Err(_) => ATTESTATION_STATUS::INVALID_SESSION,
    }
    
}


//Handle the request from Source Enclave for a session
#[no_mangle]
pub extern "C" fn session_request(src_enclave_id: sgx_enclave_id_t,
				  dh_msg1: &mut [u8;1700])
	-> ATTESTATION_STATUS {
        session_request_safe(src_enclave_id, dh_msg1)
}

fn proc_msg1_safe(dh_msg1_str: *const u8 , msg1_len: usize,
		  dh_msg2: &mut [u8;1700]
) -> ATTESTATION_STATUS {
    
    let str_slice = unsafe { slice::from_raw_parts(dh_msg1_str, msg1_len) };
    
    
    let dh_msg1 = match std::str::from_utf8(&str_slice) {
        Ok(v) =>{
            match serde_json::from_str::<DHMsg1>(v){
                Ok(v) => v.inner,
                Err(_) => return ATTESTATION_STATUS::INVALID_SESSION
            }
        },
        Err(_) => return ATTESTATION_STATUS::INVALID_SESSION
    };

    
    let mut dh_msg2_inner: SgxDhMsg2 = SgxDhMsg2::default(); //Diffie-Hellman Message 2
    
    
    let status = match INITIATOR.lock() {
	    Ok(mut r) => 
        {   
            r.proc_msg1(&dh_msg1, &mut dh_msg2_inner)
        },
	    Err(_) => {
    
            return ATTESTATION_STATUS::ATTESTATION_ERROR
        }
    };

    if status.is_err() {
    
        return ATTESTATION_STATUS::ATTESTATION_ERROR;
    }

    
    match serde_json::to_string(& DHMsg2 { inner: dh_msg2_inner } ) {
	Ok(v) => {
	    let len = v.len();
    
	    let mut v_sized=format!("{}", len);
	    v_sized=format!("{}{}", v_sized.len(), v_sized);
	    v_sized.push_str(&v);
    
	    let mut v_bytes=v_sized.into_bytes();
    
	    v_bytes.resize(1700,0);
    
	    *dh_msg2 = v_bytes.as_slice().try_into().unwrap();
	},
	Err(_) => return ATTESTATION_STATUS::INVALID_SESSION
    };

    
    ATTESTATION_STATUS::SUCCESS
}


//Handle the request from Source Enclave for a session
#[no_mangle]
pub extern "C" fn proc_msg1(dh_msg1_str: *const u8 , msg1_len: usize,
                           dh_msg2: &mut [u8;1700])
				  -> ATTESTATION_STATUS {
        proc_msg1_safe(dh_msg1_str, msg1_len, dh_msg2)
}

fn internal_set_session_key(val: sgx_align_key_128bit_t) -> SgxResult<()> {
    match SESSIONKEY.lock() {
        Ok(mut key) => {
            let default = sgx_align_key_128bit_t::default();
            if key.key != default.key {
                return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
            }
            *key = val;
            Ok(())
        },
        Err(_) => Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER),
    }
}

fn proc_msg3_safe(dh_msg3_str: *const u8 , msg3_len: usize, sealed_log:  * mut u8) -> ATTESTATION_STATUS {

    let str_slice = unsafe{ slice::from_raw_parts(dh_msg3_str, msg3_len) };

    let mut dh_msg3_raw = match std::str::from_utf8(&str_slice) {
        Ok(v) =>{
            match serde_json::from_str::<DHMsg3>(v){
                Ok(v) => v.inner,
                Err(_) => return ATTESTATION_STATUS::INVALID_SESSION
            }
        },
        Err(_) => return ATTESTATION_STATUS::INVALID_SESSION
    };

    let mut dh_aek: sgx_align_key_128bit_t = sgx_align_key_128bit_t::default(); // Session Key
    let mut responder_identity: sgx_dh_session_enclave_identity_t = sgx_dh_session_enclave_identity_t::default();


    let dh_msg3_raw_len = mem::size_of::<sgx_dh_msg3_t>() as u32 + dh_msg3_raw.msg3_body.additional_prop_length;
    let dh_msg3 = unsafe{ SgxDhMsg3::from_raw_dh_msg3_t(&mut dh_msg3_raw, dh_msg3_raw_len ) };
    if dh_msg3.is_none() {
        return ATTESTATION_STATUS::ATTESTATION_SE_ERROR;
    }
    let dh_msg3 = dh_msg3.unwrap();
    
    let status = match INITIATOR.lock() {
	Ok(mut r) => r.proc_msg3(&dh_msg3, &mut dh_aek.key, &mut responder_identity),
	Err(_) => return ATTESTATION_STATUS::ATTESTATION_ERROR,
    };
    
    if status.is_err() {
        return ATTESTATION_STATUS::ATTESTATION_ERROR;
    }

    /*
    let cb = get_callback();
    if cb.is_some() {
        let ret = (cb.unwrap().verify)(&responder_identity);
        if ret != ATTESTATION_STATUS::SUCCESS as u32{
            return ATTESTATION_STATUS::INVALID_SESSION;
        }
    }
     */
    

    let key_sealed  = SgxKey128BitSealed {
	inner: dh_aek.key
    };
    
    let sealable = match SgxSealable::try_from(key_sealed){
	Ok(x) => x,
        Err(_) => return ATTESTATION_STATUS::ATTESTATION_ERROR
    };

    let sealed_data = match sealable.to_sealed(){
        Ok(x) => x,
	Err(_) => return ATTESTATION_STATUS::ATTESTATION_ERROR
    };

    
    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log, EC_LOG_SIZE as u32);
    if opt.is_none() {
	return ATTESTATION_STATUS::ATTESTATION_ERROR;
    }

    match ECKEY.lock() {
	Ok(mut ec_key) => {
	    *ec_key = dh_aek;
	},
	Err(_) => return ATTESTATION_STATUS::INVALID_SESSION,
    };

    ATTESTATION_STATUS::SUCCESS
}


//Handle the request from Source Enclave for a session
#[no_mangle]
pub extern "C" fn proc_msg3(dh_msg3_str: *const u8 , msg3_len: usize, sealed_log:  * mut u8)
				  -> ATTESTATION_STATUS {
    proc_msg3_safe(dh_msg3_str, msg3_len, sealed_log)
}

#[allow(unused_variables)]
fn exchange_report_safe(src_enclave_id: sgx_enclave_id_t,
			dh_msg2_str: *const u8 , msg2_len: usize,
			dh_msg3_arr: &mut [u8;1700],
			sealed_log: *mut u8
//			session_info: &mut DhSessionInfo
) -> ATTESTATION_STATUS {

    println!("{:?}","pos13");

    match is_initialized() { 
        Ok(true) => return ATTESTATION_STATUS::INVALID_SESSION,
        Ok(false) => (),
        Err(_) => return ATTESTATION_STATUS::INVALID_SESSION,
    };

    println!("{:?}","pos14");

    let str_slice = unsafe { slice::from_raw_parts(dh_msg2_str, msg2_len) };
    
    println!("{:?}","pos15");

    let dh_msg2 = match std::str::from_utf8(&str_slice) {
	Ok(v) =>{
	    match serde_json::from_str::<DHMsg2>(v){
		Ok(v) => v.inner,
		Err(_) => return ATTESTATION_STATUS::INVALID_SESSION
	    }
	},
	Err(_) => return ATTESTATION_STATUS::INVALID_SESSION
    };
    
    println!("{:?}","pos16");

    let mut dh_aek = sgx_align_key_128bit_t::default() ;   // Session key
    
    println!("{:?}","pos17");

    let mut initiator_identity = sgx_dh_session_enclave_identity_t::default();

    println!("{:?}","pos18");
    
    let dh_msg3_r  = match SESSIONINFO.lock() {
	Ok(session_info) => {
    
	    let mut responder = match session_info.session.session_status {
		    DhSessionStatus::InProgress(res) => {res},
		    _ => {
		        return ATTESTATION_STATUS::INVALID_SESSION;
		    }
	    };

	    let mut result = SgxDhMsg3::default();
        
	    let status = responder.proc_msg2(&dh_msg2, &mut result, &mut dh_aek.key, &mut initiator_identity);
	    if status.is_err() {
        	return ATTESTATION_STATUS::ATTESTATION_ERROR;
	    }
	    result
	},
	Err(e) => {
        return ATTESTATION_STATUS::INVALID_SESSION
        }
    };

    println!("{:?}","pos19");

    let raw_len = dh_msg3_r.calc_raw_sealed_data_size();
    let mut dh_msg3_inner = sgx_dh_msg3_t::default();
    let _ = unsafe{ dh_msg3_r.to_raw_dh_msg3_t(&mut dh_msg3_inner, raw_len ) };

    println!("{:?}","pos20");

    match serde_json::to_string(& DHMsg3 { inner: dh_msg3_inner } ) {
	Ok(v) => {
	    let len = v.len();
	    let mut v_sized=format!("{}", len);
	    v_sized=format!("{}{}", v_sized.len(), v_sized);
	    v_sized.push_str(&v);
	    let mut v_bytes=v_sized.into_bytes();
	    v_bytes.resize(1700,0);
	    *dh_msg3_arr = v_bytes.as_slice().try_into().unwrap();
	},
	Err(e) => {
            return ATTESTATION_STATUS::INVALID_SESSION
        }
    };

    println!("{:?}","pos20");

    let key_sealed  = SgxKey128BitSealed {
	    inner: dh_aek.key
    };
    
    println!("{:?}","pos21");

    let sealable = match SgxSealable::try_from(key_sealed){
	Ok(x) => x,
        Err(_) => return ATTESTATION_STATUS::ATTESTATION_ERROR
    };

    println!("{:?}","pos22");

    let sealed_data = match sealable.to_sealed(){
        Ok(x) => x,
	Err(_) => return ATTESTATION_STATUS::ATTESTATION_ERROR
    };
    
    println!("{:?}","pos23");

    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log, EC_LOG_SIZE as u32);
    if opt.is_none() {
	return ATTESTATION_STATUS::ATTESTATION_ERROR;
    }

    println!("{:?}","pos24");

    match SESSIONKEY.lock() {
	    Ok(mut session_key) => {
	        *session_key = dh_aek;
	    },
	Err(e) => {
            return ATTESTATION_STATUS::INVALID_SESSION
        },
    };
    
    println!("{:?}","pos25");

    match SESSIONINFO.lock() {
	Ok(mut session_info) => {
                session_info
				 .session.session_status = DhSessionStatus::Active(dh_aek);
				 ATTESTATION_STATUS::SUCCESS},
	Err(e) => {
            ATTESTATION_STATUS::INVALID_SESSION
        },
    }
    
}
//Verify Message 2, generate Message3 and exchange Message 3 with Source Enclave
#[no_mangle]
pub extern "C" fn exchange_report(src_enclave_id: sgx_enclave_id_t,
				  dh_msg2_str: *const u8, msg2_len: usize,
				  dh_msg3_arr: &mut [u8;1700],
				  sealed_log: *mut u8,
) -> ATTESTATION_STATUS {
    
    rsgx_lfence();

    println!("{:?}","pos12");

    exchange_report_safe(src_enclave_id, dh_msg2_str, msg2_len, dh_msg3_arr, sealed_log)
}

//Respond to the request from the Source Enclave to close the session
#[no_mangle]
#[allow(unused_variables)]
pub extern "C" fn end_session(src_enclave_id: sgx_enclave_id_t)
        -> ATTESTATION_STATUS {

    rsgx_lfence();

    match SESSIONINFO.lock() {
	    Ok(mut session_info) => {
	        *session_info = DhSessionInfo::default();
	        ATTESTATION_STATUS::SUCCESS
	    },
	    Err(_) => ATTESTATION_STATUS::INVALID_SESSION
    }
}


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

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
struct SgxPayload {
    payload_size: u32,
    reserved: [u8; 12],
    payload_tag: [u8; SGX_SEAL_TAG_SIZE],
    encrypt: Box<[u8]>,
    additional: Box<[u8]>,
}

/*
impl_struct! {
    pub struct encrypted_data_t {
        pub plain_text_offset: uint32_t,
        pub reserved: [uint8_t; 12],
        pub aes_data: sgx_aes_gcm_data_t,
    }
}
 */

/*
impl_struct! {
    pub struct sgx_aes_gcm_data_t {
        pub payload_size: uint32_t,
        pub reserved: [uint8_t; 12],
        pub payload_tag: [uint8_t; SGX_SEAL_TAG_SIZE],
        pub payload: [uint8_t; 0],
    }

    pub struct sgx_sealed_data_t {
        pub key_request: sgx_key_request_t,
        pub plain_text_offset: uint32_t,
        pub reserved: [uint8_t; 12],
	pub aes_data: sgx_aes_gcm_data_t,
    }
}
*/


#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct EncryptedData {
    payload_data: SgxPayload,
}

impl EncryptedData {
    pub fn new() -> Self {
        EncryptedData::default()
    }
    pub fn get_payload_size(&self) -> u32 {
        self.payload_data.payload_size
    }
    pub fn get_payload_tag(&self) -> &[u8; SGX_SEAL_TAG_SIZE] {
        &self.payload_data.payload_tag
    }

    pub fn get_encrypt_txt(&self) -> &[u8] {
        &*self.payload_data.encrypt
    }
    pub fn get_additional_txt(&self) -> &[u8] {
        &*self.payload_data.additional
    }

    pub fn calc_raw_sealed_data_size(add_mac_txt_size: u32, encrypt_txt_size: u32) -> u32 {
        let max = u32::MAX;
        let sealed_data_size = mem::size_of::<sgx_sealed_data_t>() as u32;

        if add_mac_txt_size > max - encrypt_txt_size {
            return max;
        }
        let payload_size: u32 = add_mac_txt_size + encrypt_txt_size;
        if payload_size > max - sealed_data_size {
            return max;
        }
        sealed_data_size + payload_size
    }

    pub fn get_add_mac_txt_len(&self) -> u32 {
        let data_size = self.payload_data.additional.len();
        if data_size > self.payload_data.payload_size as usize
            || data_size >= u32::MAX as usize
        {
            u32::MAX
        } else {
            data_size as u32
        }
    }

    pub fn get_encrypt_txt_len(&self) -> u32 {
        let data_size = self.payload_data.encrypt.len();
        if data_size > self.payload_data.payload_size as usize
            || data_size >= u32::MAX as usize
        {
            u32::MAX
        } else {
            data_size as u32
	}
    }


    pub fn try_from(additional_text: &[u8], encrypt_text: &[u8],
    payload_iv: &[u8], encrypt_key: &mut sgx_align_key_128bit_t) -> SgxResult<Self> {

	let mut enc_data = Self::new();
	enc_data.payload_data.encrypt = vec![0_u8; encrypt_text.len()].into_boxed_slice();

	let error = rsgx_rijndael128GCM_encrypt(
            &encrypt_key.key,
            encrypt_text,
            payload_iv,
            &additional_text,
            &mut enc_data.payload_data.encrypt,
            &mut enc_data.payload_data.payload_tag,
	);
	if error.is_err() {
            return Err(error.unwrap_err());
	}
	
	enc_data.payload_data.payload_size = (encrypt_text.len() + additional_text.len()) as u32;
	if !additional_text.is_empty() {
            enc_data.payload_data.additional = additional_text.to_vec().into_boxed_slice();
	}
		
	Ok(enc_data)
    }
    
    pub fn unencrypt(&self, encrypt_key: &mut sgx_align_key_128bit_t) -> SgxResult<UnencryptedData> {
	//
        // code that calls sgx_unseal_data commonly does some sanity checks
        // related to plain_text_offset.  We add fence here since we don't
        // know what crypto code does and if plain_text_offset-related
        // checks mispredict the crypto code could operate on unintended data
        //
        rsgx_lfence();

        let payload_iv = [0_u8; SGX_SEAL_IV_SIZE];
        let mut unsealed_data: UnencryptedData = UnencryptedData::default();
        unsealed_data.decrypt = vec![0_u8; self.payload_data.encrypt.len()].into_boxed_slice();

        let error = rsgx_rijndael128GCM_decrypt(
            &encrypt_key.key,
            self.get_encrypt_txt(),
            &payload_iv,
            self.get_additional_txt(),
            self.get_payload_tag(),
            &mut unsealed_data.decrypt,
        );
        if error.is_err() {
	        println!("error: {}", error.unwrap_err());
            return Err(error.unwrap_err());
        }

        if self.payload_data.additional.len() > 0 {
            unsealed_data.additional = self.get_additional_txt().to_vec().into_boxed_slice();
        }
        unsealed_data.payload_size = self.get_payload_size();


        Ok(unsealed_data)
    }


    pub unsafe fn to_raw_sealed_data_t(
        &self,
        p: *mut sgx_sealed_data_t,
        len: u32,
    ) -> Option<*mut sgx_sealed_data_t> {
        if p.is_null() {
            return None;
        }
        if !rsgx_raw_is_within_enclave(p as *mut u8, len as usize)
            && !rsgx_raw_is_outside_enclave(p as *mut u8, len as usize)
        {
            return None;
        }

        let additional_len = self.get_add_mac_txt_len();
        let encrypt_len = self.get_encrypt_txt_len();
        if (additional_len == u32::MAX) || (encrypt_len == u32::MAX) {
            return None;
        }
        if (additional_len + encrypt_len) != self.get_payload_size() {
            return None;
        }

        let sealed_data_size = sgx_calc_sealed_data_size(additional_len, encrypt_len);
        if sealed_data_size == u32::MAX {
            return None;
        }
        if len < sealed_data_size {
            return None;
        }

        let ptr_sealed_data = p as *mut u8;
        let ptr_encrypt = ptr_sealed_data.add(mem::size_of::<sgx_sealed_data_t>());
        if encrypt_len > 0 {
            ptr::copy_nonoverlapping(
                self.payload_data.encrypt.as_ptr(),
                ptr_encrypt,
                encrypt_len as usize,
            );
        }
        if additional_len > 0 {
            let ptr_additional = ptr_encrypt.offset(encrypt_len as isize);
            ptr::copy_nonoverlapping(
                self.payload_data.additional.as_ptr(),
                ptr_additional,
                additional_len as usize,
            );
        }

        let raw_sealed_data = &mut *p;
	raw_sealed_data.key_request = sgx_key_request_t::default();
        raw_sealed_data.plain_text_offset = encrypt_len;
        raw_sealed_data.aes_data.payload_size = self.payload_data.payload_size;
        raw_sealed_data.aes_data.payload_tag = self.payload_data.payload_tag;

        Some(p)
    }


    #[allow(clippy::cast_ptr_alignment)]
    pub unsafe fn from_raw_sealed_data_t(p: *const sgx_sealed_data_t, len: u32) -> Option<Self> {
        if p.is_null() {
            return None;
        }
        if !rsgx_raw_is_within_enclave(p as *mut u8, len as usize)
            && !rsgx_raw_is_outside_enclave(p as *mut u8, len as usize)
        {
            return None;
        }

        if (len as usize) < mem::size_of::<sgx_sealed_data_t>() {
            return None;
        }

        let raw_encrypted_data = &*p;
        if raw_encrypted_data.plain_text_offset > raw_encrypted_data.aes_data.payload_size {
            return None;
        }

        let ptr_encrypted_data = p as *mut u8;
        let additional_len = sgx_get_add_mac_txt_len(ptr_encrypted_data as *const sgx_sealed_data_t);
        let encrypt_len = sgx_get_encrypt_txt_len(ptr_encrypted_data as *const sgx_sealed_data_t);
        if (additional_len == u32::MAX) || (encrypt_len == u32::MAX) {
            return None;
        }
        if (additional_len + encrypt_len) != raw_encrypted_data.aes_data.payload_size {
            return None;
        }

        let encrypted_data_size = sgx_calc_sealed_data_size(additional_len, encrypt_len);
        if encrypted_data_size == u32::MAX {
            return None;
        }
        if len < encrypted_data_size {
            return None;
        }

        let ptr_encrypt = ptr_encrypted_data.add(mem::size_of::<sgx_sealed_data_t>());

        let encrypt: Vec<u8> = if encrypt_len > 0 {
            let mut temp: Vec<u8> = Vec::with_capacity(encrypt_len as usize);
            temp.set_len(encrypt_len as usize);
            ptr::copy_nonoverlapping(
                ptr_encrypt as *const u8,
                temp.as_mut_ptr(),
                encrypt_len as usize,
            );
            temp
        } else {
            Vec::new()
        };

        let additional: Vec<u8> = if additional_len > 0 {
            let ptr_additional = ptr_encrypt.offset(encrypt_len as isize);
            let mut temp: Vec<u8> = Vec::with_capacity(additional_len as usize);
            temp.set_len(additional_len as usize);
            ptr::copy_nonoverlapping(
                ptr_additional as *const u8,
                temp.as_mut_ptr(),
                additional_len as usize,
            );
            temp
        } else {
            Vec::new()
        };

        let mut encrypted_data = Self::default();
        encrypted_data.payload_data.payload_size = raw_encrypted_data.aes_data.payload_size;
        encrypted_data.payload_data.payload_tag = raw_encrypted_data.aes_data.payload_tag;
        encrypted_data.payload_data.additional = additional.into_boxed_slice();
        encrypted_data.payload_data.encrypt = encrypt.into_boxed_slice();

        Some(encrypted_data)
    }

}

#[derive(Clone, Default)]
pub struct UnencryptedData {
    pub payload_size: u32,
    pub decrypt: Box<[u8]>,
    pub additional: Box<[u8]>,
}

impl UnencryptedData {
    ///
    /// Get the payload size of the UnencryptedData.
    ///
    #[allow(dead_code)]
    pub fn get_payload_size(&self) -> u32 {
        self.payload_size
    }
    ///
    /// Get the pointer of decrypt buffer in UnencryptedData.
    ///
    #[allow(dead_code)]
    pub fn get_decrypt_txt(&self) -> &[u8] {
        &*self.decrypt
    }
    ///
    /// Get the pointer of additional buffer in UnencryptedData.
    ///
    #[allow(dead_code)]
    pub fn get_additional_txt(&self) -> &[u8] {
        &*self.additional
    }
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


#[derive(Serialize, Deserialize, Default)]
pub struct DHMsg3 {
    #[serde(with = "DHMsg3Def")]
    pub inner: sgx_dh_msg3_t,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_dh_msg1_t")]
struct DHMsg1Def {
    #[serde(with = "EC256PublicDef")]
    pub g_a: sgx_ec256_public_t,
    #[serde(with = "TargetInfoDef")]
    pub target: sgx_target_info_t,
}

#[derive(Serialize, Deserialize)]
#[serde(remote = "sgx_ec256_public_t")]
struct EC256PublicDef {
    #[serde(serialize_with = "<[_]>::serialize")]
    pub gx: [uint8_t; SGX_ECP256_KEY_SIZE],
    #[serde(serialize_with = "<[_]>::serialize")]
    pub gy: [uint8_t; SGX_ECP256_KEY_SIZE],
}

#[derive(Serialize, Deserialize, Debug)]
pub struct KeyGenMsg2 {
    pub shared_key_id: Uuid,
    pub dlog_proof: DLogProof,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignMsg1 {
    pub shared_key_id: Uuid,
    pub eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KUSendMsg {        // Sent from server to lockbox                                                                                                                                                                                                                             
    pub user_id: Uuid,
    pub statechain_id: Uuid,
    pub x1: FE,
    pub t2: Vec<u8>,
    pub o2_pub: GE,
}
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct KUReceiveMsg {      // Sent from lockbox back to server                                                                                                                                                                                                                       
    pub s2_pub: GE,
}


/// State Entity protocols
#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq)]
pub enum Protocol {
    Deposit,
    Transfer,
    Withdraw,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignSecondMsgRequest {
    pub protocol: Protocol,
    pub message: BigInt,
    pub party_two_sign_message: SignMessage,
}

#[derive(Serialize, Deserialize, Debug)]
pub struct SignMsg2 {
    pub shared_key_id: Uuid,
    pub sign_second_msg_request: SignSecondMsgRequest,
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

mod party_two {
    use super::{BigInt, GE, ECDDHProof};
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct EphKeyGenFirstMsg {
	pub pk_commitment: BigInt,
	pub zk_pok_commitment: BigInt,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct EphKeyGenSecondMsg {
	pub comm_witness: EphCommWitness,
    }

    
    #[derive(Clone, Debug, Serialize, Deserialize)]
    pub struct EphCommWitness {
	pub pk_commitment_blind_factor: BigInt,
	pub zk_pok_blind_factor: BigInt,
	pub public_share: GE,
	pub d_log_proof: ECDDHProof,
	pub c: GE, //c = secret_share * base_point2
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct PartialSig {
	pub c3: BigInt,
    }
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
	EC_LOG_SIZE
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
	EC_LOG_SIZE
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
	let sealed_data = match item.to_sealed(){
	    Ok(v) => v,
	    Err(e) => return Err(e)
	};
	let mut sealed_log  = Self::default();

	let opt = to_sealed_log_for_slice(&sealed_data, (*sealed_log).as_mut_ptr(), Self::size() as u32);
	if opt.is_none() {
            return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
	}
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

//#[derive(Serialize, Deserialize, Clone, Default, Debug)]
//struct SessionKey {
//    inner: sgx_key_128bit_t
//}

#[derive(Serialize, Deserialize, Clone, Debug)]
struct SgxKey128BitSealed {
    inner: sgx_key_128bit_t
}

impl TryFrom<(* mut u8, u32)> for SgxKey128BitSealed {
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


impl TryFrom<SgxKey128BitSealed> for SgxSealable {
    type Error = sgx_status_t;
    fn try_from(item: SgxKey128BitSealed) -> Result<Self, Self::Error> {
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

impl TryFrom<SgxSealable> for SgxKey128BitSealed {
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
struct FESealed {
    inner: FE
}

impl TryFrom<(* mut u8, u32)> for FESealed {
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

impl TryFrom<FESealed> for SgxSealable {
    type Error = sgx_status_t;
    fn try_from(item: FESealed) -> Result<Self, Self::Error> {
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

impl TryFrom<SgxSealable> for FESealed {
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

#[derive(Serialize, Deserialize, Clone, Debug)]
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

    pub fn create_commitments_with_fixed_secret_share(
        mut secret_share: FE,
    ) -> (KeyGenFirstMsg, CommWitness, EcKeyPair) {
        let base: GE = ECPoint::generator();



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
    party2_public: GE,
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
    shared_key: MasterKey1,
    eph_key_gen_first_message_party_two: party_two::EphKeyGenFirstMsg,
    eph_ec_key_pair_party1: EphEcKeyPair,
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


#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct KeyupdateSealed {
    s2: FE,
}

impl TryFrom<(* mut u8, u32)> for KeyupdateSealed {
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

impl TryFrom<KeyupdateSealed> for SgxSealable {
    type Error = sgx_status_t;
    fn try_from(item: KeyupdateSealed) -> Result<Self, Self::Error> {
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

impl TryFrom<SgxSealable> for KeyupdateSealed {
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

#[allow(non_snake_case)]
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

#[allow(non_snake_case)]
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
    #[allow(non_snake_case)]
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

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct MasterKey1 {
    pub public: Party1Public,
    pub private: Party1Private,
    chain_code: BigInt,
}

mod party_one {
    use super::*;

    #[derive(Debug, Serialize, Deserialize)]
    pub struct Signature {
	pub s: BigInt,
	pub r: BigInt,
    }

    impl Signature {
	pub fn compute_with_recid(
            party_one_private: &Party1Private,
            partial_sig_c3: &BigInt,
	    ephemeral_local_share: &EphEcKeyPair,
            ephemeral_other_public_share: &GE,
	) -> SignatureRecid {
            //compute r = k2* R1                                                                                                                                                                                                                                                             
            let r = ephemeral_other_public_share
		.scalar_mul(&ephemeral_local_share.secret_share.get_element());
	    
	    let rx = r.x_coor().unwrap().mod_floor(&FE::q());
            let ry = r.y_coor().unwrap().mod_floor(&FE::q());
            let mut k1_inv = ephemeral_local_share.secret_share.invert();
	    
            let s_tag = Paillier::decrypt(
		&party_one_private.paillier_priv,
		&RawCiphertext::from(partial_sig_c3),
            )
		.0;
            let mut s_tag_fe: FE = ECScalar::from(&s_tag);
            let s_tag_tag = s_tag_fe * k1_inv;
            k1_inv.zeroize();
	    s_tag_fe.zeroize();
            let s_tag_tag_bn = s_tag_tag.to_big_int();
            let s = std::cmp::min(s_tag_tag_bn.clone(), FE::q() - &s_tag_tag_bn);
	    
            /*                                                                                                                                                                                                                                                                               
            Calculate recovery id - it is not possible to compute the public key out of the signature                                                                                                                                                                                       
            itself. Recovery id is used to enable extracting the public key uniquely.                                                                                                                                                                                                       
            1. id = R.y & 1                                                                                                                                                                                                                                                                 
            2. if (s > curve.q / 2) id = id ^ 1                                                                                                                                                                                                                                             
             */
            let is_ry_odd = ry.is_odd();
            let mut recid = if is_ry_odd { 1 } else { 0 };
            if s_tag_tag_bn.clone() > FE::q() - s_tag_tag_bn.clone() {
		recid = recid ^ 1;
            }
	    
            SignatureRecid { s, r: rx, recid }
	}
    }
    
    #[derive(Debug, Serialize, Deserialize)]
    pub struct SignatureRecid {
	pub s: BigInt,
	pub r: BigInt,
	pub recid: u8,
    }

    #[derive(Debug, Serialize, Deserialize)]
    pub struct EphKeyGenSecondMsg {}

}

#[derive(Debug, Serialize, Deserialize)]
pub struct SignMessage {
    pub partial_sig: party_two::PartialSig,
    pub second_message: party_two::EphKeyGenSecondMsg,
}

#[derive(Copy, PartialEq, Eq, Clone, Debug)]
pub enum Errors {
    KeyGenError,
    SignError,
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
    
    pub fn sign_second_message(
        &self,
        party_two_sign_message: &SignMessage,
        _eph_key_gen_first_message_party_two: &party_two::EphKeyGenFirstMsg,
        eph_ec_key_pair_party1: &EphEcKeyPair,
        _message: &BigInt,
    ) -> Result<party_one::SignatureRecid, Errors> {
        let signature_with_recid = party_one::Signature::compute_with_recid(
            &self.private,
            &party_two_sign_message.partial_sig.c3,
            &eph_ec_key_pair_party1,
            &party_two_sign_message
                .second_message
                .comm_witness
                .public_share,
        );
	Ok(signature_with_recid)
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
    let rust_raw_string = "<-This is a in-Enclave ";
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
pub extern "C" fn get_self_report(p_report: &mut sgx_report_t) -> sgx_status_t {

    let self_report = sgx_tse::rsgx_self_report();

    *p_report = self_report;
    
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn create_sealed_random_bytes32(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {
    
    let data = match Bytes32::new_random(){
          Ok(v) => v,
        Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
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

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn verify_sealed_bytes32(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {

    let _data = match Bytes32::try_from((sealed_log, sealed_log_size)) {
	Ok(v) => v,
	Err(e) => return e
    };
    
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn set_ec_key(sealed_log: * mut u8) -> sgx_status_t {

    let data = match SgxKey128BitSealed::try_from((sealed_log, SgxSealedLog::size() as u32)) {
        Ok(v) => v,
	    Err(e) => return e
    };

    match ECKEY.lock() {
	    Ok(mut ec_key) => {
	        let mut key_align = sgx_align_key_128bit_t::default();
	        key_align.key = data.inner;
	        *ec_key = key_align;
	        sgx_status_t::SGX_SUCCESS
	    },
	    Err(_) => sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    }
}

#[no_mangle]
pub extern "C" fn get_ec_key(sealed_log: * mut u8) -> sgx_status_t {

    match ECKEY.lock() {
        Ok(ec_key) => {
       
            let key_sealed  = SgxKey128BitSealed {
                inner: ec_key.key
            };
            
            let sealable = match SgxSealable::try_from(key_sealed){
            Ok(x) => x,
                Err(_) => return  sgx_status_t::SGX_ERROR_INVALID_PARAMETER
            };
        
            let sealed_data = match sealable.to_sealed(){
                Ok(x) => x,
            Err(_) => return  sgx_status_t::SGX_ERROR_INVALID_PARAMETER
            };
            
            let opt = to_sealed_log_for_slice(&sealed_data, sealed_log, EC_LOG_SIZE as u32);
            if opt.is_none() {
            return  sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
            }
            sgx_status_t::SGX_SUCCESS
        
        },
        Err(_) => sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    }

}

#[no_mangle]
pub extern "C" fn create_sealed_random_fe(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {

    let secret_share: FE = ECScalar::new_random();

    let fes = FESealed { inner: secret_share }; 
    
    let sealable = match SgxSealable::try_from(fes){
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
    
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn verify_sealed_fe(sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t {

    match FESealed::try_from((sealed_log, sealed_log_size)) {
	Ok(_) => sgx_status_t::SGX_SUCCESS,
	Err(e) => e
    }

}

#[no_mangle]
pub extern "C" fn create_ec_random_fe(ec_log: * mut u8) -> sgx_status_t {

    let secret_share: FE = ECScalar::new_random();
    let fes = FESealed { inner: secret_share };

    let fes_vec = match serde_cbor::to_vec(&fes){
	    Ok(r) => r,
	    Err(e) => {
	        println!("error: {:?}", e);
	        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	    },
    };

    match encrypt(&fes_vec){
	Ok(ed) => {

	    let opt = to_encrypted_log_for_slice(&ed, ec_log, EC_LOG_SIZE as u32);
	    if opt.is_none() {
		return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
	    }
	    
	    sgx_status_t::SGX_SUCCESS
	},
	Err(e) => {
	    println!("error: {:?}", e);
	    sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	},
    }
}

#[no_mangle]
pub extern "C" fn verify_ec_fe(ec_log_in: * const u8, ec_log_in_len: u32) -> sgx_status_t {

    //let slice = unsafe { slice::from_raw_parts(ec_log_in, ec_log_in_len as usize)};
    match from_encrypted_log_for_slice(ec_log_in, ec_log_in_len) {
	Some(encrypted) => {
	    match unencrypt(&encrypted){
		    Ok(_) =>     sgx_status_t::SGX_SUCCESS,
		    _ =>     sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
	    }
	},
	None =>  sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    }
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


    // First, build a slice for input_str
    let input_slice = unsafe { slice::from_raw_parts(input_str, some_len) };

    // slice::from_raw_parts does not guarantee the length, we need a check
    if input_slice.len() != some_len {
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

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
pub extern "C" fn generate_keypair(_input_str: *const u8) -> sgx_status_t {

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

    let _pubkey = libsecp256k1::PublicKey::from_secret_key(&privkey);

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
    
    match sk1.tweak_add_assign(&sk2){
	Ok(_) => (),
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
    
    match sk1.tweak_mul_assign(&sk2){
	Ok(_) => (),
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

    let (signature, _recovery_id) = libsecp256k1::sign(&message, &sk);

    *sig = signature.serialize();

    sgx_status_t::SGX_SUCCESS
}


#[no_mangle]
pub extern "C" fn get_public_key(sealed_log: * mut u8, public_key: &mut[u8;33]) -> sgx_status_t {

    let data = match Bytes32::try_from((sealed_log, SgxSealedLog::size() as u32)) {
	Ok(v) => v,
	Err(e) => return e
    };

    let sk = match libsecp256k1::SecretKey::parse(&data){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    };
    
    *public_key = libsecp256k1::PublicKey::from_secret_key(&sk).serialize_compressed();
    
    sgx_status_t::SGX_SUCCESS
}

fn raw_encrypted_to_decrypted(raw_enc: * mut u8, raw_enc_len: usize) -> SgxResult<UnencryptedData> {
//    let slice = unsafe { slice::from_raw_parts(raw_enc, EC_LOG_SIZE)};
    match from_encrypted_log_for_slice(raw_enc, raw_enc_len as u32) {
        
	    Some(encrypted) => {
	        unencrypt(&encrypted)
	    },
	    None =>  {
            Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
        },

    }
}

#[no_mangle]
pub extern "C" fn first_message(sealed_log_in: * mut u8, sealed_log_out: * mut u8,
				key_gen_first_msg: &mut [u8;256]) -> sgx_status_t {
    if let Ok(ud) = raw_encrypted_to_decrypted(sealed_log_in, EC_LOG_SIZE) {
	match serde_cbor::from_slice::<FESealed>(&ud.decrypt){
	    Ok(r) => {
		let mut secret_share = r.inner;
		return first_message_common(&mut secret_share, sealed_log_out, key_gen_first_msg)
	    },
	    Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	};
    };
    sgx_status_t::SGX_ERROR_INVALID_PARAMETER
}

#[no_mangle]
pub extern "C" fn first_message_transfer(sealed_log_in: * mut u8, sealed_log_out: *mut u8,
				key_gen_first_msg: &mut [u8;256]) -> sgx_status_t {

    let data = match KeyupdateSealed::try_from((sealed_log_in, SgxSealedLog::size() as u32)) {
        Ok(v) => v,
	Err(e) => return e
    };

    let mut secret_share = data.s2;

    first_message_common(&mut secret_share, sealed_log_out, key_gen_first_msg)
}

#[no_mangle]
pub extern "C" fn test_sc_encrypt_unencrypt() -> sgx_status_t {

    let test_vec = test_vec();
    match encrypt(&test_vec) {
	Ok(ed) => {	    
	    match *test_vec.as_slice() == *(ed.payload_data.encrypt) {
		false => (),
		true => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
	    };
	    let ud = match unencrypt(&ed) {
		Ok(ud) => ud,
		Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
	    };
	    match *test_vec.as_slice() == *(ud.decrypt) {
		true => sgx_status_t::SGX_SUCCESS,
		false => sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
	    }
	}
	,
	Err(ret) => return ret
    }
}

#[no_mangle]
pub extern "C" fn set_session_enclave_key(sealed_log_in: *const u8) -> sgx_status_t {
    
    match is_initialized() { 
        Ok(true) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
        Ok(false) => (),
        Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };

    match from_encrypted_log_for_slice(sealed_log_in, EC_LOG_SIZE as u32) {
        Some(encrypted) => {
            match session_unencrypt(&encrypted){
                Ok(r) =>     {
                    match ECKEY.lock(){
                        Ok(mut k) => {
                            *k = sgx_align_key_128bit_t::default();
                            k.key = match serde_cbor::from_slice(&(*r.decrypt)){
                                Ok(r) => r,
                                Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
                            };
                            set_initialized();
                            return sgx_status_t::SGX_SUCCESS
                        },
                        Err(e) => {
                            println!("error: {:?}", e);
                            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
                        }
                    }
            },
            _ =>  return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
            }
        },
        None =>  return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    }
}

fn encrypt(encrypt: &[u8]) -> SgxResult<EncryptedData> {
    match ECKEY.lock() {
	    Ok(mut k) => {
	        EncryptedData::try_from(&[], encrypt, &[0;12], &mut k)
	    },
	    Err(e) => {
	        println!("error: {:?}", e);
	        Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
	    }
    }
}

fn unencrypt(encrypt: &EncryptedData) -> SgxResult<UnencryptedData> {
    match ECKEY.lock() {
	Ok(mut k) => {
	    encrypt.unencrypt(&mut k) 
	},
	Err(_) => {
        Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
        }
    }
}

fn session_unencrypt(encrypt: &EncryptedData) -> SgxResult<UnencryptedData> {
    match SESSIONKEY.lock() {
	    Ok(mut k) => {
            encrypt.unencrypt(&mut k) 
	    },
	    Err(_) => {
            Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER)
        }
    }
}

#[no_mangle]
pub extern "C" fn test_encrypt_to_out(sealed_log_out: *mut u8 ) -> sgx_status_t {

    let test_vec = test_vec();

    match encrypt(&test_vec) {
	Ok(ed) => {
	    let opt = to_encrypted_log_for_slice(&ed, sealed_log_out, EC_LOG_SIZE as u32);
	    if opt.is_none() {
		return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
	    }
	},
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
    }
    
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn test_in_to_decrypt(data_in: *const u8, data_len: usize) -> sgx_status_t 
{
    let str_slice = unsafe { slice::from_raw_parts(data_in, data_len)};

    let encrypted_data_str = match std::str::from_utf8(&str_slice) {
	Ok(r) => r,
	Err(e) => {
	    let _ = io::stdout().write(format!("encrypted data str error: {:?}", e).as_str().as_bytes());
	    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	}
    };

    let encrypted_data: EncryptedData = match serde_json::from_str(&encrypted_data_str){
        Ok(r) => r,
        Err(e) => {
	    let _ = io::stdout().write(format!("encrypted data error: {:?}", e).as_str().as_bytes());
	    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	}
    };

    match unencrypt(&encrypted_data) {
	    Ok(ud) => {
	        match *test_vec().as_slice() == *(ud.decrypt) {
		        true => sgx_status_t::SGX_SUCCESS,
		        false => sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
		    }
	    },
	    Err(e) => {
	        println!("error: {:?}", e);
	        sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	    }
    }
}


fn first_message_common( secret_share: &mut FE, sealed_log_out: *mut u8,
                         key_gen_first_msg: &mut [u8;256]) -> sgx_status_t {
    

    let (key_gen_first_message, comm_witness, ec_key_pair) =
	KeyGenFirstMsg::create_commitments_with_fixed_secret_share(*secret_share);

    //------

    let first_message_sealed = FirstMessageSealed { comm_witness, ec_key_pair };

    let fms_vec = match serde_cbor::to_vec(&first_message_sealed){
	    Ok(r) => r,
	    Err(e) => {
	        println!("error: {:?}", e);
	        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	    },
    };

    match encrypt(fms_vec.as_slice()){
	    Ok(ed) => {
	        let opt = to_encrypted_log_for_slice(&ed, sealed_log_out, EC_LOG_SIZE as u32);
	        if opt.is_none() {
		        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
	        }
	    },
	    Err(e) => {
	        println!("error: {:?}", e);
	        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	    },
    };

    
    let key_gen_first_message_str = match serde_json::to_string(&key_gen_first_message){
	Ok(v) => v,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    };

    let len = key_gen_first_message_str.len();
    let mut plain_str_sized=format!("{}", len);
    plain_str_sized=format!("{}{}", plain_str_sized.len(),plain_str_sized);
    plain_str_sized.push_str(&key_gen_first_message_str);

    let mut plain_bytes=plain_str_sized.into_bytes();
    plain_bytes.resize(256,0);

    *key_gen_first_msg  = match plain_bytes.as_slice().try_into(){
	Ok(x) => x,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    };

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn second_message(sealed_log_in: * mut u8, sealed_log_out: * mut u8,
				 msg2_str: *const u8, len: usize,
				 kg_party_one_second_message: &mut [u8;480000] 
) -> sgx_status_t {

    let str_slice = unsafe { slice::from_raw_parts(msg2_str, len) };
    
    let key_gen_msg2: KeyGenMsg2 = match std::str::from_utf8(&str_slice) {
	Ok(v) =>{
            match serde_json::from_str(v){
		Ok(v) => v,
		Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
            }
	},
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    };
    
    let party2_public: GE = key_gen_msg2.dlog_proof.pk.clone();
    
    if let Ok(ud) = raw_encrypted_to_decrypted(sealed_log_in, EC_LOG_SIZE) {
	match serde_cbor::from_slice::<FirstMessageSealed>(&ud.decrypt){
	    Ok(data) => {
		let comm_witness = data.comm_witness;
		let comm_witness_public_share = comm_witness.public_share.clone();
		let ec_key_pair = &data.ec_key_pair;
		
		let key_gen_second_message = 
                    KeyGenSecondMsg { comm_witness };
		
		let (ek, dk) = Paillier::keypair().keys();
		let randomness = Randomness::sample(&ek);
		
		let encrypted_share = Paillier::encrypt_with_chosen_randomness(
                    &ek,
                    RawPlaintext::from(ec_key_pair.secret_share.to_big_int()),
                    &randomness,
		).0.into_owned();
		
		let paillier_key_pair = PaillierKeyPair{ ek, dk: dk.clone(), encrypted_share, randomness: randomness.0.clone()};
		
		let party_one_private = Party1Private {
		    x1: ec_key_pair.secret_share,
		    paillier_priv: dk,
		    c_key_randomness: randomness.0,
		};
		
		
		let (pdl_statement, pdl_proof, composite_dlog_proof) =
		    PaillierKeyPair::pdl_proof(&party_one_private, &paillier_key_pair);
				
		let correct_key_proof = NICorrectKeyProof::proof(&paillier_key_pair.dk);
		
		let second_message =  KeyGenParty1Message2 {
		    ecdh_second_message: key_gen_second_message,
		    ek: paillier_key_pair.ek.clone(),
		    c_key: paillier_key_pair.encrypted_share.clone(),
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
		plain_str_sized=format!("{}{}", plain_str_sized.len(), plain_str_sized);
		plain_str_sized.push_str(&plain_str);
		
		let mut plain_bytes=plain_str_sized.into_bytes();
		plain_bytes.resize(480000,0);
		
		*kg_party_one_second_message  = match plain_bytes.as_slice().try_into(){
		    Ok(x) => x,
		    Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
		};
	    
		let master_key = MasterKey1::set_master_key(
		    &BigInt::from(0),
		    party_one_private.clone(),
		    &comm_witness_public_share,
		    &party2_public,
		    paillier_key_pair.clone(),
		);
		
		let second_message_sealed =  SecondMessageSealed {
		    paillier_key_pair: paillier_key_pair,
		    party_one_private,
		    party2_public,
		    master_key
		};

		let sms_vec = match serde_cbor::to_vec(&second_message_sealed){
		    Ok(r) => r,
		    Err(e) => {
			    println!("error: {:?}", e);
			    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
		    },
		};

		match encrypt(sms_vec.as_slice()){
		    Ok(ed) => {
			    let opt = to_encrypted_log_for_slice(&ed, sealed_log_out, EC_LOG_SIZE as u32);
			    if opt.is_none() {
			        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
			    }
		    },
		    Err(e) => {
			    println!("error: {:?}", e);
			    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
		    },
		};
		
		return sgx_status_t::SGX_SUCCESS
	    },
	    Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	};
    }
    
    sgx_status_t::SGX_ERROR_INVALID_PARAMETER
}


#[no_mangle]
pub extern "C" fn sign_first(sealed_log_in: * mut u8, sealed_log_out: * mut u8,
			     sign_msg1_str: *const u8, len: usize,
			     sign_party_one_first_message: &mut [u8;480000]) -> sgx_status_t {
    
    let str_slice = unsafe { slice::from_raw_parts(sign_msg1_str, len) };

    let sign_msg1_str = match std::str::from_utf8(&str_slice) {
	Ok(r) => r,
	Err(e) => {
	    let _ = io::stdout().write(format!("error: {:?}", e).as_str().as_bytes());
	    println!("error: {:?}", e);
	    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	}
    };

    let sign_msg1: SignMsg1 = match serde_json::from_str(&sign_msg1_str){
        Ok(r) => r,
        Err(e) => {
	    let _ = io::stdout().write(format!("error: {:?}", e).as_str().as_bytes());
	    println!("error: {:?}", e);
	    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	}
    };

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
    plain_str_sized=format!("{}{}", plain_str_sized.len(), plain_str_sized);
    plain_str_sized.push_str(&plain_str);

    let mut plain_bytes=plain_str_sized.into_bytes();
    plain_bytes.resize(480000,0);

    *sign_party_one_first_message  = match plain_bytes.as_slice().try_into(){
	Ok(x) => x,
	Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    };
    
    if let Ok(ud) = raw_encrypted_to_decrypted(sealed_log_in, EC_LOG_SIZE) {
	match serde_cbor::from_slice::<SecondMessageSealed>(&ud.decrypt){
	    Ok(data) => {

		let sign_first_sealed =  SignFirstSealed {
		    shared_key: data.master_key,
		    eph_key_gen_first_message_party_two: sign_msg1.eph_key_gen_first_message_party_two,
		    eph_ec_key_pair_party1: eph_ec_key_pair_party1,
		};

		let sfs_vec = match serde_cbor::to_vec::<SignFirstSealed>(&sign_first_sealed) {
		    Ok(r) => r,
		    Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
		};

		match encrypt(sfs_vec.as_slice()){
		    Ok(ed) => {
			    let opt = to_encrypted_log_for_slice(&ed, sealed_log_out, EC_LOG_SIZE as u32);
			    if opt.is_none() {
			        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
			    }
		    },
		    Err(e) => {
			    println!("error: {:?}", e);
			    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
		    },
		};
		
		return sgx_status_t::SGX_SUCCESS
		
	    },
	    Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	};
    };

    sgx_status_t::SGX_ERROR_INVALID_PARAMETER
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct SignSecondOut {
    inner: Vec<Vec<u8>>
}


#[no_mangle]
pub extern "C" fn sign_second(sealed_log_in: * mut u8, _sealed_log_out: * mut u8,
			      sign_msg2_str: * mut u8,
			      len: usize,
			      plain_out:  &mut [u8;480000]) -> sgx_status_t {

    let str_slice = unsafe { slice::from_raw_parts(sign_msg2_str, len) };
    let sign_msg2: SignMsg2 = match std::str::from_utf8(&str_slice) {
        Ok(v) =>{
            match serde_json::from_str(v){
                Ok(v) => v,
                Err(_) => {
		    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
		}
            }
        },
        Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
    };

    
    if let Ok(ud) = raw_encrypted_to_decrypted(sealed_log_in, EC_LOG_SIZE) {

	match serde_cbor::from_slice::<SignFirstSealed>(&ud.decrypt){
            Ok(ssi) => {
		let signature = match ssi.shared_key.sign_second_message(
		    &sign_msg2.sign_second_msg_request.party_two_sign_message,
		    &ssi.eph_key_gen_first_message_party_two,
		    &ssi.eph_ec_key_pair_party1,
		    &sign_msg2.sign_second_msg_request.message,
		) {
		    Ok(sig) => sig,
		    Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
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
		let s = Secp256k1::new();
		let mut sig_vec = match secp256k1::Signature::from_compact(&s, &v[..]){
		    Ok(x) => x.serialize_der(&s).to_vec(),
		    Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
		};
		sig_vec.push(01);
		let pk_vec = ssi.shared_key.public.q.get_element().serialize().to_vec();
		let witness = vec![sig_vec, pk_vec];
		let ws: Vec<Vec<u8>> = witness;
		
		let output = SignSecondOut { inner: ws };
		
		let plain_str = serde_json::to_string(&output).unwrap();
		
		let len = plain_str.len();
		let mut plain_str_sized=format!("{}", len);
		plain_str_sized=format!("{}{}", plain_str_sized.len(), plain_str_sized);
		plain_str_sized.push_str(&plain_str);
		
		let mut plain_bytes=plain_str_sized.into_bytes();
		plain_bytes.resize(480000,0);
		
		*plain_out  = match plain_bytes.as_slice().try_into(){
		    Ok(x) => x,
		    Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
		};
		
		return sgx_status_t::SGX_SUCCESS


	    }
            Err(_e) => {
                return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
            }
        }
    };
    
    sgx_status_t::SGX_ERROR_INVALID_PARAMETER
}

#[no_mangle]
pub extern "C" fn keyupdate_first(sealed_log_in: * mut u8, sealed_log_out: * mut u8,
			     receiver_msg: *const u8, len: usize,
			     plain_out: &mut EcLog) -> sgx_status_t {
    
    let str_slice = unsafe { slice::from_raw_parts(receiver_msg, len) };
    let receiver_msg_str = match std::str::from_utf8(&str_slice) {
	Ok(r) => r,
	Err(e) => {
	    let _ = io::stdout().write(format!("error: {:?}", e).as_str().as_bytes());
	    println!("error: {:?}", e);
	    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	}
    };
    let rec_msg: KUSendMsg = match serde_json::from_str(&receiver_msg_str){
        Ok(r) => r,
        Err(e) => {
	    let _ = io::stdout().write(format!("error: {:?}", e).as_str().as_bytes());
	    println!("error: {:?}", e);
	    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	}
    };


    if let Ok(ud) = raw_encrypted_to_decrypted(sealed_log_in, EC_LOG_SIZE) {
	match serde_cbor::from_slice::<SecondMessageSealed>(&ud.decrypt){
	    Ok(data) => {

		let s1 = data.party_one_private.x1;

        let key_bytes = &hex::decode(&s1.clone().get_element().to_string()).unwrap();

        let t2s = ecies::decrypt(key_bytes, &rec_msg.t2).unwrap();

        let t2: FE = ECScalar::from(&BigInt::from_hex(&hex::encode(&t2s)));

		// derive updated private key share
		let s2 = t2 * (rec_msg.x1.invert()) * s1;

		// Note:
		//  s2 = o1*o2_inv*s1
		//  t2 = o1*x1*o2_inv
		
		let g: GE = ECPoint::generator();
		let s2_pub = g * s2;
		
		let p1_pub = data.party2_public * s1;
		let p2_pub = rec_msg.o2_pub * s2;
		
		// Check P1 = o1_pub*s1 === p2 = o2_pub*s2
		if p1_pub != p2_pub {
		    return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
		}
		
		let rec_msg_out = KUReceiveMsg {
		    s2_pub,
		};
		let plain_str = match serde_json::to_string(&rec_msg_out){
		    Ok(v) => v,
		    Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
		};
		
		let len = plain_str.len();
		let mut plain_str_sized=format!("{}", len);
		plain_str_sized=format!("{}{}", plain_str_sized.len(), plain_str_sized);
		plain_str_sized.push_str(&plain_str);
		
		let mut plain_bytes=plain_str_sized.into_bytes();
		plain_bytes.resize(8192,0);
		*plain_out  = match plain_bytes.as_slice().try_into(){
		    Ok(x) => x,
		    Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
		};
		
		let keyupdate_sealed =  KeyupdateSealed {
		    s2,
		};
		
		let sealable = match SgxSealable::try_from(keyupdate_sealed){
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

		return sgx_status_t::SGX_SUCCESS
	    },
	    Err(_) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER
	};
    };

    sgx_status_t::SGX_ERROR_INVALID_PARAMETER

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


fn to_encrypted_log_for_slice(encrypted_data: &EncryptedData, encrypted_log: * mut u8, encrypted_log_size: u32) -> Option<* mut sgx_sealed_data_t> {
    unsafe {
        encrypted_data.to_raw_sealed_data_t(encrypted_log as * mut sgx_sealed_data_t, encrypted_log_size)
    }
}

fn from_encrypted_log_for_slice(encrypted_log: * const u8, encrypted_log_size: u32) -> Option<EncryptedData> {
    unsafe {
        EncryptedData::from_raw_sealed_data_t(encrypted_log as * const sgx_sealed_data_t, encrypted_log_size)
    }
}



