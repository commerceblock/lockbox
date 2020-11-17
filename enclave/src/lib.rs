// Licensed to the Apache Software Foundation (ASF) under one
// or more contributor license agreements.  See the NOTICE file
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
#[cfg(not(target_env = "sgx"))]
#[macro_use]
extern crate sgx_tstd as std;
extern crate sgx_rand;

use sgx_types::{sgx_status_t, sgx_sealed_data_t, SgxResult};
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

#[macro_use]
extern crate serde_derive;
extern crate serde_cbor;

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


    fn new_random(size: usize) -> SgxResult<Self> {
	if size > SgxSealable::size() {
	    return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
	}

	let mut randVec = Vec::<u8>::new();
	let mut rand = match StdRng::new() {
            Ok(rng) => rng,
            Err(_) => { return Err(sgx_status_t::SGX_ERROR_UNEXPECTED); },
	};
	let mut randVec = vec![0;size];
	let mut randBytes = randVec.as_mut_slice();
	rand.fill_bytes(randBytes);

	match SgxSealable::try_from(randBytes){
	    Ok(v) => Ok(v),
	    Err(_) => return Err(sgx_status_t::SGX_ERROR_UNEXPECTED)
	}
    }
    
    #[inline]
    pub const fn size() -> usize {
	1024
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

impl TryFrom<&[u8]> for SgxSealable {
    type Error = sgx_status_t;
    fn try_from(item: &[u8]) -> Result<Self, Self::Error> {
	if item.len() > Self::size() {
	    return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
	}
	let mut inner = Vec::<u8>::new();
	inner.extend(item.iter());
	Ok(Self{inner})
    }
}

impl TryFrom<&mut [u8]> for SgxSealable {
    type Error = sgx_status_t;
    fn try_from(item: &mut [u8]) -> Result<Self, Self::Error> {
	if item.len() > Self::size() {
	    return Err(sgx_status_t::SGX_ERROR_INVALID_PARAMETER);
	}
	let mut inner = Vec::<u8>::new();
	inner.extend(item.iter());
	Ok(Self{inner})
    }
}

#[derive(Clone, Debug)]
pub struct SgxSealedLog {
    inner: [u8; Self::size()]
}

impl SgxSealedLog{
    #[inline]
    pub const fn size() -> usize {
	1024
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
pub extern "C" fn get_random_sealed_log(sealed_log: * mut u8, rand_size: u32) -> sgx_status_t {

    println!("get sealable...");
    let sealable = match SgxSealable::new_random(rand_size as usize){
	Ok(v) => v,
	Err(e) => return e
    };

    println!("seal...");
    let sealed_data = match sealable.to_sealed() {
	Ok(x) => x,
        Err(ret) => return ret
    };

    println!("sealed log...");
    let opt = to_sealed_log_for_slice(&sealed_data, sealed_log, SgxSealedLog::size() as u32);
    println!("...got sealed log");
    if opt.is_none() {
	println!("sealed log for slice failed 1...");
    }
    if opt.is_none() {
	println!("sealed log for slice failed...");
        return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
    }

    println!("{:?}", sealed_log);

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
pub extern "C" fn verify_sealed_log(sealed_log: * mut u8) -> sgx_status_t {

    let opt = from_sealed_log_for_slice::<u8>(sealed_log, SgxSealedLog::size() as u32);
    println!("sealed data from log");
    let sealed_data = match opt {
        Some(x) => x,
        None => {
            return sgx_status_t::SGX_ERROR_INVALID_PARAMETER;
        },
    };
    println!("unsealed data from sealed data");
    let unsealed_data = match SgxSealable::try_from_sealed(&sealed_data){
        Ok(x) => x,
        Err(ret) => {
            return ret;
        },
    };

//    let data = match  SgxSealable::try_from(unsealed_data) {
//	Ok(v) => v,
//	Err(e) => return sgx_status_t::SGX_ERROR_INVALID_PARAMETER,
//    };

    println!("{:?}", sealed_log);

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
