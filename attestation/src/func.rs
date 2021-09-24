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

//use core::mem;
//use core::sync::atomic::{AtomicPtr, Ordering};

use sgx_types::*;
use std::boxed::Box;
use std::sync::atomic::{AtomicPtr, Ordering};

use types::*;
use err::*;


extern {
    pub fn session_request_ocall(dh_msg1: *mut sgx_dh_msg1_t) -> sgx_status_t;


    pub fn exchange_report_ocall(dh_msg2: *mut sgx_dh_msg2_t,
                                 dh_msg3: *mut sgx_dh_msg3_t) -> sgx_status_t;

    pub fn end_session_ocall() -> sgx_status_t;
}


static CALLBACK_FN: AtomicPtr<()> = AtomicPtr::new(0 as * mut ());

pub fn init(cb: Callback) {
    let ptr = CALLBACK_FN.load(Ordering::SeqCst);
    if ptr.is_null() {
        let ptr: * mut Callback = Box::into_raw(Box::new(cb));
        CALLBACK_FN.store(ptr as * mut (), Ordering::SeqCst);
    }
}

pub fn close_session() -> ATTESTATION_STATUS {
    let ret = 0;
    let status = sgx_status_t::SGX_SUCCESS;
    if status != sgx_status_t::SGX_SUCCESS {
        return ATTESTATION_STATUS::ATTESTATION_SE_ERROR;
    }
    ATTESTATION_STATUS::from_repr(ret as u32).unwrap()
}