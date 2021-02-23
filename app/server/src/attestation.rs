use crate::sgx_types::*;

use crate::config;
use crate::client;

use crate::db::get_db_read_only;

use crate::protocol::requests::{post_lb, get_lb};

use std::convert::TryInto;

use std::fmt;

use crate::shared_lib::structs::{DHMsg1, DHMsg2, DHMsg3, EnclaveIDMsg, ExchangeReportMsg};

use crate::server::Lockbox;

use super::Result;

use rocket_contrib::json::Json;

use rocket::{State, http::Status};

#[no_mangle]
extern "C"
fn session_request_ocall(
    src_enclave_id: sgx_enclave_id_t,
    dest_enclave_id: sgx_enclave_id_t,
    dh_msg1: *mut sgx_dh_msg1_t) -> sgx_status_t {

    println!("\nEntering session request ocall\n");

    let config = config::get_config();

    println!("...getting db...\n");
    let db = get_db_read_only(&config);
    
    //let client_src = client::get_client_src();

    let url: &str = "http://0.0.0.0:8000";
    let client_src = client::Lockbox::new(url.to_string());
    let client_dest = client::Lockbox::new(url.to_string());
    
//    let client_dest = client::get_client_dest();
//    let client_src = client::get_client_src();

    println!("...getting src enclave id...\n");
    let enclave_id_msg = match get_lb::<EnclaveIDMsg>(&client_dest, "attestation/enclave_id") {
	Ok(r) => r,
	Err(e) => {
	    println!("error: {}", &e.to_string());
	    return sgx_status_t::SGX_ERROR_UNEXPECTED;
	},
    };
    println!("...enclave id: {}\n", enclave_id_msg.inner);

//    let inner_slice: &[u8] = unsafe { std::slice::from_raw_parts(dh_msg1 as *const sgx_dh_msg1_t as *const u8, 576) };
//    let dh_msg1_ser = DHMsg1{ inner: inner_slice.to_vec() };


    println!("...requesting session...\n");
    let response: DHMsg1 = match post_lb(&client_src, "attestation/session_request", &enclave_id_msg) {
	Ok(r) => r,
	Err(e) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };

    let inner = response.inner;
    unsafe{
	*dh_msg1 = inner;
    }
    println!("...success\n");
    //    unsafe {sgx_init_quote(ret_ti, ret_gid)}
    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
extern "C"
fn exchange_report_ocall(dh_msg2: *mut sgx_dh_msg2_t,
                         dh_msg3: *mut sgx_dh_msg3_t) -> sgx_status_t {
    println!("Entering exchange_report_ocall\n");

    let client_dest = client::get_client_dest();
    let client_src = client::get_client_src();

    let enclave_id_msg = match get_lb::<EnclaveIDMsg>(&client_src, "attestation/enclave/id") {
	Ok(r) => r,
	Err(e) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };

    
    let er_msg = ExchangeReportMsg {
	src_enclave_id: enclave_id_msg.inner,
	dh_msg2: unsafe{DHMsg2{ inner: *dh_msg2 }}
    };
    //,
//	session_ptr: 0
  //  };
    
    let response: DHMsg3 = match post_lb(&client_dest, "attestation/exchange_report", &er_msg) {
	Ok(r) => r,
	Err(e) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };

//    dh_msg3 = response.as_ptr();

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
extern "C"
fn end_session_ocall() -> sgx_status_t {

    let client_dest = client::get_client_dest();

    match get_lb::<()>(&client_dest, "attestation/end_session") {
	Ok(_) =>  sgx_status_t::SGX_SUCCESS,
	Err(_) =>  sgx_status_t::SGX_ERROR_UNEXPECTED,
    }
}
