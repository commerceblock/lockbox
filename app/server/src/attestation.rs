use crate::sgx_types::*;
use crate::client;
use crate::protocol::requests::{post_lb, get_lb};
use crate::shared_lib::structs::{DHMsg1, DHMsg2, DHMsg3, EnclaveIDMsg, ExchangeReportMsg};
use log::error;

#[no_mangle]
extern "C"
fn session_request_ocall(
    dh_msg1: *mut sgx_dh_msg1_t) -> sgx_status_t {

    let url: &str = "http://0.0.0.0:8000";
    let client_src = client::Lockbox::new(url.to_string());
    let client_dest = client::Lockbox::new(url.to_string());
    
    let enclave_id_msg = match get_lb::<EnclaveIDMsg>(&client_dest, "attestation/enclave_id") {
	    Ok(r) => r,
	    Err(e) => {
	        error!("error: {}", &e.to_string());
	        return sgx_status_t::SGX_ERROR_UNEXPECTED;
	    },
    };


    let response: DHMsg1 = match post_lb(&client_src, "attestation/session_request", &enclave_id_msg) {
	Ok(r) => r,
	Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };

    let inner = response.inner;
    unsafe{
	*dh_msg1 = inner;
    }

    sgx_status_t::SGX_SUCCESS
}

#[no_mangle]
extern "C"
fn exchange_report_ocall(dh_msg2: *mut sgx_dh_msg2_t,
                         _dh_msg3: *mut sgx_dh_msg3_t) -> sgx_status_t {
    
    let client_dest = client::get_client_dest();
    let client_src = client::get_client_src();

    let enclave_id_msg = match get_lb::<EnclaveIDMsg>(&client_src, "attestation/enclave/id") {
	Ok(r) => r,
	Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };

    
    let er_msg = ExchangeReportMsg {
	src_enclave_id: enclave_id_msg.inner,
	dh_msg2: unsafe{DHMsg2{ inner: *dh_msg2 }}
    };
    
    let _response: DHMsg3 = match post_lb(&client_dest, "attestation/exchange_report", &er_msg) {
	    Ok(r) => r,
	    Err(_) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };

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
