use crate::sgx_types::*;

use crate::config;
use crate::client;

use crate::db::get_db_read_only;

use crate::protocol::requests::post_lb;

use std::convert::TryInto;

use std::fmt;

use crate::shared_lib::structs::{DHMsg1, DHMsg2};

use crate::server::Lockbox;

use super::Result;

use rocket_contrib::json::Json;

use rocket::State;

#[no_mangle]
extern "C"
fn session_request_ocall(
    src_enclave_id: sgx_enclave_id_t,
    dest_enclave_id: sgx_enclave_id_t,
    dh_msg1: *const sgx_dh_msg1_t) -> sgx_status_t {

    let config = config::get_config();

    let db = get_db_read_only(&config);
    
    //let client_src = client::get_client_src();

    let client_dest = client::get_client_dest();

    let path = "attestation/session/request";

    let inner_slice: &[u8] = unsafe { std::slice::from_raw_parts(dh_msg1 as *const sgx_dh_msg1_t as *const u8, 576) };
    let dh_msg1_ser = DHMsg1{ inner: inner_slice.to_vec() };
   
    
    let response: DHMsg2 = match post_lb(&client_dest, path, &dh_msg1_ser) {
	Ok(r) => r,
	Err(e) => return sgx_status_t::SGX_ERROR_UNEXPECTED,
    };

    println!("Entering session_request_ocall");
    //    unsafe {sgx_init_quote(ret_ti, ret_gid)}
    sgx_status_t::SGX_SUCCESS
}

#[post("/attestation/session/request", format = "json", data = "<dh_msg1_ser>")]
pub fn session_request(
    lockbox: State<Lockbox>,
    dh_msg1_ser: Json<DHMsg1>,
) -> Result<Json<DHMsg2>> {
    match lockbox.session_request(&dh_msg1_ser.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

pub trait Attestation {
    fn session_request(&self, msg1: &DHMsg1) -> Result<DHMsg2>;
}

impl Attestation for Lockbox{
    fn session_request(&self, msg1: &DHMsg1) -> Result<DHMsg2> {
	Ok(DHMsg2::default())
    }
}
