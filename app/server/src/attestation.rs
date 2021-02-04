extern crate sgx_types;
extern crate sgx_urts;
use self::sgx_types::*;

use crate::config;

use crate::db::get_db_read_only;

#[no_mangle]
extern "C"
fn session_request_ocall(
    src_enclave_id: sgx_enclave_id_t,
    dest_enclave_id: sgx_enclave_id_t,
    dh_msg1: *const sgx_dh_msg1_t) -> sgx_status_t {

    let config = config::get_config();

    let db = get_db_read_only(&config);

    println!("Entering session_request_ocall");
    //    unsafe {sgx_init_quote(ret_ti, ret_gid)}
    sgx_status_t::SGX_SUCCESS
}
