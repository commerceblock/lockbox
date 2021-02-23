extern crate init_shared_lib;
extern crate shared_lib;
use init_shared_lib::*;
use std::env;
use shared_lib::structs::{EnclaveIDMsg, DHMsg1, DHMsg2, DHMsg3, ExchangeReportMsg};

fn main() {
    let lockbox_url_src: &str = &env::var("LOCKBOX_URL_SRC").unwrap_or("http://0.0.0.0:8000".to_string());
    let lockbox_src = Lockbox::new(lockbox_url_src.to_string());
    let lockbox_url_dst: &str = &env::var("LOCKBOX_URL_DST").unwrap_or("http://0.0.0.0:8000".to_string());
    let lockbox_dst = Lockbox::new(lockbox_url_dst.to_string());

    println!("...getting src enclave id...\n");
    let enclave_id_msg = get_lb::<EnclaveIDMsg>(&lockbox_src, "attestation/enclave_id").unwrap();

    println!("enclave id: {:?}", enclave_id_msg);
    
    println!("...requesting session with dst...\n");
    let dhmsg1: DHMsg1 = post_lb(&lockbox_dst, "attestation/session_request", &enclave_id_msg).unwrap();

    println!("...proc_msg1...\n");
    let dh_msg2: DHMsg2 = post_lb(&lockbox_src, "attestation/proc_msg1", &dhmsg1).unwrap();
    
    let rep_msg = ExchangeReportMsg {
	src_enclave_id: enclave_id_msg.inner,
	dh_msg2,
    };
    
    let dh_msg3: DHMsg3 = post_lb(&lockbox_dst, "attestation/exchange_report", &rep_msg).unwrap();
    
    println!("...proc_msg3...\n");
    let res: () = post_lb(&lockbox_src, "attestation/proc_msg3", &dh_msg3).unwrap();
}
