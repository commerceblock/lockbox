use std::ops::{Deref, DerefMut};
extern crate sgx_types;
extern crate sgx_urts;
use self::sgx_types::*;
use self::sgx_urts::SgxEnclave;
use crate::error::LockboxError;

static ENCLAVE_FILE: &'static str = "/opt/lockbox/bin/enclave.signed.so";

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Enclave {
    inner: SgxEnclave
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
			  Ok(v) => Ok(Self{inner:v}),
			  Err(e) => return Err(LockboxError::Generic(e.to_string()).into()),
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
     pub fn get_random_sealed_data(&self) -> Result<[u8; 1024]> {
     	 let mut sealed_log = [0; 1024];
	 let mut enclave_ret = sgx_status_t::SGX_SUCCESS;

	 let result = unsafe {
	     create_sealeddata_for_serializable(self.geteid(), &mut enclave_ret, sealed_log.as_ptr() as * mut u8, 1024);
	 };

	 match enclave_ret {
	      sgx_status_t::SGX_SUCCESS => Ok(sealed_log),
       	       _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	 }
     }

     pub fn verify_sealed_data(&self, sealed_log: [u8; 1024]) -> Result<()> {
     	 let mut enclave_ret = sgx_status_t::SGX_SUCCESS;

	 let result = unsafe {
	     verify_sealeddata_for_serializable(self.geteid(), &mut enclave_ret, sealed_log.as_ptr() as * mut u8, 1024);
	 };

	 match enclave_ret {
	      sgx_status_t::SGX_SUCCESS => Ok(()),
       	       _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	 }
     }

     pub fn destroy(&self) {
     	 unsafe {
	     sgx_destroy_enclave(self.geteid());
	 }
     }
}

extern {
    fn say_something(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
                     some_string: *const u8, len: usize) -> sgx_status_t;

    fn create_sealeddata_for_serializable(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
       		sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t;

    fn verify_sealeddata_for_serializable(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
       		sealed_log: * mut u8, sealed_log_size: u32) -> sgx_status_t;
}

//A trait to mark a struct or part of a struct as sealed
pub trait SgxSealed{}

pub struct SealedData {}

#[cfg(test)]
mod tests {
    use super::*;

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
    fn test_get_random_sealed_data() {
       let enc = Enclave::new().unwrap();
       let rsd = enc.get_random_sealed_data().unwrap();
       enc.destroy();
    }

    #[test]
    fn test_verify_sealed_data() {
       let enc = Enclave::new().unwrap();
       let rsd = enc.get_random_sealed_data().unwrap();
       enc.verify_sealed_data(rsd).unwrap();
       enc.destroy();
    }
}



