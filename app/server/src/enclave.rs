use std::ops::{Deref, DerefMut};
extern crate sgx_types;
extern crate sgx_urts;
//extern crate curv;
use self::sgx_types::*;
use self::sgx_urts::SgxEnclave;
use crate::error::LockboxError;
//#[macro_use]
//extern crate serde_derive;
//extern crate serde_cbor;
extern crate bitcoin;
use bitcoin::secp256k1::{Signature, Message, PublicKey, SecretKey, Secp256k1};
pub use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*;
use curv::{BigInt, FE};

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
    
    pub fn get_random_sealed_log(&self, rand_size: u32) -> Result<[u8; 1024]> {
     	let sealed_log = [0; 1024];
	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	
	let _result = unsafe {
	    create_sealed_secret_key(self.geteid(), &mut enclave_ret, sealed_log.as_ptr() as * mut u8, 1024);
	};
	
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok(sealed_log),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }

    pub fn verify_sealed_log(&self, sealed_log: [u8; 1024]) -> Result<()> {
     	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	
	let _result = unsafe {
	    verify_sealed_secret_key(self.geteid(), &mut enclave_ret, sealed_log.as_ptr() as * mut u8, 1024);
	};
	
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok(()),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }
    
    pub fn calc_sha256(&self, input_string: String) -> Result<[u8; 32]>{
	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	let mut hash = [0u8;32];
	let _result = unsafe {
	    calc_sha256(self.geteid(), &mut enclave_ret, input_string.as_ptr() as * const u8, input_string.len() as u32, hash.as_ptr() as * mut u8);
	};
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok(hash),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }

    pub fn sk_tweak_mul_assign(&self, sealed_log1: [u8; 1024], sealed_log2: [u8; 1024]) -> Result<[u8; 1024]> {
     	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	
	let _result = unsafe {
	    sk_tweak_add_assign(self.geteid(), &mut enclave_ret, sealed_log1.as_ptr() as * mut u8, 1024, sealed_log2.as_ptr() as * mut u8, 1024);
	};
	
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok((sealed_log1)),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }

    pub fn sk_tweak_add_assign(&self, sealed_log1: [u8; 1024], sealed_log2: [u8; 1024]) -> Result<[u8; 1024]> {
     	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	
	let _result = unsafe {
	    sk_tweak_mul_assign(self.geteid(), &mut enclave_ret, sealed_log1.as_ptr() as * mut u8, 1024, sealed_log2.as_ptr() as * mut u8, 1024);
	};
	
	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => Ok((sealed_log1)),
       	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }

    pub fn sign(&self, message: &Message, sealed_log: &[u8; 1024]) -> Result<Signature> {
     	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;


	let sig = [0u8;64];
	
	let _result = unsafe {
	    sign(self.geteid(), &mut enclave_ret,
	    message.as_ptr(),  sealed_log.as_ptr() as *mut u8, sig.as_ptr() as *mut u8);
	};

	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => match Signature::from_compact(&sig){
		Ok(v) => Ok(v),
		Err(e) => Err(e.into()),
	    },
            _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into())
	}
    }

    pub fn get_public_key(&self, sealed_log: &[u8; 1024]) -> Result<PublicKey> {
     	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;

	let mut public_key = [0u8;33];
	
	let _result = unsafe {
	    get_public_key(self.geteid(), &mut enclave_ret,
	    sealed_log.as_ptr() as *mut u8, public_key.as_mut_ptr());
	};

	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => {
		match PublicKey::from_slice(&public_key){
		    Ok(v) => Ok(v),
		    Err(e) => Err(e.into()),
		}
	    },
            _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into()),
	}
    }

    pub fn first_message(&self, sealed_log_in: &mut [u8; 1024]) -> Result<(party_one::KeyGenFirstMsg, [u8;2048])>
    {
     	let mut enclave_ret = sgx_status_t::SGX_SUCCESS;
	let mut sealed_log_out = [0u8; 2048];
	let mut plain_ret = [0u8; 119];
	let mut sz_ret = [0u8;8];

	let _result = unsafe {
	    first_message(self.geteid(), &mut enclave_ret,
			  sealed_log_in.as_mut_ptr() as *mut u8,
			  sealed_log_out.as_mut_ptr() as *mut u8,
			  plain_ret.as_mut_ptr() as *mut u8,
			 sz_ret.as_mut_ptr() as *mut u8);	    
	};

	match enclave_ret {
	    sgx_status_t::SGX_SUCCESS => {
		let size = usize::from_be_bytes(sz_ret);
		let kg1m: party_one::KeyGenFirstMsg = match serde_cbor::from_slice(&plain_ret[0..size]) {
		    Ok(x) => x,
		    Err(_) => return Err(LockboxError::Generic(format!("Error deserialising KeyGenFirstMsg: {:?}!", plain_ret)).into())
		};
		Ok((kg1m, sealed_log_out))
	    },
	    _ => Err(LockboxError::Generic(format!("[-] ECALL Enclave Failed {}!", enclave_ret.as_str())).into()),
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


    fn create_sealed_secret_key(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
            sealed_log: * mut u8, sealed_log_size: u32 );

    fn verify_sealed_secret_key(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
				sealed_log: * mut u8, sealed_log_size: u32);

    fn calc_sha256(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		   input_str: * const u8, len: u32, hash: * mut u8) -> sgx_status_t;

    fn sk_tweak_add_assign(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
			   sealed_log1: * mut u8, sealed_log1_size: u32,
			   sealed_log2: * mut u8, sealed_log2_size: u32) -> sgx_status_t;

    fn sk_tweak_mul_assign(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
			   sealed_log1: * mut u8, sealed_log1_size: u32,
			   sealed_log2: * mut u8, sealed_log2_size: u32) -> sgx_status_t;


    fn sign(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
	    some_message: * const u8,  sk_sealed_log: *mut u8, sig: *mut u8) -> sgx_status_t;

    fn get_public_key(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		      sk_sealed_log: *mut u8, public_key: *mut u8) -> sgx_status_t;

    fn first_message(eid: sgx_enclave_id_t, retval: *mut sgx_status_t,
		     sealed_log_in: *mut u8,
		     sealed_log_out: *mut u8,
		     key_gen_first_msg: *mut u8,
		     msg_size: *mut u8);	
}

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
    fn test_get_random_sealed_log() {
       let enc = Enclave::new().unwrap();
       let _rsd = enc.get_random_sealed_log(100).unwrap();
       enc.destroy();
    }

    #[test]
    fn test_verify_sealed_log() {
       let enc = Enclave::new().unwrap();
       let rsd = enc.get_random_sealed_log(1020).unwrap();
       enc.verify_sealed_log(rsd).unwrap();
       enc.destroy();
    }

    #[test]
    fn test_calc_sha256() {
	let enc = Enclave::new().unwrap();
	let hash = enc.calc_sha256("test string".to_string()).unwrap();
	let expected_hash: [u8;32] = [213, 87, 156, 70, 223, 204, 127, 24, 32, 112, 19, 230, 91, 68, 228, 203, 78, 44, 34, 152, 244, 172, 69, 123, 168, 248, 39, 67, 243, 30, 147, 11];
	assert_eq!(hash, expected_hash);
	enc.destroy();
    }

    #[test]
    fn test_sk_tweak_add_assign() {
	let enc = Enclave::new().unwrap();
	let rsd1 = enc.get_random_sealed_log(32).unwrap();
	let rsd2 = enc.get_random_sealed_log(32).unwrap();

	let rsd = enc.sk_tweak_add_assign(rsd1, rsd2).unwrap();

	enc.destroy();
    }

    #[test]
    fn test_sk_tweak_mul_assign() {
	let enc = Enclave::new().unwrap();
	let rsd1 = enc.get_random_sealed_log(32).unwrap();
	let rsd2 = enc.get_random_sealed_log(32).unwrap();

	let rsd = enc.sk_tweak_mul_assign(rsd1, rsd2).unwrap();
	
	enc.destroy();
    }

    #[test]
    fn test_sign_verify() {
	let enc = Enclave::new().unwrap();
	let rsd1 = enc.get_random_sealed_log(32).unwrap();
	let msg_data : [u8;32] = [214, 88, 152, 71, 224, 205, 127, 22, 31, 115, 20, 230, 91, 68, 228, 203, 78, 44, 34, 152, 244, 172, 69, 123, 168, 248, 39, 67, 243, 30, 147, 11];
	let message = Message::from_slice(&msg_data).unwrap();
	let signature = enc.sign(&message, &rsd1).unwrap();
	let pubkey = enc.get_public_key(&rsd1).unwrap();

	let secp = Secp256k1::new();
	secp.verify(&message, &signature, &pubkey).unwrap();

	let msg_data_wrong : [u8;32] = [213, 88, 152, 71, 224, 205, 127, 22, 31, 115, 20, 230, 91, 68, 228, 203, 78, 44, 34, 152, 244, 172, 69, 123, 168, 248, 39, 67, 243, 30, 147, 11];
	let message_wrong = Message::from_slice(&msg_data_wrong).unwrap();
	match secp.verify(&message_wrong, &signature, &pubkey){
	    Ok(_) => assert!(false, "expected Err: Incorrect Signature"),
	    Err(e) => assert!(e.to_string().contains("signature failed verification"), format!("{} does not contain \"signature failed verification\"", e)),
	}

	enc.destroy();
    }

    #[test]
    fn test_first_message() {
	let enc = Enclave::new().unwrap();
	let mut rsd1 = enc.get_random_sealed_log(32).unwrap();
	enc.verify_sealed_log(rsd1).unwrap();
	let (kg1m, sealed_log_out) = enc.first_message(&mut rsd1).unwrap();
    }
    
}



