use num_bigint::BigInt;
use sgx_isa::{Attributes, Miscselect, Keyname, Keypolicy, Keyrequest, ErrorCode, Report};
use rand::random;
use rand::rngs::OsRng;
use aes_gcm::{Key, Aes128Gcm, KeyInit, AeadCore};
use aes_gcm::aead::Aead;
use hex::{encode, decode};
use crate::db::SealedData;

// Define a structure to keep metadata about the sealed data that should be stored alongside the sealed data.
#[derive(Debug, Clone)]
pub struct SealData {
    rand: [u8; 16],
    isvsvn: u16,
    cpusvn: [u8; 16],
    attributes: Attributes,
    miscselect: Miscselect,
}

// Define a structure to hold the nonce and cipher text
#[derive(Debug, Clone, PartialEq)]
pub struct Sealed {
    pub nonce: Vec<u8>,
    pub ciphertext: Vec<u8>
}

// Derive a sealing key for the current enclave given `label` and `seal_data`.
fn egetkey(label: [u8; 16], seal_data: &SealData) -> Result<[u8; 16], ErrorCode> {
    // Key ID is combined from fixed label and random data
    let mut keyid = [0; 32];
    keyid[..16].copy_from_slice(&label);
    keyid[16..].copy_from_slice(&seal_data.rand);

    Keyrequest {
        keyname: Keyname::Seal as _,
        keypolicy: Keypolicy::MRENCLAVE,
        isvsvn: seal_data.isvsvn,
        cpusvn: seal_data.cpusvn,
        attributemask: [!0; 2],
        keyid,
        miscmask: !0,
        ..Default::default()
    }.egetkey()
}

// Function to seal data using the sealing key
fn seal_data(secret_data: &[u8], sealing_key: &[u8; 16], sealing_data: SealData) -> Sealed {
    let key = &Key::<Aes128Gcm>::from_slice(sealing_key);

    let cipher = Aes128Gcm::new(key);
    let mut nonce = Aes128Gcm::generate_nonce(&mut OsRng);

    let ciphertext = cipher.encrypt(&nonce, secret_data).unwrap();
    
    Sealed {
        nonce: nonce.to_vec(),
        ciphertext
    }
}

// Function to unseal sealed data using the sealing key
fn unseal_data(sealing_key: &[u8; 16], nonce: Vec<u8>, ciphertext: Vec<u8>) -> Vec<u8> {
    let key = &Key::<Aes128Gcm>::from_slice(sealing_key);

    let cipher = Aes128Gcm::new(key);
    let plaintext = cipher.decrypt(nonce.as_slice().into(), ciphertext.as_ref()).unwrap();

    plaintext
}

// Function to generate a sealing key and associated metadata
fn generate_seal_data() -> ([u8; 16], SealData, [u8; 16]) {
    let report = Report::for_self();
    let label = random(); // Use a random label for each seal operation
    let seal_data = SealData {
        rand: label,
        isvsvn: report.isvsvn,
        cpusvn: report.cpusvn,
        attributes: report.attributes,
        miscselect: report.miscselect,
    };

    let sealing_key = match egetkey(label, &seal_data) {
        Ok(key) => key,
        Err(_) => panic!("Failed to generate sealing key"),
    };

    (sealing_key, seal_data, label)
}

// Function to seal recovered secret
pub fn seal_recovered_secret(recovered_secret: BigInt) -> (Sealed, [u8; 16]) {
    let (sealing_key, sealing_data, label) = generate_seal_data();
    let serialized_secret = recovered_secret.to_biguint().unwrap().to_bytes_be();
    (seal_data(&serialized_secret, &sealing_key, sealing_data), label)
}

// Function to unseal recovered secret
pub fn unseal_recovered_secret(sealed_data: SealedData) -> String {
    let report = Report::for_self();
    let label = decode(sealed_data.label).unwrap();
    let mut label_array = [0u8; 16];
    label_array.copy_from_slice(&label[..16]);
    let seal_data = SealData {
        rand: label_array,
        isvsvn: report.isvsvn,
        cpusvn: report.cpusvn,
        attributes: report.attributes,
        miscselect: report.miscselect,
    };
    let sealing_key = match egetkey(label_array, &seal_data) {
        Ok(key) => key,
        Err(_) => panic!("Failed to generate sealing key"),
    };
    let nonce_bytes = decode(sealed_data.nonce).unwrap();
    let ciphertext_bytes = decode(sealed_data.cipher).unwrap();
    encode(unseal_data(&sealing_key, nonce_bytes, ciphertext_bytes))
}

#[test]
fn test_seal_and_unseal() {
    let recovered_secret = BigInt::parse_bytes(b"ffffffffffffffffffffffffffffffffffffff", 16).unwrap();
    let (sealing_key, sealing_data, label) = generate_seal_data();
    let serialized_secret = recovered_secret.to_biguint().unwrap().to_bytes_be();
    let sealed = seal_data(&serialized_secret, &sealing_key, sealing_data);
    let plaintext = unseal_data(&sealing_key, sealed.nonce, sealed.ciphertext);
    assert_eq!(recovered_secret.to_str_radix(16), encode(plaintext));
}
