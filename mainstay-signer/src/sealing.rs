use num_bigint::BigInt;
use sgx_isa::{Attributes, Miscselect, Keyname, Keypolicy, Keyrequest, ErrorCode, Report};
use rand::random;

// Define a structure to keep metadata about the sealed data that should be stored alongside the sealed data.
#[derive(Debug, Clone)]
pub struct SealData {
    rand: [u8; 16],
    isvsvn: u16,
    cpusvn: [u8; 16],
    attributes: Attributes,
    miscselect: Miscselect,
}

// Define a structure to hold the sealing key
struct SealingKey {
    key: [u8; 16],
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
fn seal_data(data: &[u8], sealing_key: &SealingKey) -> SealData {
    let mut sealed_data = sgx_sealed_data_t::default();
    let status = sealed_data.encrypt(&sealing_key.key, data);
    sealed_data
}

// Function to unseal sealed data using the sealing key
fn unseal_data(sealed_data: &SealData, sealing_key: &SealingKey) -> Vec<u8> {
    let mut unsealed_data = vec![0u8; sealed_data.get_decrypt_txt_len()];
    let status = sealed_data.decrypt(&sealing_key.key, &mut unsealed_data);
    unsealed_data
}

// Function to generate a sealing key and associated metadata
fn generate_seal_data() -> (SealingKey, SealData) {
    let report = Report::default();
    let seal_data = SealData {
        rand: random(),
        isvsvn: report.isvsvn,
        cpusvn: report.cpusvn,
        attributes: report.attributes,
        miscselect: report.miscselect,
    };

    let label = random(); // Use a random label for each seal operation
    let sealing_key = match egetkey(label, &seal_data) {
        Ok(key) => SealingKey { key },
        Err(_) => panic!("Failed to generate sealing key"),
    };

    (sealing_key, seal_data)
}

// Function to seal recovered secret
pub fn seal_recovered_secret(recovered_secret: BigInt) -> SealData {
    let sealing_key = generate_seal_data().0;
    let serialized_secret = recovered_secret.to_biguint().unwrap().to_bytes_be();
    seal_data(&serialized_secret, &sealing_key)
}
