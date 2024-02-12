use num_bigint::BigInt;
use sgx_isa::{Attributes, Miscselect, Keyname, Keypolicy, Keyrequest, ErrorCode, Report};
use rand::random;
use ring::aead::{Aad, Nonce, UnboundKey, BoundKey, SealingKey, OpeningKey, NonceSequence, AES_256_GCM};
use ring::hkdf::{Salt, HKDF_SHA256};
use sha2::{Sha256, Digest};
use secrecy::zeroize::{Zeroize, Zeroizing};

struct OnlyOnce(Option<Nonce>);

impl OnlyOnce {
    fn new(nonce: Nonce) -> Self {
        Self(Some(nonce))
    }
}

impl NonceSequence for OnlyOnce {
    fn advance(&mut self) -> Result<Nonce, ring::error::Unspecified> {
        Ok(self
            .0
            .take()
            .expect("sealed / unseal more than once with the same key"))
    }
}

// Define a structure to keep metadata about the sealed data that should be stored alongside the sealed data.
#[derive(Debug, Clone)]
pub struct SealData {
    rand: [u8; 16],
    isvsvn: u16,
    cpusvn: [u8; 16],
    attributes: Attributes,
    miscselect: Miscselect,
}

// Define a structure to hold the sealing key and cipher text
pub struct Sealed {
    keyrequest: Keyrequest,
    ciphertext: [u8; 16]
}

const HKDF_SALT_STRING: &str = "MAINSTAY::SgxSealing";

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
    let mut ciphertext: &mut [u8] = &mut secret_data.to_vec();
    let keyrequest = Keyrequest::try_copy_from(sealing_key).unwrap();
    let key_material = Zeroizing::new(keyrequest.egetkey().unwrap());
    let keyid_len = keyrequest.keyid.len();
    let (_, nonce) = keyrequest.keyid.split_at(keyid_len - 12);
    let mut nonce_array = [0u8; 12];
    nonce_array.copy_from_slice(nonce);
    let single_use_nonce = OnlyOnce(Some(Nonce::assume_unique_for_key(nonce_array)));

    let mut hasher = Sha256::new();
    hasher.update(HKDF_SALT_STRING);
    let hkdf_salt = hasher.finalize();

    let aesgcm_key = UnboundKey::from(
        Salt::new(HKDF_SHA256, &hkdf_salt)
            .extract(key_material.as_slice())
            .expand(&[&sealing_data.rand], &AES_256_GCM)
            .expect("Failed to derive sealing key from key material"),
    );
    let mut sealing_key = SealingKey::new(
        aesgcm_key, 
        single_use_nonce
    );

    let mut tag = sealing_key.seal_in_place_separate_tag(Aad::empty(), &mut ciphertext).unwrap();
    ciphertext.copy_from_slice(tag.as_ref());
    let mut ciphertext_array = [0u8; 16];
    ciphertext_array.copy_from_slice(&ciphertext[..16]);
    Sealed {
        keyrequest: keyrequest,
        ciphertext: ciphertext_array
    }
}

// Function to unseal sealed data using the sealing key
// fn unseal_data(label: &[u8], sealed: &Sealed) -> Vec<u8> {
//     let keyrequest = sealed.keyrequest;
//     let key_material = Zeroizing::new(keyrequest.egetkey().unwrap());
//     let keyid_len = keyrequest.keyid.len();
//     let (_, nonce) = keyrequest.keyid.split_at(keyid_len - 12);
//     let mut nonce_array = [0u8; 12];
//     nonce_array.copy_from_slice(nonce);
//     let single_use_nonce = OnlyOnce(Some(Nonce::assume_unique_for_key(nonce_array)));

//     let mut hasher = Sha256::new();
//     hasher.update(HKDF_SALT_STRING);
//     let hkdf_salt = hasher.finalize();

//     let aesgcm_key = UnboundKey::from(
//         Salt::new(HKDF_SHA256, &hkdf_salt)
//             .extract(key_material.as_slice())
//             .expand(&[label], &AES_256_GCM)
//             .expect("Failed to derive sealing key from key material"),
//     );
//     let unsealing_key = OpeningKey::new(
//         aesgcm_key,
//         single_use_nonce,
//     );

//     let mut ciphertext = sealed.ciphertext.into();
//     let plaintext_ref = unsealing_key
//         .open_in_place(Aad::empty(), &mut ciphertext)?;
//     let plaintext_len = plaintext_ref.len();

//     ciphertext.truncate(plaintext_len);
//     ciphertext
// }

// Function to generate a sealing key and associated metadata
fn generate_seal_data() -> ([u8; 16], SealData) {
    let report = Report::for_self();
    let seal_data = SealData {
        rand: random(),
        isvsvn: report.isvsvn,
        cpusvn: report.cpusvn,
        attributes: report.attributes,
        miscselect: report.miscselect,
    };

    let label = seal_data.rand; // Use a random label for each seal operation
    let sealing_key = match egetkey(label, &seal_data) {
        Ok(key) => key,
        Err(_) => panic!("Failed to generate sealing key"),
    };

    (sealing_key, seal_data)
}

// Function to seal recovered secret
pub fn seal_recovered_secret(recovered_secret: BigInt) -> Sealed {
    let (sealing_key, sealing_data) = generate_seal_data();
    let serialized_secret = recovered_secret.to_biguint().unwrap().to_bytes_be();
    seal_data(&serialized_secret, &sealing_key, sealing_data)
}
