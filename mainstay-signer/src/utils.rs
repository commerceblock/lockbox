use bip32::{ExtendedPrivateKey, ExtendedKeyAttrs, ExtendedKey, ChildNumber, Prefix};
use bip32;
use hex::{encode, decode};
use secp256k1::{self, ecdsa::SerializedSignature};
use bitcoin::{self, PrivateKey};
use std::str::FromStr;
use secp256k1::SecretKey;
use secp256k1::PublicKey;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode::deserialize;
use hex::FromHex;
use std::env;
use dotenv::dotenv;
use std::str;
use std::sync::Arc;
use crate::GlobalState;

fn derive_privkey_from_merkle_root(merkle_root: Vec<u8>, initial_priv_key_hex: String) -> [u8; 32] {
    let rev_merkle_root: Vec<u8> = merkle_root.iter().rev().cloned().collect();
    let rev_merkle_root_hex = encode(rev_merkle_root);
    let path = get_path_from_commitment(rev_merkle_root_hex).unwrap();

    let initial_priv_key_bytes = decode(initial_priv_key_hex).expect("Invalid public key hex string");
    let mut priv_key_bytes = [0u8; 32];
    priv_key_bytes.copy_from_slice(&initial_priv_key_bytes);
    
    if merkle_root != &[0; 32] {
        let mut key_bytes = [0x00u8; 33];
        key_bytes[1..].copy_from_slice(&initial_priv_key_bytes);
        let (depth, parent_fp, child_number, chain_code) = get_config_values();
        let attrs = ExtendedKeyAttrs {
            depth: depth,
            parent_fingerprint: parent_fp,
            child_number: ChildNumber(child_number),
            chain_code: chain_code
        };
        let initial_extended_key = ExtendedKey {
            prefix: Prefix::XPRV,
            attrs: attrs,
            key_bytes: key_bytes
        };
        let initial_extended_privkey = ExtendedPrivateKey::try_from(initial_extended_key).unwrap();
        let child_privkey = derive_child_priv_key(&initial_extended_privkey, &path.to_string());
        
        return child_privkey;
    }
    
    priv_key_bytes
}

fn get_path_from_commitment(commitment: String) -> Option<String> {
    let path_size = 16;
    let child_size = 4;

    if commitment.len() != path_size * child_size {
        return None;
    }

    let mut derivation_path = String::new();
    for it in 0..path_size {
        let index = &commitment[it * child_size..it * child_size + child_size];
        let decoded_index = u64::from_str_radix(index, 16).unwrap();
        derivation_path.push_str(&decoded_index.to_string());
        if it < path_size - 1 {
            derivation_path.push('/');
        }
    }

    Some(derivation_path)
}

fn derive_child_priv_key(parent: &ExtendedPrivateKey<bip32::secp256k1::SecretKey>, path: &str) -> [u8; 32] {
    let mut extended_key = parent.clone();
    let mut private_key = parent.to_bytes();
    for step in path.split('/') {
        match step {
            "m" => continue,
            number => {
                if let Ok(index) = number.parse::<u32>() {
                    let new_extended_key = extended_key.derive_child(ChildNumber(index)).expect("Failed to derive child key");
                    private_key = new_extended_key.to_bytes();
                    extended_key = new_extended_key.clone();
                } else {
                    panic!("Invalid derivation path step: {}", step);
                }
            }
        }
    }
    private_key
}

pub fn sign_tx(state: &Arc<GlobalState>, sighash_string: Vec<String>, merkle_root: String) -> Vec<String> {
    let merkle_root_bytes = decode(merkle_root).expect("Invalid merkle root hex string");
    let priv_key = state.signing.recovered_secret.lock().unwrap().clone().unwrap().to_str_radix(16);
    let topup_key_string = state.topup.recovered_secret.lock().unwrap().clone().unwrap().to_str_radix(16);
    let secret_key = derive_privkey_from_merkle_root(merkle_root_bytes, priv_key);

    println!("secret_key: {}", encode(secret_key).as_str());
    println!("topup_key: {}", topup_key_string.as_str());

    let secretkey = SecretKey::from_slice(&secret_key).unwrap();
    let topup_key: SecretKey = SecretKey::from_slice(&decode(topup_key_string).unwrap()).unwrap();

    let secp = secp256k1::Secp256k1::new();
    let public_key = PublicKey::from_secret_key(&secp, &secretkey);
    let topup_pubkey = PublicKey::from_secret_key(&secp, &topup_key);

    let sighash: [u8; 32] = FromHex::from_hex(sighash_string[0].clone()).unwrap();

    let msg = secp256k1::Message::from_digest_slice(&sighash[..]).unwrap();
    let signature = secp.sign_ecdsa(&msg, &secretkey).serialize_der();

    let witness = encode(signature).as_str().to_owned() + " " + public_key.to_string().to_owned().as_str();

    let mut witness_vec = Vec::new();
    witness_vec.push(witness);
    
    if sighash_string.len() > 1 {
        let sighash_topup: [u8; 32] = FromHex::from_hex(sighash_string[1].clone()).unwrap();
        let msg_topup = secp256k1::Message::from_digest_slice(&sighash_topup[..]).unwrap();
        let signature_topup = secp.sign_ecdsa(&msg_topup, &topup_key).serialize_der();
        let witness_topup = encode(signature_topup).as_str().to_owned() + " " + topup_pubkey.to_string().to_owned().as_str();

        witness_vec.push(witness_topup);
    }

    return witness_vec;

}

pub fn get_config_values() -> (u8, [u8; 4], u32, [u8; 32]) {
    dotenv().ok();
    let depth_str = env::var("DEPTH").expect("You've not set the DEPTH in .env");
    let depth = depth_str.parse::<u8>().unwrap();

    let parent_fp_str = env::var("PARENT_FINGERPRINT").expect("You've not set the DEPTH in .env");
    let parent_fp = decode(parent_fp_str).unwrap();
    let mut parent_fp_bytes = [0u8; 4];
    parent_fp_bytes.copy_from_slice(&parent_fp);

    let child_number_str = env::var("CHILD_NUMBER").expect("You've not set the CHILD_NUMBER in .env");
    let child_number = child_number_str.parse().unwrap();

    let chain_code_str = env::var("CHAINCODE").expect("You've not set the CHAINCODE in .env");
    let chain_code = decode(chain_code_str).unwrap();
    let mut chain_code_bytes = [0u8; 32];
    chain_code_bytes.copy_from_slice(&chain_code);

    return (depth, parent_fp_bytes, child_number, chain_code_bytes);
}
