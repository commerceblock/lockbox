use bip32::{ExtendedPrivateKey, ChildNumber};
use bip32;
use hex::{encode, decode};
use secp256k1;
use btc_transaction_utils::p2wsh::InputSigner;
use btc_transaction_utils::multisig::RedeemScript;
use btc_transaction_utils::TxInRef;
use bitcoin::{self, PrivateKey};
use std::str::FromStr;
use secp256k1::key::SecretKey;
use secp256k1::key::PublicKey;
use bitcoin::blockdata::transaction::Transaction;
use bitcoin::consensus::encode::deserialize;
use hex::FromHex;
use std::env;
use dotenv::dotenv;
use bitcoin::util::bip143;
use std::str;

fn derive_privkey_from_merkle_root(merkle_root: Vec<u8>, initial_priv_key_hex: String) -> [u8; 32] {
    let rev_merkle_root: Vec<u8> = merkle_root.iter().rev().cloned().collect();
    let rev_merkle_root_hex = encode(rev_merkle_root);
    let path = get_path_from_commitment(rev_merkle_root_hex).unwrap();

    let initial_priv_key_bytes = decode(initial_priv_key_hex).expect("Invalid public key hex string");
    let mut priv_key_bytes = [0u8; 32];
    priv_key_bytes.copy_from_slice(&initial_priv_key_bytes);

    let initial_extended_privkey = ExtendedPrivateKey::new(priv_key_bytes).unwrap();
    let child_privkey = derive_child_priv_key(&initial_extended_privkey, &path.to_string());
    
    child_privkey
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

pub fn sign_tx(tx_hex: String, value: u64, merkle_root: String) -> Option<String> {
    let merkle_root_bytes = decode(merkle_root).expect("Invalid merkle root hex string");
    dotenv().ok();
    let priv_key = env::var("PRIVATE_KEY").expect("You've not set the PRIVATE_KEY in .env");
    let secret_key = derive_privkey_from_merkle_root(merkle_root_bytes, priv_key);

    let privatekey = PrivateKey::from_str(str::from_utf8(&secret_key).unwrap()).unwrap();
    let hex_tx = Vec::<u8>::from_hex(tx_hex).unwrap();
    let tx: Transaction = deserialize(&hex_tx).expect("deserialize tx");

    let sighash_components = bip143::SighashComponents::new(&tx);

    let pubkey = privatekey.public_key(&secp256k1::Secp256k1::new());

    let script_code = bitcoin::Address::p2pkh(&pubkey, privatekey.network).script_pubkey();
    let sighash = sighash_components.sighash_all(
        &tx.input[0],
        &script_code,
        value,
    );
    let msg = secp256k1::Message::from_slice(&sighash[..]).unwrap();
    let mut signature = secp256k1::Secp256k1::new().sign(&msg, &privatekey.key).serialize_der();


    Some(encode(signature))
}

