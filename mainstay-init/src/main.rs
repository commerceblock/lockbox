use rand::Rng;
use bitcoin::secp256k1::{SecretKey, PublicKey, Secp256k1};
use hex::encode;
use hex::decode;

use shamir_secret_sharing::ShamirSecretSharing as SSS;
use num_bigint::BigInt;
use bip39::{Mnemonic, Language};

fn main() {
    // Generate a random 32-byte private key
    let mut rng = rand::thread_rng();
    let private_key_bytes: [u8; 32] = rng.gen();

    // Create a secp256k1 SecretKey from the generated private key bytes
    let secret_key = SecretKey::from_slice(&private_key_bytes).expect("Invalid private key");

    // Create a secp256k1 Secp256k1 context
    let secp256k1 = Secp256k1::new();

    // Compute the corresponding public key
    let public_key = PublicKey::from_secret_key(&secp256k1, &secret_key);

    // Convert the public key to hex format
    let public_key_hex = encode(&public_key.serialize());

    println!("Generating random private key ...");
    println!("Public Key: {}", public_key_hex);


    let sss = SSS {
        threshold: 2,
        share_amount: 3,
        prime: BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",16).unwrap()
        };
    
    let secret = BigInt::parse_bytes(secret_key.to_string().as_bytes(),16).unwrap();

    println!("Generating secret shares ...");

    println!(" ");

    let shares = sss.split(secret.clone());
    
    for i in 0..shares.len() {

        println!("       Share {}: {:?}", i, shares[i].1.to_str_radix(16));
        // Encode the private key as a mnemonic
        let mnemonic = encode_private_key(&decode(&shares[i].1.to_str_radix(16)).unwrap()[..]);
        println!("Encoded mnemonic: {}", mnemonic);
        println!(" ");

        // Decode the mnemonic back to the private key
        let decoded_private_key = decode_private_key(&mnemonic).unwrap();

        assert_eq!(shares[i].1.to_bytes_be().1, decoded_private_key[0..32]);

    }

    assert_eq!(secret, sss.recover(&shares[0..sss.threshold as usize]));
    
    assert_eq!(secret, sss.recover(&shares[1..3 as usize]));

    let rec_shares = vec![shares[2].clone(), shares[0].clone()];

    assert_eq!(secret, sss.recover(rec_shares.as_slice()));

    // println!("Recovered Shared Secret: {:?}", sss.recover(&shares[0..sss.threshold as usize]).to_str_radix(16));

}

fn encode_private_key(private_key: &[u8]) -> String {
    // Create a BIP39 mnemonic from the private key
    let mnemonic = Mnemonic::from_entropy(private_key).unwrap();

    // Convert the mnemonic to a String
    mnemonic.to_string()
}

fn decode_private_key(mnemonic: &str) -> Result<[u8; 33], bip39::Error> {
    // Parse the mnemonic back to a BIP39 object
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic)?;

    // Get the seed from the mnemonic
    let private_key = mnemonic.to_entropy_array();

    Ok(private_key.0)
}