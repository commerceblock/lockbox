use rand::Rng;
use bitcoin::secp256k1::{SecretKey, PublicKey, Secp256k1};
use hex::encode;

use shamir_secret_sharing::ShamirSecretSharing as SSS;
use num_bigint::BigInt;

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

    println!("Private Key: {:x}", secret_key);
    println!("Public Key: {}", public_key_hex);


    let sss = SSS {
        threshold: 2,
        share_amount: 3,
        prime: BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",16).unwrap()
        };
    
    let secret = BigInt::parse_bytes(secret_key.to_string().as_bytes(),16).unwrap();

    let secret_hex = format!("{:?}", secret.to_str_radix(16).as_str());

    println!("Shared Secret: {}", secret_hex);
    
    let shares = sss.split(secret.clone());
    
    for i in 0..shares.len() {

        println!("       Share {}: {:?}", i, shares[i].1.to_str_radix(16));

    }

    assert_eq!(secret, sss.recover(&shares[0..sss.threshold as usize]));
    
    println!("Recovered Shared Secret: {:?}", sss.recover(&shares[0..sss.threshold as usize]).to_str_radix(16));

}
