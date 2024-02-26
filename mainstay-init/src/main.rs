use rand::Rng;
use bitcoin::secp256k1::{SecretKey, PublicKey, Secp256k1};
use hex::encode;
use hex::decode;
use std::io;

use shamir_secret_sharing::ShamirSecretSharing as SSS;
use num_bigint::BigInt;
use bip39::{Mnemonic, Language};

use bitcoin::network::constants::Network;
use bitcoin::util::address::Address;
use bitcoin::util::key::PublicKey as BitcoinPublicKey;

use qrcode::QrCode;
use qrcode::render::svg;

fn main() {
    // Generate a random 32-byte private key
    let mut rng = rand::thread_rng();
    let private_key_bytes: [u8; 32] = rng.gen();

    let private_key_bytes_topup: [u8; 32] = rng.gen();

    // Create a secp256k1 SecretKey from the generated private key bytes
    let secret_key = SecretKey::from_slice(&private_key_bytes).expect("Invalid private key");
    let secret_key_topup = SecretKey::from_slice(&private_key_bytes_topup).expect("Invalid private key");

    // Create a secp256k1 Secp256k1 context
    let secp256k1 = Secp256k1::new();

    // Compute the corresponding public key
    let public_key = PublicKey::from_secret_key(&secp256k1, &secret_key);
    let public_key_topup = PublicKey::from_secret_key(&secp256k1, &secret_key_topup);

    // Convert the public key to hex format
    let public_key_hex = encode(&public_key.serialize());
    let public_key_hex_topup = encode(&public_key_topup.serialize());

    println!("Generating random private keys ...");

    println!("Public Key: {}", public_key_hex);
    println!("Public Key Topup: {}", public_key_hex_topup);

    let public_key_bytes = hex::decode(public_key_hex).expect("Failed to decode public key");
    let public_key_bytes_topup = hex::decode(public_key_hex_topup).expect("Failed to decode public key");

    // Parse the public key
    let uncompressed_key = BitcoinPublicKey::from_slice(&public_key_bytes).expect("Failed to parse public key");
    let uncompressed_key_topup = BitcoinPublicKey::from_slice(&public_key_bytes_topup).expect("Failed to parse public key");

    // Create a P2WPKH address from the compressed public key
    let address = Address::p2wpkh(&uncompressed_key, Network::Bitcoin);
    let address_topup = Address::p2wpkh(&uncompressed_key_topup, Network::Bitcoin);

    let bech32_address = address.unwrap().to_string();
    let bech32_address_topup = address_topup.unwrap().to_string();

    println!("Main Address: {}", bech32_address);
    println!("Topup Address: {}", bech32_address_topup);

    // Generate a QR code for the Bitcoin address
    let code = QrCode::new(bech32_address).expect("Failed to generate QR code");
    let image = code.render::<svg::Color>()
        .build();

    std::fs::write("address_main_qr.svg", image).expect("Failed to save QR code to file");

    let code_topup = QrCode::new(bech32_address_topup).expect("Failed to generate QR code");
    let image_topup = code_topup.render::<svg::Color>()
        .build();
    std::fs::write("address_topup_qr.svg", image_topup).expect("Failed to save QR code to file");

    let sss = SSS {
        threshold: 2,
        share_amount: 3,
        prime: BigInt::parse_bytes(b"fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f",16).unwrap()
        };
    
    let secret = BigInt::parse_bytes(secret_key.to_string().as_bytes(),16).unwrap();
    let secret_topup = BigInt::parse_bytes(secret_key_topup.to_string().as_bytes(),16).unwrap();

    println!("Generating secret shares ...");

    println!(" ");

    let shares = sss.split(secret.clone());
    let shares_topup = sss.split(secret_topup.clone());
    
    println!("Press Enter to continue...");
    let mut buffer = String::new();

    // Read a line from the standard input
    io::stdin().read_line(&mut buffer).expect("Failed to read line");

    for i in 0..shares.len() {

        for _j in 0..100 {
            println!(" ");
        }

        println!("       Share main {}: {:?}", i, shares[i].1.to_str_radix(16));
        println!("       Share topup {}: {:?}", i, shares_topup[i].1.to_str_radix(16));
        // Encode the private key as a mnemonic
        let mnemonic = encode_private_key(&decode(&shares[i].1.to_str_radix(16)).unwrap()[..]);
        let mnemonic_topup = encode_private_key(&decode(&shares_topup[i].1.to_str_radix(16)).unwrap()[..]);
        println!("Encoded mnemonic: {}", mnemonic);
        println!(" ");
        println!("Encoded mnemonic topup: {}", mnemonic_topup);
        println!(" ");

        // Decode the mnemonic back to the private key
        let decoded_private_key = decode_private_key(&mnemonic).unwrap();

        assert_eq!(shares[i].1.to_bytes_be().1, decoded_private_key[0..32]);

        println!("Press Enter to continue...");
    
        // Read a line from the standard input
        io::stdin().read_line(&mut buffer).expect("Failed to read line");

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