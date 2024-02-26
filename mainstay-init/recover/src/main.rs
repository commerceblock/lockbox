use hex::encode;

use bip39::{Mnemonic, Language};

fn main() {

    let mnemonic_sign = "vintage endorse comic voyage metal grape abandon beauty battle dream warfare stomach hole spread resist pact dizzy interest crunch trap address device icon town".to_string();

    let mnemonic_topup = "vintage endorse comic voyage metal grape abandon beauty battle dream warfare stomach hole spread resist pact dizzy interest crunch trap address device icon town".to_string();

    // Decode the mnemonic back to the private key
    let decoded_sign_private_key = decode_private_key(&mnemonic_sign).unwrap();
    let decoded_topup_private_key = decode_private_key(&mnemonic_topup).unwrap();

    println!("Decoded sign private key: {:?}", encode(&decoded_sign_private_key[0..32]));
    println!("Decoded topup private key: {:?}", encode(&decoded_topup_private_key[0..32]));

}


fn decode_private_key(mnemonic: &str) -> Result<[u8; 33], bip39::Error> {
    // Parse the mnemonic back to a BIP39 object
    let mnemonic = Mnemonic::parse_in_normalized(Language::English, mnemonic)?;

    // Get the seed from the mnemonic
    let private_key = mnemonic.to_entropy_array();

    Ok(private_key.0)
}