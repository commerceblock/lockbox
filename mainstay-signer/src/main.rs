mod utils;
mod sealing;
mod db;
use serde::Serialize;
use serde::Deserialize;
use serde_json::json;
use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use num_bigint::BigInt;
use base64::{encode, decode};
use shamir_secret_sharing::ShamirSecretSharing as SSS;

const SHAMIR_SHARES: usize = 3;
const SHAMIR_THRESHOLD: usize = 2;

const CURVE: &str = "fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f";

#[derive(Debug, Clone)]
pub struct KeysAttr {
    keys: Arc<Mutex<Vec<Option<String>>>>,
    sss: SSS,
    recovered_secret: Arc<Mutex<Option<BigInt>>>,
}

#[derive(Debug, Clone)]
pub struct GlobalState {
    signing: KeysAttr,
    topup: KeysAttr
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TxDetails {
    sighash_string: Vec<String>,
    merkle_root: String,
}

pub fn get_default_global_state() -> GlobalState {
    let sss = SSS {
        threshold: SHAMIR_THRESHOLD,
        share_amount: SHAMIR_SHARES,
        prime: BigInt::parse_bytes(CURVE.as_bytes(), 16).unwrap()
    };
    let keys_attr_signing = KeysAttr {
        keys: Arc::new(Mutex::new(Vec::with_capacity(SHAMIR_SHARES))),
        sss: sss.clone(),
        recovered_secret: Arc::new(Mutex::new(None))
    };
    let keys_attr_topup = KeysAttr {
        keys: Arc::new(Mutex::new(Vec::with_capacity(SHAMIR_SHARES))),
        sss: sss.clone(),
        recovered_secret: Arc::new(Mutex::new(None))
    };

    let global_state = GlobalState {
        signing: keys_attr_signing,
        topup: keys_attr_topup
    };

    return global_state;
}

fn handle_sign(state: Arc<GlobalState>, tx_details: TxDetails) -> String {
    let sign = utils::sign_tx(
        &state,
        tx_details.sighash_string.clone(), 
        tx_details.merkle_root.clone(),
    );
    serde_json::to_string(&json!({"witness": sign})).unwrap()
}

fn handle_initialize(state: Arc<GlobalState>, key_type: String, share: String) -> String {
    let mut keys_attr: KeysAttr;
    if key_type == "signing" {
        keys_attr = state.signing.clone();
    } else if key_type == "topup" {
        keys_attr = state.topup.clone();
    } else {
        return serde_json::to_string(&json!({
            "status": "bad request, invalid key type",
        })).unwrap();
    }

    let mut keys = keys_attr.keys.lock().unwrap();
    if keys.len() < SHAMIR_THRESHOLD {
        keys.push(Some(share.clone()));
    }

    // Check if enough shares have been received to recover the secret
    if keys.len() == SHAMIR_THRESHOLD {

        let mut shares: Vec<(usize, BigInt)> = Vec::new();

        for (index, key) in keys.iter().enumerate() {
            shares.push((index+1, BigInt::parse_bytes(&key.clone().unwrap().as_bytes(), 16).unwrap()));
        }
        let recovered_secret = keys_attr.sss.recover(&shares);
        *keys_attr.recovered_secret.lock().unwrap() = Some(recovered_secret.clone());

        let (seal_data, label) = sealing::seal_recovered_secret(recovered_secret.clone());

        let data = db::SealedData {
            label: String::from_utf8(label.to_vec()).unwrap(),
            nonce: String::from_utf8(seal_data.nonce).unwrap(),
            cipher: String::from_utf8(seal_data.ciphertext).unwrap()
        };

        if let Err(err) = db::save_seal_data_to_db(data, key_type.clone()) {
            return serde_json::to_string(&json!({
                "status": format!("error in saving key to db for {:?}", key_type),
            })).unwrap();
        }

        return serde_json::to_string(&json!({
            "status": format!("accepted key for {:?}, threshold reached", key_type),
            "shared_keys": keys.len()
        })).unwrap();
    }

    serde_json::to_string(&json!({
        "status": "accepted",
        "shared_keys": keys.len()
    })).unwrap()
}

fn handle_client(mut stream: TcpStream, global_state: Arc<GlobalState>) {
    if let Ok(Some(sealed_data)) = db::get_seal_data_from_db("signing".to_string()) {
        println!("sealed data {:?}", sealed_data);
        let secret = sealing::unseal_recovered_secret(sealed_data);
        *global_state.signing.recovered_secret.lock().unwrap() = Some(BigInt::parse_bytes(secret.as_bytes(), 16).unwrap());
    }
    if let Ok(Some(sealed_data)) = db::get_seal_data_from_db("topup".to_string()) {
        println!("sealed data {:?}", sealed_data);
        let secret = sealing::unseal_recovered_secret(sealed_data);
        *global_state.topup.recovered_secret.lock().unwrap() = Some(BigInt::parse_bytes(secret.as_bytes(), 16).unwrap());
    }
    let mut buffer = [0; 1024];
    stream.read(&mut buffer).unwrap();

    let request = String::from_utf8_lossy(&buffer[..]);
    let parts: Vec<&str> = request.split("\r\n").collect();

    let path = parts[0].split_whitespace().nth(1).unwrap();
    let path_parts: Vec<&str> = path.split("/").collect();
    let route = path_parts[1];
    let mut body = parts[parts.len() - 1];
    body = body.trim_end_matches(char::from(0));

    let response = match route {
        "sign" => handle_sign(global_state, serde_json::from_str::<TxDetails>(&body).unwrap()),
        _ => {
            let key_type = path_parts[2];
            handle_initialize(global_state, key_type.to_string(), body.to_string())
        }
    };

    let response = format!(
        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
        response.len(),
        response
    );

    stream.write(response.as_bytes()).unwrap();
    stream.flush().unwrap();
}

fn main() {
    let global_state = Arc::new(get_default_global_state());
    let listener = TcpListener::bind("127.0.0.1:8000").unwrap();
    
    println!("Server running on port 8000...");

    for stream in listener.incoming() {
        let global_state = Arc::clone(&global_state);
        std::thread::spawn(move || {
            handle_client(stream.unwrap(), global_state);
        });
    }
}

// #[test]
// fn test_sign() {
//     // Initialize global state
//     let global_state = Arc::new(get_default_global_state());
//     *global_state.signing.recovered_secret.lock().unwrap() = BigInt::parse_bytes(b"77822a5eaa0755fdeff332a40e4c30a3184bde3495afebd1c58cbd7771dd091b", 16);
//     *global_state.topup.recovered_secret.lock().unwrap() = BigInt::parse_bytes(b"e213cd24a754a2d37d02c1831191321ddaaf7cffebeb68bdd481cbff879fe5c7", 16);

//     // Start the server in a separate thread
//     let server_handle = std::thread::spawn(move || {
//         // Create TcpListener
//         let listener = std::net::TcpListener::bind("127.0.0.1:8000").unwrap();
//         for stream in listener.incoming() {
//             if let Ok(mut stream) = stream {
//                 // Handle client request
//                 handle_client(stream, global_state.clone());
//             }
//         }
//     });

//     // Simulate client request
//     let client_request = "POST /sign HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{\"sighash_string\": [\"8d0ad2782d8f6e3f63c6f9611841c239630b55061d558abcc6bac53349edac70\"], \"merkle_root\": \"8d0ad2782d8f6e3f63c6f9611841c239630b55061d558abcc6bac53349edac70\"}";
//     let mut stream = std::net::TcpStream::connect("127.0.0.1:8000").unwrap();
//     stream.write_all(client_request.as_bytes()).unwrap();

//     // Wait for server to process request
//     std::thread::sleep(std::time::Duration::from_secs(1));

//     // Read server response
//     let mut buffer = String::new();
//     stream.read_to_string(&mut buffer).unwrap();

//     // Assert response status code
//     assert!(buffer.contains("HTTP/1.1 200 OK"));

//     // Stop the server
//     drop(stream);
//     server_handle.join().unwrap();
// }

// #[test]
// fn test_initialize() {
//     // Initialize global state
//     let global_state = Arc::new(get_default_global_state());
//     let sss = global_state.signing.sss.clone();

//     // Start the server in a separate thread
//     let server_handle = std::thread::spawn(move || {
//         // Create TcpListener
//         let listener = std::net::TcpListener::bind("127.0.0.1:8000").unwrap();
//         for stream in listener.incoming() {
//             if let Ok(mut stream) = stream {
//                 // Handle client request
//                 handle_client(stream, global_state.clone());
//             }
//         }
//     });

//     // Simulate client requests for initialization
//     let secret = BigInt::parse_bytes(b"ffffffffffffffffffffffffffffffffffffff", 16).unwrap();
//     let shares = sss.split(secret.clone());

//     let mut streams = Vec::new();
//     for i in 0..SHAMIR_THRESHOLD {
//         let mut stream = std::net::TcpStream::connect("127.0.0.1:8000").unwrap();
//         let request = format!("POST /initialize/signing HTTP/1.1\r\nContent-Type: application/json\r\n\r\n{}", shares[i].1.to_str_radix(16));
//         stream.write_all(request.as_bytes()).unwrap();
//         streams.push(stream);
//     }

//     // Wait for server to process requests
//     std::thread::sleep(std::time::Duration::from_secs(1));

//     // Read server response for the last request
//     let mut buffer = String::new();
//     streams.last().unwrap().read_to_string(&mut buffer).unwrap();

//     // Assert response status code
//     assert!(buffer.contains("HTTP/1.1 200 OK"));

//     // Read the recovered secret from the server state
//     // let recovered_secret = global_state.signing.recovered_secret.lock().unwrap().clone().unwrap();

//     // Compare the recovered secret with the expected value
//     // assert_eq!(recovered_secret, secret);

//     // Stop the server
//     for stream in streams {
//         drop(stream);
//     }
//     server_handle.join().unwrap();
// }
