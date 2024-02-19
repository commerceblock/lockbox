use serde::{Serialize, Deserialize};
use serde_json::json;
use std::net::TcpStream;
use std::io::{Read, Write};
use dotenv::dotenv;
use std::env;

#[derive(Debug, Serialize, Deserialize)]
pub struct SealedData {
    pub label: String,
    pub nonce: String,
    pub cipher: String,
}

const POSTGREST_URL: &str = "localhost:3000";

pub fn save_seal_data_to_db(sealed_data: SealedData, key_type: String) -> Result<(), Box<dyn std::error::Error>> {
    let request_body = format!("label={}&nonce={}&cipher={}&key_type={}", 
                                    sealed_data.label, sealed_data.nonce, sealed_data.cipher, key_type);

    let client_request = format!("POST /sealed_data HTTP/1.1\r\n\
                            Content-Type: application/x-www-form-urlencoded\r\n\
                            Content-Length: {}\r\n\
                            \r\n\
                            {}", request_body.len(), request_body);

    let mut stream = TcpStream::connect(POSTGREST_URL).expect("Failed to connect to server");

    stream.write_all(client_request.as_bytes()).expect("Failed to send request");

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();
    
    // Check if the response status is 201 Created
    if response.contains("HTTP/1.1 201 Created") {
        println!("Data saved successfully");
        Ok(())
    } else {
        println!("Failed to save data: {}", response);
        Err("Failed to save data".into())
    }
}

pub fn get_seal_data_from_db(key_type: String) -> Result<Option<SealedData>, Box<dyn std::error::Error>>{
    let client_request = format!("GET /sealed_data?key_type=eq.{} HTTP/1.1\r\nConnection: close\r\n\r\n", key_type);

    let mut stream = TcpStream::connect(POSTGREST_URL).expect("Failed to connect to server");

    stream.write_all(client_request.as_bytes()).expect("Failed to send request");

    let mut response = String::new();
    stream.read_to_string(&mut response).unwrap();

    // Extract JSON data from the response
    let json_start_index = response.find('{').unwrap_or(0);
    let json_end_index = response.rfind('}').unwrap_or(0);

    if json_start_index < json_end_index {
        let json_data = &response[json_start_index..=json_end_index];

        // Deserialize JSON data into SealedData
        if let Ok(sealed_data) = serde_json::from_str::<SealedData>(json_data) {
            Ok(Some(sealed_data))
        } else {
            println!("Failed to deserialize sealed data");
            Ok(None)
        }
    } else {
        println!("No sealed data found in response");
        Ok(None)
    }
}
