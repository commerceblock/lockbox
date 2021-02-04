use reqwest;

extern crate lazy_static;
use lazy_static::lazy_static; // 1.4.0
use crate::config::get_config;

lazy_static! {
    static ref CLIENT_SRC: Lockbox = Lockbox::new(get_config().client.url_src);
}

pub fn get_client_src() -> &'static Lockbox {
    &CLIENT_SRC
}

lazy_static! {
    static ref CLIENT_DEST: Lockbox = Lockbox::new(get_config().client.url_dest);
}

pub fn get_client_dest() -> &'static Lockbox {
    &CLIENT_DEST
}

#[derive(Debug, Clone)]
pub struct Lockbox {
    pub client: reqwest::blocking::Client,
    pub endpoint: String,
    pub active: bool,
}

impl Lockbox {
    pub fn new(endpoint: String) -> Lockbox {
        let client = reqwest::blocking::Client::new();
        let active = endpoint.len() > 0;
        let lb = Lockbox {
            client,
            endpoint,
            active,
        };
        lb
    }
}
