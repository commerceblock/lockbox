extern crate centipede;
extern crate config;
extern crate curv;
extern crate floating_duration;
extern crate kms;
extern crate monotree;
extern crate multi_party_ecdsa;
extern crate reqwest;
extern crate zk_paillier;

#[cfg(test)]
extern crate mockito;

#[macro_use]
extern crate serde_derive;
extern crate serde;
extern crate serde_json;

extern crate daemon_engine;
extern crate tokio;

#[macro_use]
extern crate log;

#[macro_use]
extern crate failure;

#[cfg(test)]
#[macro_use]
extern crate serial_test;

extern crate base64;
extern crate bitcoin;
extern crate electrumx_client;
extern crate hex;
extern crate itertools;
extern crate rand;
extern crate shared_lib;
extern crate uuid;

pub mod error;

use serde::{Deserialize, Serialize};


use config::Config as ConfigRs;
use error::CError;

pub type Result<T> = std::result::Result<T, CError>;

#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    pub endpoint: String,
    pub testing_mode: bool,
}

impl Config {
    pub fn get() -> Result<Config> {
        let cfg = get_config()?;
        Ok(Config {
            endpoint: cfg.get("endpoint")?,
            testing_mode: cfg.get("testing_mode")?,
        })
    }
}

impl Default for Config {
    fn default() -> Config {
        Config {
            endpoint: "http://localhost:8000".to_string(),
            testing_mode: true,
        }
    }
}

pub fn default_config() -> Result<ConfigRs> {
    let mut conf_rs = ConfigRs::new();
    let _ = conf_rs
        // First merge struct default config
        .merge(ConfigRs::try_from(&Config::default())?)?;
    Ok(conf_rs)
}

pub fn get_config() -> Result<ConfigRs> {
    let mut conf_rs = default_config()?;
    // Add in `./Settings.toml`
    conf_rs
        .merge(config::File::with_name("Settings").required(false))?
        // Add in settings from the environment (with prefix "APP")
        // Eg.. `APP_DEBUG=1 ./target/app` would set the `debug` key
        .merge(config::Environment::with_prefix("LOCKBOX"))?;
    Ok(conf_rs)
}

#[derive(Debug, Clone)]
pub struct ClientShim {
    pub client: reqwest::blocking::Client,
    pub auth_token: Option<String>,
    pub endpoint: String,
}

impl ClientShim {
    pub fn from_config(config: &Config) -> ClientShim {
        Self::new(config.endpoint.to_owned(), None)
    }

    pub fn new(endpoint: String, auth_token: Option<String>) -> ClientShim {
        let client = reqwest::blocking::Client::new();
        let cs = ClientShim {
            client,
            auth_token,
            endpoint,
        };
        cs
    }

}

#[cfg(test)]
pub mod tests {
    use super::*;
    use std::time::Instant;

    #[test]
    #[ignore]
    fn test_tor_control() {
        let config = get_config().expect("failed to get config");
        let tor = Tor::from_config(&config);
        let _ = tor.get_bytes_read().expect("failed to get bytes read");
        let _ = tor.newnym().expect("failed to get new tor identity");
        //let tor_control = TorControl::new(&tor).expect("failed to get new TorControl");
    }

    #[test]
    #[ignore]
    fn test_client_shim_tor_control() {
        let config = Config::get().expect("failed to get config");
        let mut cs = ClientShim::from_config(&config);
        let _ = cs.new_tor_id().expect("failed to get new tor id");
    }

    #[test]
    #[ignore]
    fn test_tor_stats() {
        let config = Config::get().expect("failed to get config");
        let mut cs = ClientShim::from_config(&config);
        let mut buffer = Vec::new();
        let mut sum: f32 = 0.0;
        let mut max: f32 = 0.0;
        let mut min = std::f32::MAX;
        let old_ip = cs
            .get_public_ip_address()
            .expect("failed get_public_ip_address");
        for _ in 0..10 {
            let timer = Instant::now();
            cs.new_tor_id().expect("failed to get new tor id");
            let elapsed = timer.elapsed().as_millis() as f32;
            let new_ip = cs
                .get_public_ip_address()
                .expect("failed get_public_ip_address");
            assert!(new_ip != old_ip, "expected new ip address");
            buffer.push(elapsed);
            println!("{} ms", elapsed);
            sum = sum + elapsed;
            max = max.max(elapsed);
            min = min.min(elapsed);
        }
        let count = buffer.len() as f32;
        let mean = sum / count;
        let variance: f32 = buffer
            .iter()
            .map(|val| {
                let diff = mean - val;
                diff * diff
            })
            .sum::<f32>()
            / count;
        let stdev = variance.sqrt();

        println!("Average time for new tor id is {} +/- {} ms", mean, stdev);
        println!("Longest time: {} ms", max);
        println!("Shortest time: {} ms", min);
    }
}
