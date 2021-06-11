//! # Config
//!
//! Config module handling config options from file and env

use super::Result;

use config_rs::{Config as ConfigRs, Environment, File};
use serde::{Deserialize, Serialize};
use std::env;
extern crate lazy_static;
use lazy_static::lazy_static; // 1.4.0

lazy_static! {
    static ref CONFIG: Config = Config::load().unwrap();
}

pub fn get_config() -> Config {
    (*CONFIG).clone()
}


#[derive(Debug, Serialize, Deserialize, Clone)]
/// Storage specific config
pub struct StorageConfig {
    pub db_path: String,
}

impl Default for StorageConfig {
    fn default() -> StorageConfig {
        StorageConfig {
	    db_path: String::from(""),
        }
    }
}

#[derive(Debug, Serialize, Deserialize, Clone)]
/// Client specific config
pub struct ClientConfig {
    pub url_src: String,
    pub url_dest: String,
}

impl Default for ClientConfig {
    fn default() -> ClientConfig {
        ClientConfig {
	    url_src: String::from(""),
	    url_dest: String::from(""),
        }
    }
}

/// Enclave specific config
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct EnclaveConfig {
    pub index: u32,
}

impl Default for EnclaveConfig {
    fn default() -> EnclaveConfig {
        EnclaveConfig {
	    index: 0,
        }
    }
}


#[derive(Debug, Serialize, Deserialize, Clone)]
/// Rocket specific config
pub struct RocketConfig {
    /// Rocket keep alive parameter
    pub keep_alive: u32,
    /// Rocket address
    pub address: String,
    /// Rocket port
    pub port: u16,
}

impl Default for RocketConfig {
    fn default() -> RocketConfig {
        RocketConfig {
            keep_alive: 0,
            address: "0.0.0.0".to_string(),
            port: 8000,
        }
    }
}

/// Config struct storing all StataChain Entity config
#[derive(Debug, Serialize, Deserialize, Clone)]
pub struct Config {
    /// Log file location. If not present print to stdout
    pub log_file: String,
    /// Testing mode
    pub testing_mode: bool,
    /// Storage config
    pub storage: StorageConfig,
    /// Rocket config
    pub rocket: RocketConfig,
    /// Enclave config
    pub enclave: EnclaveConfig,
    /// Client config
    pub client: ClientConfig
}

impl Default for Config {
    fn default() -> Config {
        Config {
            log_file: String::from(""),
            testing_mode: true,
            storage: StorageConfig::default(),
            rocket: RocketConfig::default(),
	    enclave: EnclaveConfig::default(),
	    client: ClientConfig::default(),
        }
    }
}

impl Config {
    /// Load Config instance reading default values, overridden with Settings.toml,
    /// overriden with environment variables in form LOCKBOX_[setting_name]
    pub fn load() -> Result<Self> {
        let mut conf_rs = ConfigRs::new();
        let _ = conf_rs
            // First merge struct default config
            .merge(ConfigRs::try_from(&Config::default())?)?;
        // Override with settings in file Settings.toml if exists
        conf_rs.merge(File::with_name("Settings").required(false))?;
        // Override with settings in file Rocket.toml if exists
        conf_rs.merge(File::with_name("Rocket").required(false))?;
        // Override any config from env using LOCKBOX prefix
        conf_rs.merge(Environment::with_prefix("LOCKBOX"))?;

        if let Ok(v) = env::var("LOCKBOX_DB_PATH") {
            let _ = conf_rs.set("storage.db_path", v)?;
        }
	
	if let Ok(v) = env::var("LOCKBOX_ENC_INDEX") {
            let _ = conf_rs.set("enclave.index", v)?;
	}

	if let Ok(v) = env::var("LOCKBOX_CLIENT_URL_SRC") {
            let _ = conf_rs.set("client.url_src", v)?;
	}

	if let Ok(v) = env::var("LOCKBOX_CLIENT_URL_DEST") {
            let _ = conf_rs.set("client.url_dest", v)?;
	}

	
        Ok(conf_rs.try_into()?)
    }
}
