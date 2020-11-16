//! # Config
//!
//! Config module handling config options from file and env

use super::Result;

use config_rs::{Config as ConfigRs, Environment, File};
use serde::{Deserialize, Serialize};
use std::env;

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
            keep_alive: 100,
            address: "0.0.0.0".to_string(),
            port: 8000,
        }
    }
}

/// Config struct storing all StataChain Entity config
#[derive(Debug, Serialize, Deserialize)]
pub struct Config {
    /// Log file location. If not present print to stdout
    pub log_file: String,
    /// Testing mode
    pub testing_mode: bool,
    /// Storage config
    pub storage: StorageConfig,
    /// Rocket config
    pub rocket: RocketConfig,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            log_file: String::from(""),
            testing_mode: true,
            storage: StorageConfig::default(),
            rocket: RocketConfig::default(),
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

        // Override storage and mainstay config from env variables.
        // Currently doesn't seem to be supported by config_rs.
        // https://github.com/mehcode/config-rs/issues/104
        // A possible alternative would be using a "__" separator
        // e.g. Environment::with_prefix("CO").separator("__")) and
        // setting envs as below but is less readable and confusing
        // CO_CLIENTCHAIN__ASSET_HASH=73be005...
        // CO_CLIENTCHAIN__ASSET=CHALLENGE
        // CO_CLIENTCHAIN__HOST=127.0.0.1:5555
        // CO_CLIENTCHAIN__GENESIS_HASH=706f6...

        if let Ok(v) = env::var("LOCKBOX_DB_PATH") {
            let _ = conf_rs.set("storage.db_path", v)?;
        }
        Ok(conf_rs.try_into()?)
    }
}
