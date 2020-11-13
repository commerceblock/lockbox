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
    /// Storage write host
    pub db_host_w: String,
    /// Storage write port
    pub db_port_w: String,
    /// Storage write user
    pub db_user_w: String,
    /// Storage write pass
    pub db_pass_w: String,
    /// Storage write database
    pub db_database_w: String,
    /// Storage read host
    pub db_host_r: String,
    /// Storage read port
    pub db_port_r: String,
    /// Storage read user
    pub db_user_r: String,
    /// Storage read pass
    pub db_pass_r: String,
    /// Storage read database
    pub db_database_r: String,
}

impl Default for StorageConfig {
    fn default() -> StorageConfig {
        StorageConfig {
            db_host_w: String::from(""),
            db_port_w: String::from(""),
            db_user_w: String::from(""),
            db_pass_w: String::from(""),
            db_database_w: String::from(""),
            db_host_r: String::from(""),
            db_port_r: String::from(""),
            db_user_r: String::from(""),
            db_pass_r: String::from(""),
            db_database_r: String::from(""),
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

        if let Ok(v) = env::var("LOCKBOX_DB_HOST_W") {
            let _ = conf_rs.set("storage.db_host_w", v)?;
        }
        if let Ok(v) = env::var("LOCKBOX_DB_PORT_W") {
            let _ = conf_rs.set("storage.db_port_w", v)?;
        }
        if let Ok(v) = env::var("LOCKBOX_DB_USER_W") {
            let _ = conf_rs.set("storage.db_user_w", v)?;
        }
        if let Ok(v) = env::var("LOCKBOX_DB_PASS_W") {
            let _ = conf_rs.set("storage.db_pass_w", v)?;
        }
        if let Ok(v) = env::var("LOCKBOX_DB_DATABASE_W") {
            let _ = conf_rs.set("storage.db_database_w", v)?;
        }

        if let Ok(v) = env::var("LOCKBOX_DB_HOST_R") {
            let _ = conf_rs.set("storage.db_host_r", v)?;
        }
        if let Ok(v) = env::var("LOCKBOX_DB_PORT_R") {
            let _ = conf_rs.set("storage.db_port_r", v)?;
        }
        if let Ok(v) = env::var("LOCKBOX_DB_USER_R") {
            let _ = conf_rs.set("storage.db_user_r", v)?;
        }
        if let Ok(v) = env::var("LOCKBOX_DB_PASS_R") {
            let _ = conf_rs.set("storage.db_pass_r", v)?;
        }
        if let Ok(v) = env::var("LOCKBOX_DB_DATABASE_R") {
            let _ = conf_rs.set("storage.db_database_r", v)?;
        }

        if let Ok(v) = env::var("LOCKBOX_ROCKET_KEEP_ALIVE") {
            let _ = conf_rs.set("rocket.keep_alive", v)?;
        }
        if let Ok(v) = env::var("LOCKBOX_ROCKET_ADDERSS") {
            let _ = conf_rs.set("rocket.address", v)?;
        }
        if let Ok(v) = env::var("LOCKBOX_ROCKET_PORT") {
            let _ = conf_rs.set("rocket.port", v)?;
        }

        Ok(conf_rs.try_into()?)
    }
}
