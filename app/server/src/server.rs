use super::protocol::*;
use crate::config::Config;

use log::LevelFilter;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config as LogConfig, Root as LogRoot};
use log4rs::encode::pattern::PatternEncoder;

use rocket;
use rocket::{
    config::{Config as RocketConfig, Environment},
    Request, Rocket,
};
use crate::enclave::Enclave;

use tempdir::TempDir;
use rocksdb::{DB, Options as DBOptions};
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Lockbox {
    pub config: Config,
    pub enclave: Enclave,
    pub database: DB,
}


impl Lockbox
{
    pub fn load() -> Result<Lockbox> {
        // Get config as defaults, Settings.toml and env vars
        let config_rs = Config::load()?;

        let enclave = Enclave::new().expect("failed to start enclave");

	let mut path;
	cfg_if::cfg_if! {
	    if #[cfg(test)] {
		let tempdir = TempDir::new(&format!("/tmp/{}",Uuid::new_v4().to_hyphenated())).unwrap();
		path = tempdir.path();
	    } else {
		path = config_rs.storage.db_path.to_owned();
	    }
	}
	
	let path = ("/root/lockbox/database");

	let mut database = match DB::open_default(path) {
	    Ok(db) => { db },
	    Err(e) => { panic!("failed to open database: {:?}", e) }
	};
	
        Ok(Self {
            config: config_rs,
            enclave,
	    database
        })

    }
}


#[catch(500)]
fn internal_error() -> &'static str {
    "Internal server error"
}

#[catch(400)]
fn bad_request() -> &'static str {
    "Bad request"
}

#[catch(404)]
fn not_found(req: &Request) -> String {
    format!("Unknown route '{}'.", req.uri())
}

pub fn get_server()-> Result<Rocket> {
    let lbs = Lockbox::load()?;

    set_logging_config(&lbs.config.log_file);

    let rocket_config = get_rocket_config(&lbs.config);

    let rock = rocket::custom(rocket_config)
        .register(catchers![internal_error, not_found, bad_request])
        .mount(
            "/",
            routes![
                ping::ping,
                ecdsa::first_message,
                ecdsa::second_message,
                ecdsa::third_message,
                ecdsa::fourth_message,
                ecdsa::sign_first,
                ecdsa::sign_second,
		transfer::transfer_sender,
                transfer::transfer_receiver,
            ],
        )
        .manage(lbs);

    Ok(rock)
}

fn set_logging_config(log_file: &String) {
    if log_file.len() == 0 {
        let _ = env_logger::try_init();
    } else {
        // Write log to file
        let logfile = FileAppender::builder()
            .encoder(Box::new(PatternEncoder::new("{l} - {m}\n")))
            .build(log_file)
            .unwrap();
        let log_config = LogConfig::builder()
            .appender(Appender::builder().build("logfile", Box::new(logfile)))
            .build(
                LogRoot::builder()
                    .appender("logfile")
                    .build(LevelFilter::Info),
            )
            .unwrap();
        let _ = log4rs::init_config(log_config);
    }
}

fn get_rocket_config(config: &Config) -> RocketConfig {
    RocketConfig::build(Environment::Staging)
        .keep_alive(config.rocket.keep_alive.clone())
        .address(config.rocket.address.clone())
        .port(config.rocket.port.clone())
        .finalize()
        .unwrap()
}

#[cfg(test)]
mod tests {
    use super::*;
    use shared_lib::structs::{KeyGenMsg1, Protocol};
    use uuid::Uuid;
    use crate::protocol::ecdsa::Ecdsa;
    use rocket::{
	http::Status,
	local::Client,
    };
    pub use kms::ecdsa::two_party::*;                                                                                                      
    pub use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*; 
    
    fn get_client() -> Client {
        Client::new(get_server().expect("valid rocket instance")).expect("client")   
    }

    #[test]
    #[serial]
    fn test_ping() {
        let client = get_client();
        let response = client
            .get("/ping")
            .dispatch();   
        assert_eq!(response.status(), Status::Ok);
    }

	
    #[test]
    #[serial]
    fn test_first_message() {
	let server = Lockbox::load().unwrap();
	let shared_key_id = uuid::Uuid::new_v4();

	let expected = 	Uuid::nil();

	assert_eq!(server.first_message(msg).unwrap().0, expected);
    }
}
