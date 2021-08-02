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
use crate::protocol::attestation::Attestation;
use crate::Key;

use rocksdb::DB;

#[cfg(test)] 
use tempdir::TempDir;
#[cfg(test)] 
use uuid::Uuid;

use crate::db::get_db;

use std::sync::{RwLock, RwLockWriteGuard};

use std::convert::TryInto;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Lockbox {
    pub config: Config,
    pub enclave: RwLock<Enclave>,
    pub database: DB,
    pub key_database: DB,
}


impl Lockbox
{
    pub fn load(config_rs: Config) -> Result<Lockbox> {

    let enclave = RwLock::new(Enclave::new().expect("failed to start enclave"));

	let (database,key_database) = get_db(&config_rs);
		
    let lb = Self {
        config: config_rs,
        enclave,
	    database,
        key_database,
    };

	//Get the enclave id from the enclave
	let report = lb.enclave_mut().get_self_report().unwrap();
	let key_id = report.body.mr_enclave.m;
    let mut key_uuid = uuid::Builder::from_bytes(key_id[..16].try_into().unwrap());
    let db_key = Key::from_uuid(&key_uuid.build());

	//Get the sealed enclave key from the database and store it in the enclave struct
	lb.get_enclave_key(&db_key).unwrap();
	
	Ok(lb)
    }

    //pub fn enclave(&self) -> RwLockReadGuard<Enclave> {
//	self.enclave.read().unwrap()
//    }

    pub fn enclave_mut(&self) -> RwLockWriteGuard<Enclave> {
	    let lock = self.enclave.write().expect("locking enclave to write");
	    lock
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

pub fn get_server(config_rs: Config)-> Result<Rocket> {
    let lbs = Lockbox::load(config_rs)?;

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
                ecdsa::sign_first,
                ecdsa::sign_second,
		ecdsa::keyupdate_first,
		ecdsa::keyupdate_second,
		transfer::transfer_sender,
                transfer::transfer_receiver,
		attestation::enclave_id,
		attestation::session_request,
		attestation::exchange_report,
		attestation::end_session,
		attestation::test_create_session,
		attestation::proc_msg1,
		attestation::proc_msg3,
        attestation::set_session_enclave_key,
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
    use shared_lib::structs::{KeyGenMsg1, Protocol, EnclaveIDMsg,
			      DHMsg1, DHMsg2, DHMsg3, ExchangeReportMsg};
    use crate::client;
    
    use crate::protocol::ecdsa::Ecdsa;
    use rocket::{
	http::Status,
	local::Client,
    };
    pub use kms::ecdsa::two_party::*;                                                                                                      
    pub use multi_party_ecdsa::protocols::two_party_ecdsa::lindell_2017::*; 

    
    fn get_client() -> Client {
	let config = crate::config::get_config();
        Client::new(get_server(config).expect("valid rocket instance")).expect("client")   
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
	let config = crate::config::get_config();
	let server = Lockbox::load(config).unwrap();
	let shared_key_id = uuid::Uuid::new_v4();

	let expected = 	shared_key_id;
	let msg = KeyGenMsg1{shared_key_id, protocol: Protocol::Deposit};
	assert_eq!(server.first_message(msg).unwrap().0, expected);
    }

    #[test]
    #[serial]
    fn test_second_message() {
	use kms::ecdsa::two_party::*;
	use curv::{BigInt, FE, elliptic::curves::traits::ECScalar};
	use crate::shared_lib::structs::KeyGenMsg2;

	let config = crate::config::get_config();
	let server = Lockbox::load(config).unwrap();
	let shared_key_id = uuid::Uuid::new_v4();

	
	let expected = 	shared_key_id;
	let msg = KeyGenMsg1{shared_key_id, protocol: Protocol::Deposit};

	
	let (m1_id, m1_msg) = server.first_message(msg).unwrap();

	
	assert_eq!(m1_id, expected);


	let secret_key : FE = ECScalar::new_random();
	
	let (kg_party_two_first_message, kg_ec_key_pair_party2) =
            MasterKey2::key_gen_first_message_predefined(&secret_key);

	let key_gen_msg2 = KeyGenMsg2 {
            shared_key_id: shared_key_id,
            dlog_proof: kg_party_two_first_message.d_log_proof,
	};
	
	let kgp1m2 = server.second_message(key_gen_msg2).unwrap().unwrap();

	let key_gen_second_message = MasterKey2::key_gen_second_message(
            &m1_msg,
            &kgp1m2,
	);


	let (_, party_two_paillier) = key_gen_second_message.unwrap();
	let _master_key = MasterKey2::set_master_key(
            &BigInt::from(0),
            &kg_ec_key_pair_party2,
            &kgp1m2
		.ecdh_second_message
		.comm_witness
		.public_share,
            &party_two_paillier,
	);

	
    }
}
