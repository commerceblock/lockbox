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

use rocksdb::{DB, Options as DBOptions, ColumnFamilyDescriptor};

#[cfg(test)] 
use tempdir::TempDir;
#[cfg(test)] 
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

	let path;
	cfg_if::cfg_if! {
	    if #[cfg(test)] {
		let tempdir = TempDir::new(&format!("/tmp/{}",Uuid::new_v4().to_hyphenated())).unwrap();
		path = tempdir.path();
	    } else {
		path = config_rs.storage.db_path.to_owned();
	    }
	}
	
	let mut db_opts = DBOptions::default();
	db_opts.create_missing_column_families(true);
	db_opts.create_if_missing(true);

	let mut cf_opts = DBOptions::default();	
	cf_opts.set_max_write_buffer_number(16);
	let mut column_families = Vec::<ColumnFamilyDescriptor>::new();
	column_families.push(ColumnFamilyDescriptor::new("ecdsa_first_message", cf_opts.clone()));
	column_families.push(ColumnFamilyDescriptor::new("ecdsa_second_message", cf_opts.clone()));
	column_families.push(ColumnFamilyDescriptor::new("ecdsa_sign_first", cf_opts.clone()));
	column_families.push(ColumnFamilyDescriptor::new("ecdsa_sign_second", cf_opts.clone()));
	column_families.push(ColumnFamilyDescriptor::new("ecdsa_keyupdate", cf_opts.clone()));

	let database = match DB::open_cf_descriptors(&db_opts, path, column_families) {
	    Ok(db) => db,
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
                ecdsa::sign_first,
                ecdsa::sign_second,
		ecdsa::keyupdate_first,
		ecdsa::keyupdate_second,
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
	    
	let server = Lockbox::load().unwrap();
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
