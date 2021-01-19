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


    // Useful data structs for tests throughout codebase
    pub static BACKUP_TX_NOT_SIGNED: &str = "{\"version\":2,\"lock_time\":0,\"input\":[{\"previous_output\":\"faaaa0920fbaefae9c98a57cdace0deffa96cc64a651851bdd167f397117397c:0\",\"script_sig\":\"\",\"sequence\":4294967295,\"witness\":[]}],\"output\":[{\"value\":9000,\"script_pubkey\":\"00148fc32525487d2cb7323c960bdfb0a5ee6a364738\"}]}";
    pub static BACKUP_TX_SIGNED: &str = "{\"version\":2,\"lock_time\":0,\"input\":[{\"previous_output\":\"faaaa0920fbaefae9c98a57cdace0deffa96cc64a651851bdd167f397117397c:0\",\"script_sig\":\"\",\"sequence\":4294967295,\"witness\":[[48,68,2,32,45,42,91,77,252,143,55,65,154,96,191,149,204,131,88,79,80,161,231,209,234,229,217,100,28,99,48,148,136,194,204,98,2,32,90,111,183,68,74,24,75,120,179,80,20,183,60,198,127,106,102,64,37,193,174,226,199,118,237,35,96,236,45,94,203,49,1],[2,242,131,110,175,215,21,123,219,179,199,144,85,14,163,42,19,197,97,249,41,130,243,139,15,17,51,185,147,228,100,122,213]]}],\"output\":[{\"value\":9000,\"script_pubkey\":\"00148fc32525487d2cb7323c960bdfb0a5ee6a364738\"}]}";
    pub static STATE_CHAIN: &str = "{\"chain\":[{\"data\":\"026ff25fd651cd921fc490a6691f0dd1dcbf725510f1fbd80d7bf7abdfef7fea0e\",\"next_state\":null}]}";
    pub static STATE_CHAIN_SIG: &str = "{ \"purpose\": \"TRANSFER\", \"data\": \"024d4b6cd1361032ca9bd2aeb9d900aa4d45d9ead80ac9423374c451a7254d0766\", \"sig\": \"3045022100e1171094db96e68392bb2a72695dc7cbce86db7be9d2e943444b6fa08877eec9022036dc63a3b2536d8e2327e0f44ff990f18e6166dce66d87bdcb57f825158a507c\"}";

    
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

	let master_key = MasterKey2::set_master_key(
            &BigInt::from(0),
            &kg_ec_key_pair_party2,
            &kgp1m2
		.ecdh_second_message
		.comm_witness
		.public_share,
            &party_two_paillier,
	);

	
    }

    #[test]
    fn test_sign() {
        let user_id = Uuid::from_str("001203c9-93f0-46f9-abda-0678c891b2d3").unwrap();
        let tx_backup: Transaction = serde_json::from_str(&BACKUP_TX_NOT_SIGNED).unwrap();
        let hexhash = r#"
                "0000000000000000000000000000000000000000000000000000000000000000"
            "#;
        let sig_hash: sha256d::Hash = serde_json::from_str(&hexhash.to_string()).unwrap();

        let (eph_key_gen_first_message_party_two, _, _) =
            MasterKey2::sign_first_message();

        let sign_msg1 = SignMsg1 {
            shared_key_id: user_id,
            eph_key_gen_first_message_party_two: eph_key_gen_first_message_party_two,
        };

        let (sign_party_one_first_message, _) :
                (party_one::EphKeyGenFirstMsg, party_one::EphEcKeyPair) = MasterKey1::sign_first_message();

        let serialized_m1 = serde_json::to_string(&sign_party_one_first_message).unwrap();

        let _m_1 = mockito::mock("POST", "/ecdsa/sign/first")
          .with_header("content-type", "application/json")
          .with_body(serialized_m1)
          .create();

        let return_msg = sc_entity.sign_first(sign_msg1).unwrap();

        assert_eq!(sign_party_one_first_message.public_share,return_msg.public_share);
        assert_eq!(sign_party_one_first_message.c,return_msg.c);

        let d_log_proof = ECDDHProof {
            a1: ECPoint::generator(),
            a2: ECPoint::generator(),
            z: ECScalar::new_random(),
        };
        let comm_witness = party_two::EphCommWitness {
            pk_commitment_blind_factor: BigInt::from(0),
            zk_pok_blind_factor: BigInt::from(1),
            public_share: ECPoint::generator(),
            d_log_proof: d_log_proof.clone(),
            c: ECPoint::generator(),
        };

        let sign_msg2 = SignMsg2 {
            shared_key_id: user_id,
            sign_second_msg_request: SignSecondMsgRequest {
                protocol: Protocol::Deposit,
                message: BigInt::from(0),
                party_two_sign_message: party2::SignMessage {
                    partial_sig: party_two::PartialSig {c3: BigInt::from(3)},
                    second_message: party_two::EphKeyGenSecondMsg {comm_witness: comm_witness},
                },
            },
        };

        let witness: Vec<Vec<u8>> = vec![vec![48, 68, 2, 32, 94, 197, 64, 97, 183, 140, 229, 202, 52, 141, 214, 128, 218, 92, 31, 159, 14, 192, 114, 167, 169, 166, 85, 208, 129, 89, 59, 72, 233, 119, 11, 69, 2, 32, 101, 93, 62, 147, 163, 225, 79, 143, 112, 88, 161, 251, 186, 215, 255, 67, 246, 19, 93, 17, 135, 235, 196, 111, 228, 236, 109, 196, 131, 192, 230, 245, 1], vec![3, 120, 158, 98, 241, 124, 29, 175, 68, 206, 87, 99, 45, 189, 226, 48, 73, 247, 39, 150, 105, 96, 216, 148, 31, 95, 159, 155, 255, 127, 61, 19, 169]];

        let serialized_m2 = serde_json::to_string(&witness).unwrap();
        let _m_2 = mockito::mock("POST", "/ecdsa/sign/second")
          .with_header("content-type", "application/json")
          .with_body(serialized_m2)
          .create();

        let return_msg = sc_entity.sign_second(sign_msg2).unwrap();

        assert_eq!(return_msg,witness);

    }

}
