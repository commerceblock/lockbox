use super::protocol::*;
use crate::config::Config;
use crate::Database;

use log::LevelFilter;
use log4rs::append::file::FileAppender;
use log4rs::config::{Appender, Config as LogConfig, Root as LogRoot};
use log4rs::encode::pattern::PatternEncoder;
use mockall::*;

use rocket;
use rocket::{
    http::{ContentType, Status},
    local::Client,
    config::{Config as RocketConfig, Environment},
    Request, Rocket,
};
use std::sync::{Arc, Mutex};
use uuid::Uuid;
use crate::protocol::ecdsa::Ecdsa;
use crate::enclave::Enclave;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub struct Lockbox<
    T: Database + Send + Sync + 'static,
> {
    pub config: Config,
    pub database: T,
    pub enclave: Enclave,
}

impl<
        T: Database + Send + Sync + 'static,
    > Lockbox<T>
{
    pub fn load(mut db: T) -> Result<Lockbox<T>> {
        // Get config as defaults, Settings.toml and env vars
        let config_rs = Config::load()?;
        db.set_connection_from_config(&config_rs)?;

        let enclave = Enclave::new().expect("failed to start enclave");

        let lbs = Self {
            config: config_rs,
            database: db,
            enclave
        };



        Ok(lbs)
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

pub fn get_server<
    T: Database + Send + Sync + 'static,
>(
    db: T,
) -> Result<Rocket> {
    let mut lbs = Lockbox::<T>::load(db)?;

    set_logging_config(&lbs.config.log_file);

    // Initialise DBs
    lbs.database.init()?;
    if lbs.config.testing_mode {
        info!("Server running in testing mode.");
        // reset dbs
        lbs.database.reset()?;
    }

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

/// Get postgres URL from env vars. Suffix can be "TEST", "W", or "R"
pub fn get_postgres_url(
    host: String,
    port: String,
    user: String,
    pass: String,
    database: String,
) -> String {
    format!(
        "postgresql://{}:{}@{}:{}/{}",
        user, pass, host, port, database
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use mockito;
    use crate::MockDatabase;
   
    fn get_mock_db() -> MockDatabase {
        let mut db = MockDatabase::new(); 
        db.expect_set_connection_from_config().returning(|_| Ok(()));
        db.expect_init().returning(|| Ok(()));
        db.expect_reset().returning(|| Ok(()));
        db
    }

    fn get_client(db : MockDatabase) -> Client {
        Client::new(get_server(db).expect("valid rocket instance")).expect("client")   
    }

    #[test]
    fn test_ping() {
        let mut db = get_mock_db(); 
        let client = get_client(db);
        let mut response = client
            .get("/ping")
            .dispatch();   
        assert_eq!(response.status(), Status::Ok);
    }

}
