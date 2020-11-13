use rocket::http::Status;
//use crate::enclave::hello;
pub use super::super::Result;
use rocket::State;
use rocket_contrib::json::Json;
use cfg_if::cfg_if;
use crate::server::Lockbox;
use crate::error::LockboxError;

type LB = Lockbox;

#[post("/enclave/hello", format = "json", data = "<hello_message>")]
pub fn enclave_hello(
    lockbox: State<LB>,
    hello_message: Json<String>
) -> Result<Status> {
    // TODO: Add logic for health check
    let _msg = hello_message.into_inner();
    match lockbox.enclave.say_something(_msg){
    	  Ok(_) => Ok(Status::Ok),
	  Err(e) => Err(LockboxError::Generic(format!("enclave_hello: {}", e.to_string())).into())
    }

}

