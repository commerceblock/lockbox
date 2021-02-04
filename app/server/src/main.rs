extern crate server_lib;
use server_lib::{server, config};
    
fn main() {
    server::get_server(config::get_config()).unwrap();
}
