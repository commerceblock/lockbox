extern crate server_lib;
use server_lib::{server, Database, PGDatabase};

fn main() {
    server::get_server::<PGDatabase>(
        PGDatabase::get_new(),
    )
    .unwrap()
    .launch();
}
