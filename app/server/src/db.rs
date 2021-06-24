use rocksdb::{DB, Options as DBOptions, ColumnFamilyDescriptor};
use crate::config::Config;

#[cfg(test)] 
use tempdir::TempDir;
#[cfg(test)] 
use uuid::Uuid;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error>>;

pub fn get_db(config_rs: &Config) -> (DB, DB) {
    get_db_write_opt(config_rs, false)
}

pub fn get_db_read_only(config_rs: &Config) -> (DB, DB) {
    get_db_write_opt(config_rs, true)
}

pub fn get_db_write_opt(config_rs: &Config, readonly: bool) -> (DB, DB) {
    
    let path = config_rs.storage.db_path.to_owned();
    
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
   
    let key_db_path = config_rs.storage.key_db_path.to_owned();
            
        let mut key_db_opts = DBOptions::default();
        key_db_opts.create_missing_column_families(true);
        key_db_opts.create_if_missing(true);
        
        let mut key_db_cf_opts = DBOptions::default();	
        key_db_cf_opts.set_max_write_buffer_number(16);
        let mut key_db_column_families = Vec::<ColumnFamilyDescriptor>::new();
        key_db_column_families.push(ColumnFamilyDescriptor::new("enclave_id", cf_opts.clone()));
        key_db_column_families.push(ColumnFamilyDescriptor::new("enclave_key", cf_opts.clone()));

    
    if readonly{

	match DB::open_for_read_only(&db_opts, path, false) {
	    Ok(db) => {
            match DB::open_for_read_only(&key_db_opts, key_db_path, false) {
                Ok(key_db) => {
                   (db, key_db)
                },
                Err(e) => { panic!("failed to open key database: {:?}", e) }
            }
        },
	    Err(e) => { panic!("failed to open database: {:?}", e) }
	}
    } else {
	match DB::open_cf_descriptors(&db_opts, path, column_families) {
	    Ok(db) => {
            match DB::open_cf_descriptors(&key_db_opts, key_db_path, key_db_column_families) {
                Ok(key_db) => {
                    (db, key_db)
                },
                Err(e) => { panic!("failed to open key database: {:?}", e) }
            }
        },
	    Err(e) => { panic!("failed to open database: {:?}", e) }
	}
    }
}


