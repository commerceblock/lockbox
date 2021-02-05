//! Requests
//!
//! Send requests and decode responses

use floating_duration::TimeFormat;
use serde;
use std::time::Instant;

use crate::client::Lockbox;
use super::super::Result;
use crate::error::LockboxError;

pub fn post_lb<T, V>(lockbox: &Lockbox, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    _post_lb(lockbox, path, body)
}

fn _post_lb<T, V>(lockbox: &Lockbox, path: &str, body: T) -> Result<V>
where
    T: serde::ser::Serialize,
    V: serde::de::DeserializeOwned,
{
    std::thread::sleep(std::time::Duration::from_millis(100));
    let start = Instant::now();

    // catch reqwest errors
    let value = match lockbox.client.post(&format!("{}/{}", lockbox.endpoint, path)).json(&body).send() 
    {
        Ok(v) => {
            //Reject responses that are too long
            match v.content_length() {
                Some(l) => {
                    if l > 1000000 {
                        info!("Lockbox POST value ignored because of size: {}", l);
                        return Err(LockboxError::Generic(format!(
                            "Lockbox POST value ignored because of size: {}",
                            l
                        )));
                    }
                }
                None => (),
            };

            let text = v.text()?;

            text
        }
        Err(e) => return Err(LockboxError::from(e)),
    };

    info!("Lockbox request {}, took: {})", path, TimeFormat(start.elapsed()));
    Ok(serde_json::from_str(value.as_str()).unwrap())
}

pub fn get_lb<V>(lockbox: &Lockbox, path: &str) -> Result<V>
where
    V: serde::de::DeserializeOwned,
{
    std::thread::sleep(std::time::Duration::from_millis(100));
    let start = Instant::now();

    let mut b = lockbox
        .client
        .get(&format!("{}/{}", lockbox.endpoint, path));

    // catch reqwest errors
    let value = match b.send() {
        Ok(v) => v.text().unwrap(),
        Err(e) => return Err(LockboxError::from(e)),
    };

    info!("GET return value: {:?}", value);

    info!("(req {}, took: {})", path, TimeFormat(start.elapsed()));

    // catch State entity errors
    if value.contains(&String::from("Error: ")) {
        return Err(LockboxError::Generic(value));
    }

    Ok(serde_json::from_str(value.as_str()).unwrap())
}
