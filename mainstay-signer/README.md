# Mainstay Signer

The Mainstay Signer is an HTTP server designed to facilitate the signing of Mainstay transactions.

### Setup Instructions:

1. Begin by setting up Fortanix EDP by following the instructions provided in the [guide](https://edp.fortanix.com/docs/installation/guide/).

2. Next, set up PostgreSQL on your system.

3. Create database named `sealed_data_db` using the following SQL command:-

```
CREATE DATABASE sealed_data_db;
```

4. Create a table named `sealed_data` in the `sealed_data_db` database by executing the following SQL query in the PostgreSQL prompt:-

```
CREATE TABLE sealed_data (
    id SERIAL PRIMARY KEY,
    label TEXT NOT NULL,
    nonce TEXT NOT NULL,
    cipher TEXT NOT NULL,
    key_type TEXT UNIQUE CHECK (key_type IN ('topup', 'signing'))
);
```

5. Proceed to set up PostgREST by referring to the [guide](https://postgrest.org/en/v12/tutorials/tut0.html#step-4-create-database-for-api).

6. Create a configuration file named `postgrest.conf` for PostgREST and configure it as follows:-

```
db-uri = "postgres://postgres:[your-password]@localhost:5432/sealed_data_db"
db-schemas = "public"
db-anon-role = "postgres"
```

6. Launch PostgREST with the configured settings:-

```
./postgrest postgrest.conf
```

### Instructions for execution:

1. Install the required dependencies by running:

```
cargo build
```

2. Start the server:

```
cargo run main.rs
```

## API documentation

### For initializing the keys (minimum 2 shares required out of 3 with proper share indexes):- 
request:-
```
curl --data "share_string_1:share_index_for_string_1" http://localhost:8000/initialize/signing

curl --data "share_string_2:share_index_for_string_2" http://localhost:8000/initialize/signing
```

### For signing:-
request:-
```
curl --location 'http://127.0.0.1:8000/sign' \
--header 'Content-Type: application/json' \
--data '{
    "sighash_string": ["CALCULATED_WITNESS_SIGHASH_FOR_TX"],
    "merkle_root": "MERKLE_ROOT"
}'
```
response:-
```
{
    "witness": ["WITNESS_SIGNATURE"]
}
