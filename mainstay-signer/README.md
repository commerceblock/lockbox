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
db-uri = "postgres://postgres:pass@localhost:5432/sealed_data_db"
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
