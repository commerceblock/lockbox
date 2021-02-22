# Server Integration 

Generates the shared encryption key between two running enclaves.

## Build

```cargo build --release```

## Generate shared key

Lockbox source and destination URLs specified as `LOCKBOX_URL_SRC` and `LOCKBOX_URL_DST`.

```target/release/init_shared_exec```
