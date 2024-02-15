# Mainstay signer seed initialisation

## Key recovery

Edit the file `src/main.rs` and enter the mnemonic:

```
let mnemonic = "vintage endorse comic voyage metal grape abandon beauty battle dream warfare stomach hole spread resist pact dizzy interest crunch trap address device icon town".to_string();
```

Save and run `cargo run` to output the seed share:

```
Decoded private key: "f42938b97b08c0cb80009d134853dc6b16cba62ddcf5402eb4d3f3a036795c17"
```

## Initialisation

SSH into the lockbox machine. 

Enter the command with seed share:

```
curl --data "f42938b97b08c0cb80009d134853dc6b16cba62ddcf5402eb4d3f3a036795c17" http://localhost:8000/initialize/signing
```