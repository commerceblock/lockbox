# Lockbox: Intel SGX design for Mercury server key-share security

This document describes the high level design and protocol for the management of Mercury server secret key shares using SGX secure enclaves (trusted execution environments). 

The motivation for this design is to ensure two crucial properties: 

1. That the server key share is secured, even from an attacker that has root access to the server or physical access to the hardware. 
2. The server key shares are securely deleted (or become unrecoverable) when they expire (i.e. the ownership of a state coin moves to a new user. 

SGX enclaves can achieve both of these properties by generating, updating and using the statecoin server key shares exclusively within secure enclaves. In this case, the server key shares can never leave an enclave and only be updated and used in two-party signing operations when authenticated with a statecoin owner public key - even the system admin and developers with root access would be unable to either extract a key or perform an unauthenticated two-party signing operation. 

## Mercury server archecture

The lockbox is a separate application to the main Mercury server that performs all server private key share generation and operations, and stores the server private key shares in a secured way (sealed). The main server application handles all communication with user wallets, all the statechain (proof and commitment) operations and backup system (watching). The main server (which can be replicated) calls the Lockbox server whenever a private key share operation is required: these operations are:

1. Server key share generation, verification and pubkey derivation upon user deposit (`master_key`, `first_message`, `second_message`). 
2. Backup transaction co-signing on both deposit and transfer (`sign_first` and `sign_second`). 
3. Key share transfer, update and deletion. (generation of `x1` in `transfer_init` and `s2` share update and deletion in `transfer_receiver`). 

To provide additional protections against malicious access to the unprotected server and physical access to the lockbox machine - the lockbox enclave can also perform verification of the any transaction signed, to ensure that `nLocktime` is decremented correctly (storing the latest `nLocktime` state for each key share). The transaction pre-image and sighash would be deserialised within the enclave and verified. 

<br><br>
<p align="center">
<img src="images/fig1.png" align="middle" width="550" vspace="20">
</p>

<p align="center">
  <b>Fig. 1</b>: Schematic of the Mercury statechain infrastructure. 
</p>
<br><br>

## SGX Application Architecture considerations

The use of a secure SGX enclave limits execution of enclave code to a single, specific Intel CPU. An enclave cannot be replicated on several machines, and is confined to the CPU it was created on (however, enclaves can share secrets with other enclaves on different machines if that is what it is programmed to do). 

Therefore, the enclave-specific operations should be separated (onto a specific Intel CPU machine) from the main server operations, which are continuously serving the public API and can be dynamically replicated depending on demand/load. 

All of the server key share operations will then take place in the separate bare-metal machine, which communicates with the main server. 

The server private key share operations will be performed by a separate daemon which will run two separate threads using SGX instructions and functions: an untrusted thread that has full system access and can send and receive messages with the main server, and a trusted thread (the enclave) which is inaccessible to the rest of the system and can only be interacted with via function calls from the untrusted thread (`Ecalls`). 

The state of the trusted thread (enclave) can be stored persistently on disk via the SGX sealing process (i.e. secrets are encrypted with enclave keys) to handle both large numbers of key shares and system shut downs. 

<br><br>
<p align="center">
<img src="images/fig2.png" align="middle" width="400" vspace="20">
</p>

<p align="center">
  <b>Fig. 2</b>: Schematic of the Lockbox set-up and connections. 
</p>
<br><br>


Summary of changes to server secrets:

```
	x1 generated in enclave
	s2 generated in enclave (removed from Table::UserSession)
	paillierkeypair generated in enclave (removed from Table::Ecdsa)
	paillierkeypair generated in enclave (removed from Table::Ecdsa)
	party1private generated in enclave (removed from Table::Ecdsa)
	epheckeypair generated in enclave (removed from Table::Ecdsa)
```

The enclave secrets will be sealed and stored on the SGX enabled machine after each operation. 

Lockbox server will be called to perform operations in:

```
	master_key
	first_message
	second_message
    sign_first [and verification of pre-image nLocktime decrement]
    sign_second [and verification of pre-image nLocktime decrement]
	transfer_receiver [with attestation of key share deletion]
```

## Lockbox-server communication

Required high performance and a request-reply and push-pull pattern supporting multi-threading and message queuing. ZeroMQ satisfies these requirements. 

The main server will request the Lockbox server to perform specified operations as they are required according to, in turn, by operations requested by user wallets via the public API. 

## Attestation

Attestation is the process of proving that a specified program has been run on a specific machine. For Intel SGX, this is a mechanism that can be used to prove to third parties that specific cryptographic operations have been performed in a specified way within an enclave. For the Mercury protocol, this process can be used to prove to a user/public that two party key shares have been generated within the enclave in a specified way, and old shares deleted when updated in a way that they cannot be recovered. This attestation can be verified by users. 

