//! Transfer
//!
//! Transfer coins in state entity to new owner

// transfer() messages:
// 0. Receiver communicates address to Sender (B2 and C2)
// 1. Sender Initialises transfer protocol with State Entity
//      a. init, authorisation, provide receivers proofkey C2
//      b. State Entity generates x1 and sends to Sender
//      c. Sender and State Entity Co-sign new back up transaction sending to Receivers
//          backup address Addr(B2)
// 2. Receiver performs transfer with State Entity
//      a. Verify state chain is updated
//      b. calculate t1=01x1
//      c. calucaulte t2 = t1*o2_inv
//      d. Send t2, O2 to state entity
//      e. Verify o2*S2 = P

use super::super::Result;

use crate::error::{CError, WalletErrorType};
use crate::state_entity::{
    api::{get_smt_proof, get_smt_root, get_statechain, get_statechain_fee_info},
    util::{cosign_tx_input, verify_statechain_smt},
};
use crate::wallet::{key_paths::funding_txid_to_int, wallet::Wallet};
use crate::{utilities::requests, ClientShim};
use shared_lib::{ecies::WalletDecryptable, state_chain::StateChainSig, structs::*, util::{transaction_serialise, transaction_deserialise}};

use bitcoin::{Address, PublicKey};
use curv::elliptic::curves::traits::{ECPoint, ECScalar};
use curv::{FE, GE};
use std::str::FromStr;
use uuid::Uuid;

/// Transfer coins to new Owner from this wallet
pub fn transfer_sender(
    wallet: &mut Wallet,
    statechain_id: &Uuid,
    receiver_addr: SCEAddress,
) -> Result<TransferMsg3> {
    // Get required shared key data
    let shared_key_id;
    let mut prepare_sign_msg;
    {
        let shared_key = wallet.get_shared_key_by_statechain_id(statechain_id)?;
        shared_key_id = shared_key.id.clone();
        prepare_sign_msg = shared_key
            .tx_backup_psm
            .clone()
            .ok_or(CError::WalletError(WalletErrorType::KeyMissingData))?;
    }

    // Get state entity fee and locktime info
    let se_fee_info = get_statechain_fee_info(&wallet.client_shim)?;

    // First sign state chain
    let statechain_data: StateChainDataAPI = get_statechain(&wallet.client_shim, &statechain_id)?;
    let state_chain = statechain_data.chain;
    // Get proof key for signing
    let proof_key_derivation = wallet
        .se_proof_keys
        .get_key_derivation(&PublicKey::from_str(&state_chain.last().unwrap().data).unwrap());
    let statechain_sig = StateChainSig::new(
        &proof_key_derivation
            .ok_or(CError::WalletError(WalletErrorType::KeyNotFound))?
            .private_key
            .key,
        &String::from("TRANSFER"),
        &receiver_addr.proof_key.clone().to_string(),
    )?;

    // Init transfer: Send statechain signature or batch data
    let mut transfer_msg2: TransferMsg2 = requests::postb(
        &wallet.client_shim,
        &format!("transfer/sender"),
        &TransferMsg1 {
            shared_key_id: shared_key_id.to_owned(),
            statechain_sig: statechain_sig.clone(),
        },
    )?;

    wallet.decrypt(&mut transfer_msg2)?;

    let mut tx = transaction_deserialise(&prepare_sign_msg.tx_hex)?;

    // Update prepare_sign_msg with new owners address, proof key
    prepare_sign_msg.protocol = Protocol::Transfer;
    match tx.output.get_mut(0) {
        Some(v) => match receiver_addr.tx_backup_addr.clone() {
            Some(v2) => v.script_pubkey = v2.script_pubkey(),
            None => (),
        },
        None => (),
    };
    prepare_sign_msg.proof_key = Some(receiver_addr.proof_key.clone().to_string());
    //set updated decremented locktime
    tx.lock_time = statechain_data.locktime - se_fee_info.interval;
    prepare_sign_msg.tx_hex = transaction_serialise(&tx);

    // Sign new back up tx
    let new_backup_witness = cosign_tx_input(wallet, &prepare_sign_msg)?;

    let mut tx = transaction_deserialise(&prepare_sign_msg.tx_hex)?;
    // Update back up tx with new witness
    tx.input[0].witness = new_backup_witness;
    prepare_sign_msg.tx_hex = transaction_serialise(&tx);

    // Get o1 priv key
    let shared_key = wallet.get_shared_key(&shared_key_id)?;
    let o1 = shared_key.share.private.get_private_key();

    // t1 = o1x1
    let x1 = transfer_msg2.x1.get_fe()?;
    let t1 = o1 * x1;
    let t1_encryptable = FESer::from_fe(&t1);

    let mut transfer_msg3 = TransferMsg3 {
        shared_key_id: shared_key_id.to_owned(),
        t1: t1_encryptable,
        statechain_sig,
        statechain_id: statechain_id.to_owned(),
        tx_backup_psm: prepare_sign_msg.to_owned(),
        rec_se_addr: receiver_addr,
    };

    //encrypt then make immutable
    transfer_msg3.encrypt()?;
    let transfer_msg3 = transfer_msg3;

    // Mark funds as spent in wallet
    {
        let mut shared_key = wallet.get_shared_key_mut(&shared_key_id)?;
        shared_key.unspent = false;
    }

    //store transfer_msg_3 in db

    // Update server database with transfer message 3 so that
    // the receiver can get the message
    requests::postb(
        &wallet.client_shim,
        &format!("transfer/update_msg"),
        &transfer_msg3,
    )?;

    Ok(transfer_msg3)
}

// Get the transfer message 3
// created by the sender and stored in the SE database
pub fn transfer_get_msg(wallet: &mut Wallet, statechain_id: &Uuid) -> Result<TransferMsg3> {
    requests::postb(
        &wallet.client_shim,
        &format!("transfer/get_msg"),
        &statechain_id,
    )
}

/// Receiver side of Transfer protocol.
pub fn transfer_receiver(
    wallet: &mut Wallet,
    transfer_msg3: &mut TransferMsg3,
    batch_data: &Option<BatchData>,
) -> Result<TransferFinalizeData> {
    //Decrypt the message on receipt
    match wallet.decrypt(transfer_msg3) {
        Ok(_) => (),
        Err(e) => {
            return Err(CError::Generic(format!(
                "error decrypting message: {}",
                e.to_string()
            )))
        }
    };
    //Make immutable
    let transfer_msg3 = &*transfer_msg3;
    // Get statechain data (will Err if statechain not yet finalized)
    let statechain_data: StateChainDataAPI =
        get_statechain(&wallet.client_shim, &transfer_msg3.statechain_id)?;

    let tx_backup = transaction_deserialise(&transfer_msg3.tx_backup_psm.tx_hex)?;
    // Ensure backup tx funds are sent to address owned by this wallet
    let back_up_rec_se_addr = Address::from_script(
        &tx_backup.output[0].script_pubkey,
        wallet.get_bitcoin_network(),
    )
    .ok_or(CError::Generic(String::from(
        "Failed to decode ScriptpubKey.",
    )))?;
    wallet
        .se_backup_keys
        .get_address_derivation(&back_up_rec_se_addr.to_string())
        .ok_or(CError::Generic(String::from(
            "Backup Tx receiving address not found in this wallet!",
        )))?;

    // Check locktime of recieved backup transaction
    let chaintip = wallet
        .electrumx_client
        .instance
        .get_tip_header()?;
    debug!("Transfer receiver: Got current best block height: {}", chaintip.height.to_string());
    if tx_backup.lock_time <= (chaintip.height as u32) {
            return Err(CError::Generic(format!(
                "Error: backup tx locktime ({:?}) expired, blockheight {:?}",tx_backup.lock_time,chaintip.height
            )));
    }

    // Check validity of the backup transaction
    // check inputs
    // check signatures
    // TODO

    // Verify state chain represents this address as new owner
    let prev_owner_proof_key = statechain_data.chain.last().unwrap().data.clone();
    transfer_msg3
        .statechain_sig
        .verify(&prev_owner_proof_key)?;
    debug!("State chain signature is valid.");

    // Check signature is for proof key owned by this wallet
    let new_owner_proof_key = transfer_msg3.statechain_sig.data.clone();
    wallet
        .se_proof_keys
        .get_key_derivation(&PublicKey::from_str(&new_owner_proof_key).unwrap())
        .ok_or(CError::Generic(String::from(
            "Transfer Error: StateChain is signed over to proof key not owned by this wallet!",
        )))?;



    // Check try_o2() comments and docs for justification of below code
    let mut done = false;
    let mut transfer_msg5 = TransferMsg5::default();
    let mut o2 = FE::zero();
    let mut num_tries = 0;
    // t1 in transfer_msg3 is ECIES encrypted.
    // t1 is decrypted here before passing to try_o2 because try_o2 could
    // be executed multiple times and t1 is a constant
    let t1 = match transfer_msg3.t1.get_fe() {
        Ok(r) => r,
        Err(e) => {
            return Err(CError::Generic(format!(
                "Failed to get FE from transfer_msg_3 {:?} error: {}",
                transfer_msg3,
                e.to_string()
            )))
        }
    };
    while !done {
        match try_o2(
            wallet,
            &statechain_data,
            &transfer_msg3,
            &t1,
            &num_tries,
            batch_data,
        ) {
            Ok(success_resp) => {
                o2 = success_resp.0.clone();
                transfer_msg5 = success_resp.1.clone();
                done = true;
            }
            Err(e) => {
                if !e.to_string().contains(&String::from("try again")) {
                    return Err(e);
                }
                num_tries = num_tries + 1;
                debug!("try o2 failure. Trying again...");
            }
        }
    }

    // Update tx_backup_psm shared_key_id with new one
    let mut tx_backup_psm = transfer_msg3.tx_backup_psm.clone();
    tx_backup_psm.shared_key_id = transfer_msg5.new_shared_key_id.clone();

    // Data to update wallet with transfer. Should only be applied after StateEntity has finalized.
    let finalize_data = TransferFinalizeData {
        new_shared_key_id: transfer_msg5.new_shared_key_id,
        o2,
        s2_pub: transfer_msg5.s2_pub,
        statechain_data,
        proof_key: transfer_msg3.rec_se_addr.proof_key.clone().to_string(),
        statechain_id: transfer_msg3.statechain_id,
        tx_backup_psm,
    };

    // In batch case this step is performed once all other transfers in the batch are complete.
    if batch_data.is_none() {
        // Finalize protocol run by generating new shared key and updating wallet.
        transfer_receiver_finalize(wallet, finalize_data.clone())?;
    }

    Ok(finalize_data)
}

// Constraint on s2 size means that some (most) o2 values are not valid for the lindell_2017 protocol.
// We must generate random o2, test if the resulting s2 is valid and try again if not.
/// Carry out transfer_receiver() protocol with a randomly generated o2 value.
pub fn try_o2(
    wallet: &mut Wallet,
    statechain_data: &StateChainDataAPI,
    transfer_msg3: &TransferMsg3,
    t1: &FE,
    num_tries: &u32,
    batch_data: &Option<BatchData>,
) -> Result<(FE, TransferMsg5)> {
    // generate o2 private key and corresponding 02 public key
    let mut encoded_txid = num_tries.to_string();
    encoded_txid.push_str(&statechain_data.utxo.txid.to_string());
    let funding_txid_int = match funding_txid_to_int(&encoded_txid) {
        Ok(r) => r,
        Err(e) => {
            return Err(CError::Generic(format!(
                "Failed to get funding txid int from statechain_data: {:?} error: {}",
                statechain_data,
                e.to_string()
            )))
        }
    };
    let mut o2: FE = ECScalar::zero();
    let _key_share_pub = match wallet
        .se_key_shares
        .get_new_key_encoded_id(funding_txid_int, Some(&mut o2))
    {
        Ok(r) => r,
        Err(e) => {
            return Err(CError::Generic(format!(
                "Failed to get new key encoded id from funding_txid_int: {} error: {}",
                funding_txid_int,
                e.to_string()
            )))
        }
    };

    let g: GE = ECPoint::generator();
    let o2_pub: GE = g * o2;

    // t2 = t1*o2_inv = o1*x1*o2_inv

    let t2 = *t1 * (o2.invert());
    // encrypt t2 with SE key and sign with Receiver proof key (se_addr.proof_key)

    let msg4 = &mut TransferMsg4 {
        shared_key_id: transfer_msg3.shared_key_id,
        statechain_id: transfer_msg3.statechain_id,
        t2,
        statechain_sig: transfer_msg3.statechain_sig.clone(),
        o2_pub,
        tx_backup_hex: transfer_msg3.tx_backup_psm.tx_hex.clone(),
        batch_data: batch_data.to_owned(),
    };

    let transfer_msg5: TransferMsg5 =
        requests::postb(&wallet.client_shim, &format!("transfer/receiver"), msg4)?;
    Ok((o2, transfer_msg5))
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TransferFinalizeData {
    pub new_shared_key_id: Uuid,
    pub o2: FE,
    pub s2_pub: GE,
    pub statechain_data: StateChainDataAPI,
    pub proof_key: String,
    pub statechain_id: Uuid,
    pub tx_backup_psm: PrepareSignTxMsg,
}

/// Finalize protocol run by generating new shared key and updating wallet.
/// This function is called immediately in the regular transfer case or after confirmation of atomic
/// transfers completion in the batch transfer case.
pub fn transfer_receiver_finalize(
    wallet: &mut Wallet,
    finalize_data: TransferFinalizeData,
) -> Result<()> {
    // Make shared key with new private share
    wallet.gen_shared_key_fixed_secret_key(
        &finalize_data.new_shared_key_id,
        &finalize_data.o2.get_element(),
        &finalize_data.statechain_data.amount,
    )?;

    // Check shared key master public key == private share * SE public share
    if (finalize_data.s2_pub * finalize_data.o2).get_element()
        != wallet
            .get_shared_key(&finalize_data.new_shared_key_id)?
            .share
            .public
            .q
            .get_element()
    {
        return Err(CError::StateEntityError(String::from(
            "Transfer failed. Incorrect master public key generated.",
        )));
    }

    // TODO when node is integrated: Should also check that funding tx output address is address derived from shared key.
    let rec_proof_key = finalize_data.proof_key.clone();

    // Verify proof key inclusion in SE sparse merkle tree
    let root = get_smt_root(&wallet.client_shim)?.unwrap();
    let funding_txid = &finalize_data.statechain_data.utxo.txid.to_string();
    let proof = get_smt_proof(&wallet.client_shim, &root, funding_txid)?;
    assert!(verify_statechain_smt(
        &Some(root.hash()),
        &rec_proof_key,
        &proof
    ));

    // Add state chain id, proof key and SMT inclusion proofs to local SharedKey data
    {
        let shared_key = wallet.get_shared_key_mut(&finalize_data.new_shared_key_id)?;
        shared_key.statechain_id = Some(finalize_data.statechain_id);
        shared_key.tx_backup_psm = Some(finalize_data.tx_backup_psm.clone());
        shared_key.add_proof_data(&rec_proof_key, &root, &proof, funding_txid);
    }

    Ok(())
}

/// Sign data signalling intention to carry out transfer_batch protocol with given state chain
pub fn transfer_batch_sign(
    wallet: &mut Wallet,
    statechain_id: &Uuid,
    batch_id: &Uuid,
) -> Result<StateChainSig> {
    // First sign state chain
    let statechain_data: StateChainDataAPI = get_statechain(&wallet.client_shim, &statechain_id)?;
    let state_chain = statechain_data.chain;
    // Get proof key for signing
    let proof_key_derivation = wallet
        .se_proof_keys
        .get_key_derivation(&PublicKey::from_str(&state_chain.last().unwrap().data).unwrap());

    match StateChainSig::new_transfer_batch_sig(
        &proof_key_derivation.unwrap().private_key.key,
        &batch_id,
        &statechain_id,
    ) {
        Ok(r) => Ok(r),
        Err(e) => Err(e.into()),
    }
}

/// Request StateEntity start transfer_batch protocol
pub fn transfer_batch_init(
    client_shim: &ClientShim,
    signatures: &Vec<StateChainSig>,
    batch_id: &Uuid,
) -> Result<()> {
    requests::postb(
        &client_shim,
        &format!("transfer/batch/init  "),
        &TransferBatchInitMsg {
            id: batch_id.clone(),
            signatures: signatures.clone(),
        },
    )
}

/// Reveal nonce to State Entity. Used when transfer batch has failed and punishment is removed
/// from honest participants.
pub fn transfer_reveal_nonce(
    client_shim: &ClientShim,
    statechain_id: &Uuid,
    batch_id: &Uuid,
    hash: &String,
    nonce: &[u8; 32],
) -> Result<()> {
    requests::postb(
        &client_shim,
        &format!("transfer/batch/reveal"),
        &TransferRevealNonce {
            batch_id: batch_id.to_owned(),
            hash: hash.to_owned(),
            statechain_id: statechain_id.to_owned(),
            nonce: nonce.to_owned(),
        },
    )
}

#[cfg(test)]
mod tests {

    // use curv::elliptic::curves::traits::{ECPoint, ECScalar};
    // use curv::{FE, GE};

    // #[test]
    // fn math() {
    //     let g: GE = ECPoint::generator();
    //
    //     //owner1 share
    //     let o1_s: FE = ECScalar::new_random();
    //     let o1_p: GE = g * o1_s;
    //
    //     // SE share
    //     let s1_s: FE = ECScalar::new_random();
    //     let s1_p: GE = g * s1_s;
    //
    //     // deposit P
    //     let p_p = s1_p*o1_s;
    //     println!("P1: {:?}",p_p);
    //     let p_p = o1_p*s1_s;
    //     println!("P1: {:?}",p_p);
    //
    //
    //     // transfer
    //     // SE new random key x1
    //     let x1_s: FE = ECScalar::new_random();
    //
    //     // owner2 share
    //     let o2_s: FE = ECScalar::new_random();
    //     let o2_p: GE = g * o2_s;
    //
    //     // t1 = o1*x1*o2_inv
    //     let t1 = o1_s*x1_s*(o2_s.invert());
    //
    //     // t2 = t1*x1_inv*s1
    //     let s2_s = t1*(x1_s.invert())*s1_s;
    //
    //     println!("P2: {:?}",o2_p*s2_s);
    // }
}
