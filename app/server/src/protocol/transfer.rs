//! Lockbox Transfer
//!
//! Lockbox Transfer protocol trait and implementation.

pub use super::super::Result;
extern crate shared_lib;
use shared_lib::{state_chain::*, structs::*};

use crate::error::LockboxError;
use crate::server::Lockbox;

use bitcoin::Transaction;
use rocket::State;
use rocket_contrib::json::Json;
use uuid::Uuid;
use curv::{
    arithmetic::traits::Converter,
    elliptic::curves::traits::ECPoint,
    {BigInt, FE, GE}
};
type LB = Lockbox;

/// Struct holds data when transfer is complete but not yet finalized
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TransferFinalizeData {
    pub new_shared_key_id: Uuid,
    pub state_chain_id: Uuid,
    pub state_chain_sig: StateChainSig,
    pub s2: FE,
    pub theta: FE,
    pub new_tx_backup: Transaction,
    pub batch_data: Option<BatchData>,
}

/// StateChain Transfer protocol trait
pub trait Transfer {
    /// API: Initiliase transfer protocol:
    ///     - Authorisation of Owner and DoS protection
    ///     - Validate transfer parameters
    ///     - Store transfer parameters
    fn transfer_sender(&self, transfer_msg1: TransferMsg1) -> Result<TransferMsg2>;

    /// API: Transfer shared wallet to new Owner:
    ///     - Check new Owner's state chain is correct
    ///     - Perform 2P-ECDSA key rotation
    ///     - Return new public shared key S2
    fn transfer_receiver(&self, transfer_msg4: TransferMsg4) -> Result<TransferMsg5>;

    /// Update DB and SMT after successful transfer.
    /// This function is called immediately in the regular transfer case or after confirmation of atomic
    /// transfers completion in the batch transfer case.
    fn transfer_finalize(&self, finalized_data: &TransferFinalizeData) -> Result<()>;

    /// API: Update the state entity database with transfer message 3
    fn transfer_update_msg(&self, transfer_msg3: TransferMsg3) -> Result<()>;

    /// API: Get the transfer message 3 set by update_transfer_msg
    fn transfer_get_msg(&self, state_chain_id: Uuid) -> Result<TransferMsg3>;
}

impl Transfer for LB {
    fn transfer_sender(&self, _transfer_msg1: TransferMsg1) -> Result<TransferMsg2> {
       Err(LockboxError::Generic("unimplemented".to_string()))
    }

    fn transfer_receiver(&self, _transfer_msg4: TransferMsg4) -> Result<TransferMsg5> {
       Err(LockboxError::Generic("unimplemented".to_string()))
    }

    /// Update DB and SMT after successful transfer.
    /// This function is called immediately in the regular transfer case or after confirmation of atomic
    /// transfers completion in the batch transfer case.
    fn transfer_finalize(&self, _finalized_data: &TransferFinalizeData) -> Result<()> {
       Err(LockboxError::Generic("unimplemented".to_string()))
    }

    /// API: Update the state entity database with transfer message 3
    fn transfer_update_msg(&self, _transfer_msg3: TransferMsg3) -> Result<()> {
       Err(LockboxError::Generic("unimplemented".to_string()))
    }

    /// API: Get the transfer message 3 set by update_transfer_msg
    fn transfer_get_msg(&self, _state_chain_id: Uuid) -> Result<TransferMsg3> {
       Err(LockboxError::Generic("unimplemented".to_string()))
    }
}

#[post("/transfer/sender", format = "json", data = "<transfer_msg1>")]
pub fn transfer_sender(
    lockbox: State<LB>,
    transfer_msg1: Json<TransferMsg1>,
) -> Result<Json<TransferMsg2>> {
    match lockbox.transfer_sender(transfer_msg1.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/transfer/receiver", format = "json", data = "<transfer_msg4>")]
pub fn transfer_receiver(
    lockbox: State<LB>,
    transfer_msg4: Json<TransferMsg4>,
) -> Result<Json<TransferMsg5>> {
    match lockbox.transfer_receiver(transfer_msg4.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/transfer/update_msg", format = "json", data = "<transfer_msg3>")]
pub fn transfer_update_msg(
    lockbox: State<LB>,
    transfer_msg3: Json<TransferMsg3>,
) -> Result<Json<()>> {
    match lockbox.transfer_update_msg(transfer_msg3.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

#[post("/transfer/get_msg", format = "json", data = "<state_chain_id>")]
pub fn transfer_get_msg(
    lockbox: State<LB>,
    state_chain_id: Json<Uuid>,
) -> Result<Json<TransferMsg3>> {
    match lockbox.transfer_get_msg(state_chain_id.into_inner()) {
        Ok(res) => return Ok(Json(res)),
        Err(e) => return Err(e),
    }
}

