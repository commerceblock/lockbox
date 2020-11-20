/// Each State in the Chain of States
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone)]
pub struct State {
    pub data: String,                      // proof key or address
    pub next_state: Option<StateChainSig>, // signature representing passing of ownership
}
/// Data necessary to create ownership transfer signatures
#[derive(Serialize, Deserialize, Debug, PartialEq, Clone, Default, Hash, Eq)]
pub struct StateChainSig {
    pub purpose: String, // "TRANSFER", "TRANSFER-BATCH" or "WITHDRAW"
    pub data: String,    // proof key, state chain id or address
    sig: String,
}
