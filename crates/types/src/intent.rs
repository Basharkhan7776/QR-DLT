use serde::{Deserialize, Serialize};

/// Decoupled transaction intent containing state mutation parameters without witness proofs.
#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct TxIntent {
    pub nonce: u64,
    pub sender_address: [u8; 20],
    pub recipient_address: [u8; 20],
    pub amount: u64,
    pub fee: u64,
}

impl TxIntent {
    /// Computes the deterministic BLAKE3 commitment hash for this intent.
    pub fn hash(&self) -> [u8; 32] {
        let serialized = bincode::serialize(self).expect("serialization of TxIntent cannot fail");
        *blake3::hash(&serialized).as_bytes()
    }
}
