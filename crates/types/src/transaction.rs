use crate::intent::TxIntent;
use crate::witness::WitnessProof;
use qr_dlt_crypto::CryptoError;
use serde::{Deserialize, Serialize};

/// Full transaction pairing decoupled TxIntent with its corresponding WitnessProof.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub intent: TxIntent,
    pub witness: WitnessProof,
}

impl Transaction {
    pub fn new(intent: TxIntent, witness: WitnessProof) -> Self {
        Self { intent, witness }
    }

    /// Produces a deterministic BLAKE3 commitment hash for the intent.
    pub fn intent_hash(&self) -> [u8; 32] {
        self.intent.hash()
    }

    /// Produces a deterministic BLAKE3 commitment hash for the witness proof.
    pub fn witness_hash(&self) -> [u8; 32] {
        self.witness.hash()
    }

    /// Verifies that:
    /// 1. The witness public key corresponds to the intent sender address.
    /// 2. The witness signature is valid over the intent commitment hash.
    pub fn verify_signature(&self) -> Result<(), CryptoError> {
        let derived_addr = self.witness.recover_address();
        if derived_addr != self.intent.sender_address {
            return Err(CryptoError::VerificationFailed);
        }
        let intent_hash = self.intent_hash();
        self.witness.verify(&intent_hash)
    }
}
