use qr_dlt_crypto::Address;
use serde::{Deserialize, Serialize};

/// Deterministic validator set implementing round-robin Proof-of-Authority slot assignment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ValidatorSet {
    validators: Vec<Address>,
}

impl ValidatorSet {
    pub fn new(validators: Vec<Address>) -> Self {
        Self { validators }
    }

    /// Determines the authorized validator address scheduled to propose at `height`.
    pub fn get_proposer_for_height(&self, height: u64) -> Option<Address> {
        if self.validators.is_empty() {
            return None;
        }
        // Height 1 -> index 0, Height 2 -> index 1, etc.
        let idx = ((height.saturating_sub(1)) as usize) % self.validators.len();
        Some(self.validators[idx])
    }

    pub fn validators(&self) -> &[Address] {
        &self.validators
    }

    pub fn len(&self) -> usize {
        self.validators.len()
    }

    pub fn is_empty(&self) -> bool {
        self.validators.is_empty()
    }
}
