use crate::error::StorageError;
use qr_dlt_types::TxIntent;
use serde::{Deserialize, Serialize};

/// Account state tracking liquid balance and transaction sequence nonce.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct AccountState {
    pub balance: u64,
    pub nonce: u64,
}

impl AccountState {
    pub fn new(balance: u64, nonce: u64) -> Self {
        Self { balance, nonce }
    }

    /// Verifies and applies a debit for the sending account.
    pub fn apply_debit(&mut self, intent: &TxIntent) -> Result<(), StorageError> {
        let expected_nonce = self.nonce + 1;
        if intent.nonce != expected_nonce {
            return Err(StorageError::InvalidNonce {
                expected: expected_nonce,
                actual: intent.nonce,
            });
        }

        let total_deduction = intent.amount.checked_add(intent.fee).ok_or_else(|| {
            StorageError::Serialization("Arithmetic overflow in amount + fee".into())
        })?;

        if self.balance < total_deduction {
            return Err(StorageError::InsufficientBalance {
                available: self.balance,
                required: total_deduction,
            });
        }

        self.balance -= total_deduction;
        self.nonce += 1;
        Ok(())
    }

    /// Applies a credit for the receiving account.
    pub fn apply_credit(&mut self, amount: u64) -> Result<(), StorageError> {
        self.balance = self.balance.checked_add(amount).ok_or_else(|| {
            StorageError::Serialization("Arithmetic overflow during balance credit".into())
        })?;
        Ok(())
    }
}
