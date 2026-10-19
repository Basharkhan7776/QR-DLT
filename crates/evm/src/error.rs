//! Error types for the QR-DLT EVM execution engine and precompiles.

use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum EvmEngineError {
    #[error("Transaction execution reverted: {0}")]
    Reverted(String),

    #[error("Out of gas (required: {required}, available: {available})")]
    OutOfGas { required: u64, available: u64 },

    #[error("Invalid transaction: {0}")]
    InvalidTransaction(String),

    #[error("Precompile execution failed: {0}")]
    PrecompileFailed(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("State commitment error: {0}")]
    StateCommitmentError(String),
}
