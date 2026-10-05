use thiserror::Error;

#[derive(Error, Debug)]
pub enum StorageError {
    #[error("Database error: {0}")]
    Db(#[from] sled::Error),

    #[error("Serialization error: {0}")]
    Serialization(String),

    #[error("Account not found: {0}")]
    AccountNotFound(String),

    #[error("Insufficient balance: account has {available}, required {required}")]
    InsufficientBalance { available: u64, required: u64 },

    #[error("Invalid nonce: expected {expected}, got {actual}")]
    InvalidNonce { expected: u64, actual: u64 },

    #[error("Block not found at height {0}")]
    BlockNotFound(u64),

    #[error("Header not found")]
    HeaderNotFound,
}
