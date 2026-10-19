use qr_dlt_types::FalconTxError;
use thiserror::Error;

#[derive(Error, Debug)]
pub enum MempoolError {
    #[error("Transaction already exists in mempool: {0}")]
    DuplicateTransaction(String),

    #[error("Cryptographic signature verification failed: {0}")]
    InvalidSignature(String),

    #[error("Invalid nonce: account expected {expected}, transaction has {actual}")]
    InvalidNonce { expected: u64, actual: u64 },

    #[error("Insufficient balance: account has {available}, transaction requires {required}")]
    InsufficientBalance { available: u64, required: u64 },

    #[error("Zero fee transaction rejected by admission filter")]
    ZeroFee,

    #[error("Intrinsic gas exceeds gas limit: intrinsic {intrinsic}, limit {limit}")]
    GasLimitTooLow { intrinsic: u64, limit: u64 },

    #[error("Sender address {0} mismatch with public key recovery")]
    AddressMismatch(String),

    #[error("Falcon transaction error: {0}")]
    FalconTx(#[from] FalconTxError),

    #[error("Underlying storage error: {0}")]
    Storage(#[from] qr_dlt_storage::StorageError),
}
