use thiserror::Error;

#[derive(Error, Debug)]
pub enum ConsensusError {
    #[error("Invalid proposer: expected {expected}, got {actual}")]
    InvalidProposer { expected: String, actual: String },

    #[error("Invalid previous hash: expected {expected}, got {actual}")]
    InvalidPrevHash { expected: String, actual: String },

    #[error("Invalid block height: expected {expected}, got {actual}")]
    InvalidHeight { expected: u64, actual: u64 },

    #[error("Dual Merkle root mismatch: block intent or witness root is invalid")]
    InvalidMerkleRoots,

    #[error("Batch signature verification failed on transaction index {0}")]
    InvalidSignatures(usize),

    #[error("No validators registered in consensus schedule")]
    EmptyValidatorSet,

    #[error("Storage error: {0}")]
    Storage(#[from] qr_dlt_storage::StorageError),
}
