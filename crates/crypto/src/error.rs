use thiserror::Error;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum CryptoError {
    #[error("Invalid key length: expected {expected}, got {actual}")]
    InvalidKeyLength { expected: usize, actual: usize },

    #[error("Invalid signature length: expected {expected}, got {actual}")]
    InvalidSignatureLength { expected: usize, actual: usize },

    #[error("Verification failed: cryptographic signature mismatch")]
    VerificationFailed,

    #[error("Key generation failed: {0}")]
    KeyGenerationFailed(String),

    #[error("Scheme mismatch: expected {expected}, got {actual}")]
    SchemeMismatch { expected: String, actual: String },

    #[error("Serialization or parsing error: {0}")]
    SerializationError(String),
}
