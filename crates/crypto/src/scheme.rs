use serde::{Deserialize, Serialize};

#[derive(Copy, Clone, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum CryptoScheme {
    Ed25519,
    Falcon512,
    MlDsa44,
}

impl CryptoScheme {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Ed25519 => "Ed25519",
            Self::Falcon512 => "Falcon-512",
            Self::MlDsa44 => "ML-DSA-44",
        }
    }

    pub fn public_key_len(&self) -> usize {
        match self {
            Self::Ed25519 => 32,
            Self::Falcon512 => 897,
            Self::MlDsa44 => 1312,
        }
    }

    pub fn signature_len(&self) -> usize {
        match self {
            Self::Ed25519 => 64,
            Self::Falcon512 => 666,
            Self::MlDsa44 => 2420,
        }
    }
}
