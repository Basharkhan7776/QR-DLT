use qr_dlt_crypto::{address_from_public_key, verify_signature, Address, CryptoError, CryptoScheme};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

mod serde_sig64 {
    use super::*;

    pub fn serialize<S>(sig: &[u8; 64], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_bytes(sig)
    }

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 64], D::Error>
    where
        D: Deserializer<'de>,
    {
        struct SigVisitor;

        impl<'de> serde::de::Visitor<'de> for SigVisitor {
            type Value = [u8; 64];

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a 64-byte signature")
            }

            fn visit_bytes<E>(self, v: &[u8]) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                if v.len() != 64 {
                    return Err(E::custom(format!("expected 64 bytes, got {}", v.len())));
                }
                let mut arr = [0u8; 64];
                arr.copy_from_slice(v);
                Ok(arr)
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                let mut arr = [0u8; 64];
                for i in 0..64 {
                    arr[i] = seq
                        .next_element()?
                        .ok_or_else(|| serde::de::Error::custom("expected 64 bytes in sequence"))?;
                }
                Ok(arr)
            }
        }

        deserializer.deserialize_bytes(SigVisitor)
    }
}

/// Decoupled cryptographic proof supporting classical and post-quantum lattice signatures.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessProof {
    Ed25519 {
        public_key: [u8; 32],
        #[serde(with = "serde_sig64")]
        signature: [u8; 64],
    },
    Falcon512 {
        public_key: Vec<u8>,   // 897 bytes
        signature: Vec<u8>,    // ~666-690 bytes
    },
    MlDsa44 {
        public_key: Vec<u8>,   // 1312 bytes
        signature: Vec<u8>,    // 2420 bytes
    },
}

impl WitnessProof {
    /// Returns the cryptographic scheme associated with this witness.
    pub fn scheme(&self) -> CryptoScheme {
        match self {
            Self::Ed25519 { .. } => CryptoScheme::Ed25519,
            Self::Falcon512 { .. } => CryptoScheme::Falcon512,
            Self::MlDsa44 { .. } => CryptoScheme::MlDsa44,
        }
    }

    /// Returns the public key bytes.
    pub fn public_key(&self) -> &[u8] {
        match self {
            Self::Ed25519 { public_key, .. } => public_key,
            Self::Falcon512 { public_key, .. } => public_key.as_slice(),
            Self::MlDsa44 { public_key, .. } => public_key.as_slice(),
        }
    }

    /// Returns the signature bytes.
    pub fn signature(&self) -> &[u8] {
        match self {
            Self::Ed25519 { signature, .. } => signature,
            Self::Falcon512 { signature, .. } => signature.as_slice(),
            Self::MlDsa44 { signature, .. } => signature.as_slice(),
        }
    }

    /// Derives the 20-byte BLAKE3 account address from the embedded public key.
    pub fn recover_address(&self) -> Address {
        address_from_public_key(self.public_key())
    }

    /// Verifies the digital signature over the 32-byte intent commitment hash.
    pub fn verify(&self, intent_hash: &[u8; 32]) -> Result<(), CryptoError> {
        verify_signature(self.scheme(), intent_hash, self.signature(), self.public_key())
    }

    /// Computes the deterministic BLAKE3 commitment hash for this witness.
    pub fn hash(&self) -> [u8; 32] {
        let serialized = bincode::serialize(self).expect("serialization of WitnessProof cannot fail");
        *blake3::hash(&serialized).as_bytes()
    }
}
