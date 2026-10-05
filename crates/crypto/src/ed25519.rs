use crate::error::CryptoError;
use crate::scheme::CryptoScheme;
use crate::traits::{CryptoSigner, CryptoVerifier};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use rand::rngs::OsRng;

pub struct Ed25519Signer {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
}

impl Ed25519Signer {
    /// Generates a new random Ed25519 signing keypair using the operating system CSPRNG.
    pub fn generate() -> Self {
        let mut csprng = OsRng;
        let signing_key = SigningKey::generate(&mut csprng);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Reconstructs an Ed25519 signing key from a 32-byte secret seed.
    pub fn from_bytes(bytes: &[u8; 32]) -> Self {
        let signing_key = SigningKey::from_bytes(bytes);
        let verifying_key = signing_key.verifying_key();
        Self {
            signing_key,
            verifying_key,
        }
    }

    /// Returns the raw 32-byte private key scalar.
    pub fn secret_bytes(&self) -> [u8; 32] {
        self.signing_key.to_bytes()
    }
}

impl CryptoSigner for Ed25519Signer {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::Ed25519
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.verifying_key.to_bytes().to_vec()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let signature: Signature = self.signing_key.sign(message);
        Ok(signature.to_bytes().to_vec())
    }
}

pub struct Ed25519Verifier;

impl CryptoVerifier for Ed25519Verifier {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::Ed25519
    }

    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), CryptoError> {
        if public_key.len() != 32 {
            return Err(CryptoError::InvalidKeyLength {
                expected: 32,
                actual: public_key.len(),
            });
        }
        if signature.len() != 64 {
            return Err(CryptoError::InvalidSignatureLength {
                expected: 64,
                actual: signature.len(),
            });
        }

        let pk_bytes: [u8; 32] = public_key.try_into().map_err(|_| CryptoError::InvalidKeyLength {
            expected: 32,
            actual: public_key.len(),
        })?;
        let sig_bytes: [u8; 64] = signature.try_into().map_err(|_| CryptoError::InvalidSignatureLength {
            expected: 64,
            actual: signature.len(),
        })?;

        let verifying_key = VerifyingKey::from_bytes(&pk_bytes)
            .map_err(|_| CryptoError::VerificationFailed)?;
        let sig = Signature::from_bytes(&sig_bytes);

        verifying_key
            .verify(message, &sig)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}
