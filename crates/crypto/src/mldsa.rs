use crate::error::CryptoError;
use crate::scheme::CryptoScheme;
use crate::traits::{CryptoSigner, CryptoVerifier};
use pqcrypto_dilithium::dilithium2::{
    detached_sign, keypair, verify_detached_signature, DetachedSignature, PublicKey, SecretKey,
};
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as PublicKeyTrait,
    SecretKey as SecretKeyTrait,
};

pub struct MlDsa44Signer {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl MlDsa44Signer {
    /// Generates a new ML-DSA-44 (Dilithium2) keypair.
    pub fn generate() -> Self {
        let (public_key, secret_key) = keypair();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Reconstructs an ML-DSA-44 signer from raw secret and public key bytes.
    pub fn from_bytes(sk_bytes: &[u8], pk_bytes: &[u8]) -> Result<Self, CryptoError> {
        let secret_key = SecretKey::from_bytes(sk_bytes)
            .map_err(|e| CryptoError::KeyGenerationFailed(format!("{:?}", e)))?;
        let public_key = PublicKey::from_bytes(pk_bytes)
            .map_err(|e| CryptoError::KeyGenerationFailed(format!("{:?}", e)))?;
        Ok(Self {
            secret_key,
            public_key,
        })
    }

    /// Returns the raw secret key bytes.
    pub fn secret_key_bytes(&self) -> Vec<u8> {
        self.secret_key.as_bytes().to_vec()
    }
}

impl CryptoSigner for MlDsa44Signer {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::MlDsa44
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sig = detached_sign(message, &self.secret_key);
        Ok(sig.as_bytes().to_vec())
    }
}

pub struct MlDsa44Verifier;

impl CryptoVerifier for MlDsa44Verifier {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::MlDsa44
    }

    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), CryptoError> {
        let pk = PublicKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidKeyLength {
            expected: 1312,
            actual: public_key.len(),
        })?;

        let sig = DetachedSignature::from_bytes(signature).map_err(|_| {
            CryptoError::InvalidSignatureLength {
                expected: signature.len(),
                actual: signature.len(),
            }
        })?;

        verify_detached_signature(&sig, message, &pk)
            .map_err(|_| CryptoError::VerificationFailed)
    }
}
