use crate::error::CryptoError;
use crate::scheme::CryptoScheme;
use crate::traits::{CryptoSigner, CryptoVerifier};
use pqcrypto_falcon::falcon512::{
    detached_sign, keypair, verify_detached_signature, DetachedSignature, PublicKey, SecretKey,
};
use pqcrypto_traits::sign::{
    DetachedSignature as DetachedSignatureTrait, PublicKey as PublicKeyTrait,
    SecretKey as SecretKeyTrait,
};

pub struct Falcon512Signer {
    secret_key: SecretKey,
    public_key: PublicKey,
}

impl Falcon512Signer {
    /// Generates a new Falcon-512 keypair.
    pub fn generate() -> Self {
        let (public_key, secret_key) = keypair();
        Self {
            secret_key,
            public_key,
        }
    }

    /// Reconstructs a Falcon-512 signer from raw secret and public key bytes.
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

impl CryptoSigner for Falcon512Signer {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::Falcon512
    }

    fn public_key_bytes(&self) -> Vec<u8> {
        self.public_key.as_bytes().to_vec()
    }

    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError> {
        let sig = detached_sign(message, &self.secret_key);
        Ok(sig.as_bytes().to_vec())
    }
}

pub struct Falcon512Verifier;

impl CryptoVerifier for Falcon512Verifier {
    fn scheme(&self) -> CryptoScheme {
        CryptoScheme::Falcon512
    }

    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), CryptoError> {
        let pk = PublicKey::from_bytes(public_key).map_err(|_| CryptoError::InvalidKeyLength {
            expected: 897,
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
