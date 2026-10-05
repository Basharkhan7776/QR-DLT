use crate::address::{address_from_public_key, Address};
use crate::error::CryptoError;
use crate::scheme::CryptoScheme;

/// Generic interface for cryptographic keypairs capable of signing messages.
pub trait CryptoSigner: Send + Sync {
    /// The cryptographic scheme used by this signer.
    fn scheme(&self) -> CryptoScheme;

    /// Returns the raw public key bytes.
    fn public_key_bytes(&self) -> Vec<u8>;

    /// Produces a digital signature over the given message payload.
    fn sign(&self, message: &[u8]) -> Result<Vec<u8>, CryptoError>;

    /// Derives the 20-byte deterministic account address.
    fn address(&self) -> Address {
        address_from_public_key(&self.public_key_bytes())
    }
}

/// Generic interface for verifying digital signatures.
pub trait CryptoVerifier: Send + Sync {
    /// The cryptographic scheme used by this verifier.
    fn scheme(&self) -> CryptoScheme;

    /// Verifies that `signature` is valid for `message` under `public_key`.
    fn verify(&self, message: &[u8], signature: &[u8], public_key: &[u8]) -> Result<(), CryptoError>;
}
