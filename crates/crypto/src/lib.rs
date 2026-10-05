//! Quantum-Resilient Digital Signature and Cryptographic Abstractions for QR-DLT.
//!
//! Provides unified traits, key generation, signing, verification, and address derivation
//! across classical Ed25519, NIST FIPS 206 Falcon-512, and NIST FIPS 204 ML-DSA-44.

pub mod address;
pub mod ed25519;
pub mod error;
pub mod falcon;
pub mod mldsa;
pub mod scheme;
pub mod traits;

pub use address::{address_from_public_key, address_to_hex, Address};
pub use ed25519::{Ed25519Signer, Ed25519Verifier};
pub use error::CryptoError;
pub use falcon::{Falcon512Signer, Falcon512Verifier};
pub use mldsa::{MlDsa44Signer, MlDsa44Verifier};
pub use scheme::CryptoScheme;
pub use traits::{CryptoSigner, CryptoVerifier};

/// Unified signature verification dispatcher across all supported schemes.
pub fn verify_signature(
    scheme: CryptoScheme,
    message: &[u8],
    signature: &[u8],
    public_key: &[u8],
) -> Result<(), CryptoError> {
    match scheme {
        CryptoScheme::Ed25519 => Ed25519Verifier.verify(message, signature, public_key),
        CryptoScheme::Falcon512 => Falcon512Verifier.verify(message, signature, public_key),
        CryptoScheme::MlDsa44 => MlDsa44Verifier.verify(message, signature, public_key),
    }
}

/// Generic keypair generator based on the specified cryptographic scheme.
pub fn generate_keypair(scheme: CryptoScheme) -> Box<dyn CryptoSigner> {
    match scheme {
        CryptoScheme::Ed25519 => Box::new(Ed25519Signer::generate()),
        CryptoScheme::Falcon512 => Box::new(Falcon512Signer::generate()),
        CryptoScheme::MlDsa44 => Box::new(MlDsa44Signer::generate()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ed25519_roundtrip() {
        let signer = Ed25519Signer::generate();
        assert_eq!(signer.scheme(), CryptoScheme::Ed25519);
        assert_eq!(signer.public_key_bytes().len(), 32);

        let msg = b"Test message for Ed25519 digital signature";
        let sig = signer.sign(msg).expect("signing failed");
        assert_eq!(sig.len(), 64);

        let verifier = Ed25519Verifier;
        assert!(verifier.verify(msg, &sig, &signer.public_key_bytes()).is_ok());

        // Tamper test
        let mut tampered_sig = sig.clone();
        tampered_sig[0] ^= 0xff;
        assert!(verifier.verify(msg, &tampered_sig, &signer.public_key_bytes()).is_err());
    }

    #[test]
    fn test_falcon512_roundtrip() {
        let signer = Falcon512Signer::generate();
        assert_eq!(signer.scheme(), CryptoScheme::Falcon512);
        assert_eq!(signer.public_key_bytes().len(), 897);

        let msg = b"Test message for Falcon-512 lattice signature";
        let sig = signer.sign(msg).expect("signing failed");
        assert!(!sig.is_empty());

        let verifier = Falcon512Verifier;
        assert!(verifier.verify(msg, &sig, &signer.public_key_bytes()).is_ok());

        // Tamper message
        let tampered_msg = b"Tampered message for Falcon-512";
        assert!(verifier.verify(tampered_msg, &sig, &signer.public_key_bytes()).is_err());
    }

    #[test]
    fn test_mldsa44_roundtrip() {
        let signer = MlDsa44Signer::generate();
        assert_eq!(signer.scheme(), CryptoScheme::MlDsa44);
        assert_eq!(signer.public_key_bytes().len(), 1312);

        let msg = b"Test message for ML-DSA-44 lattice signature";
        let sig = signer.sign(msg).expect("signing failed");
        assert_eq!(sig.len(), 2420);

        let verifier = MlDsa44Verifier;
        assert!(verifier.verify(msg, &sig, &signer.public_key_bytes()).is_ok());

        // Tamper signature
        let mut tampered_sig = sig.clone();
        tampered_sig[10] ^= 0x01;
        assert!(verifier.verify(msg, &tampered_sig, &signer.public_key_bytes()).is_err());
    }

    #[test]
    fn test_unified_dispatcher() {
        for scheme in [CryptoScheme::Ed25519, CryptoScheme::Falcon512, CryptoScheme::MlDsa44] {
            let signer = generate_keypair(scheme);
            let msg = b"Universal verification pipeline payload";
            let sig = signer.sign(msg).expect("Signing must succeed");
            assert!(verify_signature(scheme, msg, &sig, &signer.public_key_bytes()).is_ok());

            // Wrong message fails
            assert!(verify_signature(scheme, b"Different payload", &sig, &signer.public_key_bytes()).is_err());
        }
    }
}
