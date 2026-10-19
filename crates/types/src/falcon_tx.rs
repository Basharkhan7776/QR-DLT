//! EIP-2718 Typed Transaction Envelope Type 0x46 (Falcon-512 Enveloped Transaction).
//!
//! # Specification
//! - **Envelope Type:** `0x46` (ASCII 'F' for Falcon)
//! - **Payload:** `[chain_id, nonce, gas_fee, gas_limit, to, value, data, falcon_public_key, falcon_signature]`
//! - **Address Derivation:** `keccak256(falcon_public_key)[12..32]`
//! - **Intrinsic Gas:** `21,000 (base) + 4,000 (falcon_verify) + calldata_gas + (32,000 if create)`

use alloy_rlp::{Decodable, Encodable, RlpDecodable, RlpEncodable};
use qr_dlt_crypto::address::{evm_address_from_falcon_pubkey, keccak256, Address};
use qr_dlt_crypto::traits::CryptoVerifier;
use qr_dlt_crypto::Falcon512Verifier;
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Envelope Type byte for Falcon transactions (0x46 = 'F').
pub const FALCON_TX_TYPE: u8 = 0x46;

/// Base execution gas for transactions.
pub const BASE_TRANSACTION_GAS: u64 = 21_000;

/// Intrinsic gas allocated for verifying Falcon-512 signatures at the consensus boundary.
pub const FALCON_VERIFY_INTRINSIC_GAS: u64 = 4_000;

/// Extra intrinsic gas charged for contract creation transactions.
pub const CREATE_TRANSACTION_GAS: u64 = 32_000;

/// Gas charged per zero byte in transaction calldata.
pub const CALLDATA_ZERO_GAS: u64 = 4;

/// Gas charged per non-zero byte in transaction calldata.
pub const CALLDATA_NON_ZERO_GAS: u64 = 16;

/// Expected Falcon-512 public key size.
pub const FALCON512_PUBLIC_KEY_LEN: usize = 897;

#[derive(Error, Debug, Clone, PartialEq, Eq)]
pub enum FalconTxError {
    #[error("Invalid transaction type: expected 0x{:02x}, got 0x{:02x}", FALCON_TX_TYPE, .0)]
    InvalidType(u8),

    #[error("RLP encoding/decoding error: {0}")]
    RlpError(String),

    #[error("Invalid public key length: expected {}, got {}", FALCON512_PUBLIC_KEY_LEN, .0)]
    InvalidPublicKeyLength(usize),

    #[error("Empty or invalid signature bytes")]
    InvalidSignatureLength,

    #[error("Cryptographic signature verification failed")]
    SignatureVerificationFailed,

    #[error("Intrinsic gas exceeds gas limit: intrinsic {}, limit {}", .intrinsic, .limit)]
    GasLimitTooLow { intrinsic: u64, limit: u64 },
}

/// Unsigned fields of a Falcon EIP-2718 transaction for computing the signing hash.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable, Serialize, Deserialize)]
pub struct UnsignedFalconTx {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_fee: u128,
    pub gas_limit: u64,
    pub to: Vec<u8>, // Empty for contract creation, 20 bytes otherwise
    pub value: u128,
    pub data: Vec<u8>,
}

/// Full EIP-2718 Type `0x46` Falcon-512 Enveloped Transaction.
#[derive(Clone, Debug, PartialEq, Eq, RlpEncodable, RlpDecodable, Serialize, Deserialize)]
pub struct FalconTransaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_fee: u128,
    pub gas_limit: u64,
    pub to: Vec<u8>, // Empty for contract creation, 20 bytes otherwise
    pub value: u128,
    pub data: Vec<u8>,
    pub falcon_public_key: Vec<u8>, // 897 bytes
    pub falcon_signature: Vec<u8>,  // ~666 bytes
}

impl FalconTransaction {
    /// Creates a new signed Falcon-512 transaction.
    pub fn new(
        chain_id: u64,
        nonce: u64,
        gas_fee: u128,
        gas_limit: u64,
        to: Option<Address>,
        value: u128,
        data: Vec<u8>,
        falcon_public_key: Vec<u8>,
        falcon_signature: Vec<u8>,
    ) -> Self {
        Self {
            chain_id,
            nonce,
            gas_fee,
            gas_limit,
            to: to.map(|a| a.to_vec()).unwrap_or_default(),
            value,
            data,
            falcon_public_key,
            falcon_signature,
        }
    }

    /// Returns the recipient address, or `None` if this is a contract deployment.
    pub fn to_address(&self) -> Option<Address> {
        if self.to.len() == 20 {
            let mut addr = [0u8; 20];
            addr.copy_from_slice(&self.to);
            Some(addr)
        } else {
            None
        }
    }

    /// Checks if this transaction is deploying a contract.
    pub fn is_create(&self) -> bool {
        self.to.is_empty()
    }

    /// Returns the unsigned payload used for computing the signing digest.
    pub fn unsigned_payload(&self) -> UnsignedFalconTx {
        UnsignedFalconTx {
            chain_id: self.chain_id,
            nonce: self.nonce,
            gas_fee: self.gas_fee,
            gas_limit: self.gas_limit,
            to: self.to.clone(),
            value: self.value,
            data: self.data.clone(),
        }
    }

    /// Computes the 32-byte Keccak-256 signing hash over:
    /// `keccak256(0x46 || rlp([chain_id, nonce, gas_fee, gas_limit, to, value, data]))`
    pub fn signing_hash(&self) -> [u8; 32] {
        let mut buf = Vec::new();
        buf.push(FALCON_TX_TYPE);
        self.unsigned_payload().encode(&mut buf);
        keccak256(&buf)
    }

    /// Encodes the transaction as an EIP-2718 envelope:
    /// `0x46 || rlp([chain_id, nonce, gas_fee, gas_limit, to, value, data, falcon_pk, falcon_sig])`
    pub fn encode_enveloped(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.push(FALCON_TX_TYPE);
        self.encode(&mut buf);
        buf
    }

    /// Decodes an EIP-2718 Type `0x46` enveloped transaction from raw wire bytes.
    pub fn decode_enveloped(bytes: &[u8]) -> Result<Self, FalconTxError> {
        if bytes.is_empty() {
            return Err(FalconTxError::RlpError("empty bytes".to_string()));
        }
        if bytes[0] != FALCON_TX_TYPE {
            return Err(FalconTxError::InvalidType(bytes[0]));
        }

        let mut payload = &bytes[1..];
        Self::decode(&mut payload)
            .map_err(|e| FalconTxError::RlpError(format!("{:?}", e)))
    }

    /// Computes the canonical 32-byte transaction hash:
    /// `keccak256(encode_enveloped())`
    pub fn tx_hash(&self) -> [u8; 32] {
        keccak256(&self.encode_enveloped())
    }

    /// Derives the sender's 20-byte Ethereum address:
    /// `keccak256(falcon_public_key)[12..32]`
    pub fn sender(&self) -> Result<Address, FalconTxError> {
        if self.falcon_public_key.len() != FALCON512_PUBLIC_KEY_LEN {
            return Err(FalconTxError::InvalidPublicKeyLength(
                self.falcon_public_key.len(),
            ));
        }
        Ok(evm_address_from_falcon_pubkey(&self.falcon_public_key))
    }

    /// Calculates the transaction's intrinsic gas requirement:
    /// `21,000 (base) + 4,000 (falcon_verify) + calldata_gas + (32,000 if create)`
    pub fn intrinsic_gas(&self) -> u64 {
        let mut gas = BASE_TRANSACTION_GAS + FALCON_VERIFY_INTRINSIC_GAS;

        if self.is_create() {
            gas += CREATE_TRANSACTION_GAS;
        }

        for &byte in &self.data {
            if byte == 0 {
                gas += CALLDATA_ZERO_GAS;
            } else {
                gas += CALLDATA_NON_ZERO_GAS;
            }
        }

        gas
    }

    /// Validates that gas limit is sufficient for intrinsic execution.
    pub fn validate_intrinsic_gas(&self) -> Result<(), FalconTxError> {
        let intrinsic = self.intrinsic_gas();
        if self.gas_limit < intrinsic {
            return Err(FalconTxError::GasLimitTooLow {
                intrinsic,
                limit: self.gas_limit,
            });
        }
        Ok(())
    }

    /// Cryptographically validates the Falcon-512 signature against the signing hash.
    pub fn verify_signature(&self) -> Result<(), FalconTxError> {
        if self.falcon_public_key.len() != FALCON512_PUBLIC_KEY_LEN {
            return Err(FalconTxError::InvalidPublicKeyLength(
                self.falcon_public_key.len(),
            ));
        }
        if self.falcon_signature.is_empty() {
            return Err(FalconTxError::InvalidSignatureLength);
        }

        let signing_digest = self.signing_hash();
        let verifier = Falcon512Verifier;
        verifier
            .verify(
                &signing_digest,
                &self.falcon_signature,
                &self.falcon_public_key,
            )
            .map_err(|_| FalconTxError::SignatureVerificationFailed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qr_dlt_crypto::traits::CryptoSigner;
    use qr_dlt_crypto::Falcon512Signer;

    #[test]
    fn test_falcon_tx_signing_and_verification() {
        let signer = Falcon512Signer::generate();
        let pk = signer.public_key_bytes();
        let to_addr = [0x77u8; 20];

        // Create an unsigned transaction first
        let mut tx = FalconTransaction::new(
            1337,
            0,
            20_000_000_000,
            50_000,
            Some(to_addr),
            1_000_000,
            vec![0x12, 0x34, 0x00, 0x56],
            pk.clone(),
            Vec::new(),
        );

        let signing_hash = tx.signing_hash();
        let sig = signer.sign(&signing_hash).expect("signing failed");
        tx.falcon_signature = sig;

        // Verify signature and sender
        assert!(tx.verify_signature().is_ok());
        let expected_sender = evm_address_from_falcon_pubkey(&pk);
        assert_eq!(tx.sender().unwrap(), expected_sender);
    }

    #[test]
    fn test_falcon_tx_envelope_roundtrip() {
        let signer = Falcon512Signer::generate();
        let pk = signer.public_key_bytes();
        let to_addr = [0x55u8; 20];

        let mut tx = FalconTransaction::new(
            1,
            42,
            15_000_000_000,
            100_000,
            Some(to_addr),
            500_000_000,
            vec![0xaa, 0xbb, 0xcc],
            pk,
            Vec::new(),
        );
        let sig = signer.sign(&tx.signing_hash()).unwrap();
        tx.falcon_signature = sig;

        // Encode as EIP-2718 Type 0x46 envelope
        let encoded = tx.encode_enveloped();
        assert_eq!(encoded[0], FALCON_TX_TYPE);

        // Decode from envelope
        let decoded = FalconTransaction::decode_enveloped(&encoded).expect("decoding failed");
        assert_eq!(decoded, tx);
        assert!(decoded.verify_signature().is_ok());
        assert_eq!(decoded.to_address(), Some(to_addr));
    }

    #[test]
    fn test_falcon_tx_contract_creation() {
        let signer = Falcon512Signer::generate();
        let pk = signer.public_key_bytes();

        let mut tx = FalconTransaction::new(
            1,
            0,
            10_000_000_000,
            500_000,
            None, // Create contract
            0,
            vec![0x60, 0x80, 0x60, 0x40, 0x52], // bytecode
            pk,
            Vec::new(),
        );
        let sig = signer.sign(&tx.signing_hash()).unwrap();
        tx.falcon_signature = sig;

        assert!(tx.is_create());
        assert_eq!(tx.to_address(), None);

        let encoded = tx.encode_enveloped();
        let decoded = FalconTransaction::decode_enveloped(&encoded).unwrap();
        assert!(decoded.is_create());
        assert_eq!(decoded.to_address(), None);
    }

    #[test]
    fn test_falcon_tx_intrinsic_gas_calculation() {
        let pk = vec![0u8; 897];
        let sig = vec![0u8; 666];

        // 1. Simple transfer: no data, not create
        let tx_simple = FalconTransaction::new(
            1, 0, 1000, 30_000, Some([0u8; 20]), 100, Vec::new(), pk.clone(), sig.clone(),
        );
        // 21,000 (base) + 4,000 (falcon_verify) = 25,000
        assert_eq!(tx_simple.intrinsic_gas(), 25_000);
        assert!(tx_simple.validate_intrinsic_gas().is_ok());

        // 2. Transfer with calldata: 3 zeros (3*4 = 12), 2 non-zeros (2*16 = 32)
        let data = vec![0x00, 0x00, 0x00, 0xaa, 0xbb];
        let tx_calldata = FalconTransaction::new(
            1, 0, 1000, 30_000, Some([0u8; 20]), 100, data, pk.clone(), sig.clone(),
        );
        // 25,000 + 12 + 32 = 25,044
        assert_eq!(tx_calldata.intrinsic_gas(), 25_044);

        // 3. Contract creation: + 32,000 gas
        let tx_create = FalconTransaction::new(
            1, 0, 1000, 100_000, None, 0, vec![0x60, 0x00], pk.clone(), sig.clone(),
        );
        // 25,000 + 32,000 + (1 zero * 4 = 4) + (1 non-zero * 16 = 16) = 57,020
        assert_eq!(tx_create.intrinsic_gas(), 57_020);

        // 4. Gas limit too low
        let tx_low_gas = FalconTransaction::new(
            1, 0, 1000, 20_000, Some([0u8; 20]), 100, Vec::new(), pk, sig,
        );
        assert!(matches!(
            tx_low_gas.validate_intrinsic_gas(),
            Err(FalconTxError::GasLimitTooLow { .. })
        ));
    }

    #[test]
    fn test_falcon_tx_tamper_signature_rejected() {
        let signer = Falcon512Signer::generate();
        let pk = signer.public_key_bytes();

        let mut tx = FalconTransaction::new(
            1, 0, 1000, 30_000, Some([0u8; 20]), 100, Vec::new(), pk, Vec::new(),
        );
        let mut sig = signer.sign(&tx.signing_hash()).unwrap();
        sig[5] ^= 0xff; // Tamper
        tx.falcon_signature = sig;

        assert_eq!(
            tx.verify_signature(),
            Err(FalconTxError::SignatureVerificationFailed)
        );
    }
}
