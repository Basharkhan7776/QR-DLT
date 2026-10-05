//! Core data models and cryptographic commitments for QR-DLT.
//!
//! Includes decoupled Segregated Witness representations (`TxIntent`, `WitnessProof`, `Transaction`),
//! dual-root `BlockHeader` and `Block`, and domain-separated BLAKE3 Merkle trees.

pub mod block;
pub mod intent;
pub mod merkle;
pub mod transaction;
pub mod witness;

pub use block::{Block, BlockHeader, PrunedBlock};
pub use intent::TxIntent;
pub use merkle::{compute_merkle_root, MerkleProof};
pub use transaction::Transaction;
pub use witness::WitnessProof;

#[cfg(test)]
mod tests {
    use super::*;
    use qr_dlt_crypto::{CryptoSigner, Ed25519Signer, Falcon512Signer, MlDsa44Signer};

    #[test]
    fn test_transaction_creation_and_verification_ed25519() {
        let signer = Ed25519Signer::generate();
        let sender_addr = signer.address();
        let recipient_addr = [9u8; 20];

        let intent = TxIntent {
            nonce: 1,
            sender_address: sender_addr,
            recipient_address: recipient_addr,
            amount: 1000,
            fee: 10,
        };

        let intent_hash = intent.hash();
        let signature = signer.sign(&intent_hash).unwrap();
        let pk: [u8; 32] = signer.public_key_bytes().try_into().unwrap();
        let sig: [u8; 64] = signature.try_into().unwrap();

        let witness = WitnessProof::Ed25519 {
            public_key: pk,
            signature: sig,
        };

        let tx = Transaction::new(intent, witness);
        assert!(tx.verify_signature().is_ok());
    }

    #[test]
    fn test_transaction_creation_and_verification_falcon512() {
        let signer = Falcon512Signer::generate();
        let sender_addr = signer.address();
        let recipient_addr = [7u8; 20];

        let intent = TxIntent {
            nonce: 42,
            sender_address: sender_addr,
            recipient_address: recipient_addr,
            amount: 50_000,
            fee: 100,
        };

        let intent_hash = intent.hash();
        let signature = signer.sign(&intent_hash).unwrap();
        let pk = signer.public_key_bytes();

        let witness = WitnessProof::Falcon512 {
            public_key: pk,
            signature,
        };

        let tx = Transaction::new(intent, witness);
        assert!(tx.verify_signature().is_ok());
    }

    #[test]
    fn test_transaction_creation_and_verification_mldsa44() {
        let signer = MlDsa44Signer::generate();
        let sender_addr = signer.address();
        let recipient_addr = [5u8; 20];

        let intent = TxIntent {
            nonce: 100,
            sender_address: sender_addr,
            recipient_address: recipient_addr,
            amount: 1_000_000,
            fee: 500,
        };

        let intent_hash = intent.hash();
        let signature = signer.sign(&intent_hash).unwrap();
        let pk = signer.public_key_bytes();

        let witness = WitnessProof::MlDsa44 {
            public_key: pk,
            signature,
        };

        let tx = Transaction::new(intent, witness);
        assert!(tx.verify_signature().is_ok());
    }

    #[test]
    fn test_block_dual_merkle_roots_and_pruning() {
        let signer1 = Ed25519Signer::generate();
        let signer2 = Falcon512Signer::generate();

        let intent1 = TxIntent {
            nonce: 1,
            sender_address: signer1.address(),
            recipient_address: [1u8; 20],
            amount: 50,
            fee: 1,
        };
        let sig1 = signer1.sign(&intent1.hash()).unwrap();
        let tx1 = Transaction::new(
            intent1,
            WitnessProof::Ed25519 {
                public_key: signer1.public_key_bytes().try_into().unwrap(),
                signature: sig1.try_into().unwrap(),
            },
        );

        let intent2 = TxIntent {
            nonce: 1,
            sender_address: signer2.address(),
            recipient_address: [2u8; 20],
            amount: 75,
            fee: 2,
        };
        let sig2 = signer2.sign(&intent2.hash()).unwrap();
        let tx2 = Transaction::new(
            intent2,
            WitnessProof::Falcon512 {
                public_key: signer2.public_key_bytes(),
                signature: sig2,
            },
        );

        let block = Block::new([0u8; 32], 1, 1700000000, [0u8; 20], vec![tx1, tx2]);
        assert!(block.verify_roots());

        let pruned = block.to_pruned();
        assert_eq!(pruned.header, block.header);
        assert!(pruned.verify_intent_root());
    }
}
