//! Transaction mempool admission filtering and parallel batch verification for QR-DLT.

pub mod admission;
pub mod batch_verifier;
pub mod error;
pub mod pool;

pub use admission::validate_admission;
pub use batch_verifier::BatchVerifier;
pub use error::MempoolError;
pub use pool::Mempool;

#[cfg(test)]
mod tests {
    use super::*;
    use qr_dlt_crypto::{CryptoSigner, Ed25519Signer, Falcon512Signer, MlDsa44Signer};
    use qr_dlt_storage::{AccountState, LedgerStore};
    use qr_dlt_types::{Transaction, TxIntent, WitnessProof};

    fn create_test_tx_ed25519(
        signer: &Ed25519Signer,
        nonce: u64,
        amount: u64,
        fee: u64,
    ) -> Transaction {
        let intent = TxIntent {
            nonce,
            sender_address: signer.address(),
            recipient_address: [9u8; 20],
            amount,
            fee,
        };
        let sig = signer.sign(&intent.hash()).unwrap();
        Transaction::new(
            intent,
            WitnessProof::Ed25519 {
                public_key: signer.public_key_bytes().try_into().unwrap(),
                signature: sig.try_into().unwrap(),
            },
        )
    }

    #[test]
    fn test_mempool_admission_and_rejection() {
        let store = LedgerStore::open_temporary().unwrap();
        let mempool = Mempool::new();
        let alice = Ed25519Signer::generate();

        // 1. Unfunded account fails
        let tx1 = create_test_tx_ed25519(&alice, 1, 100, 5);
        assert!(mempool.admit(tx1.clone(), &store).is_err());

        // 2. Fund Alice and re-admit
        store.put_account(&alice.address(), &AccountState::new(1000, 0)).unwrap();
        assert!(mempool.admit(tx1.clone(), &store).is_ok());
        assert_eq!(mempool.len(), 1);

        // 3. Duplicate rejected
        assert!(mempool.admit(tx1, &store).is_err());

        // 4. Nonce sequence test: admit nonce 2
        let tx2 = create_test_tx_ed25519(&alice, 2, 50, 10);
        assert!(mempool.admit(tx2, &store).is_ok());
        assert_eq!(mempool.len(), 2);

        // 5. Nonce gap rejected: try nonce 4
        let tx4 = create_test_tx_ed25519(&alice, 4, 10, 1);
        assert!(mempool.admit(tx4, &store).is_err());
    }

    #[test]
    fn test_parallel_batch_verifier() {
        let verifier = BatchVerifier::with_thread_count(4).unwrap();
        let alice = Ed25519Signer::generate();
        let bob = Falcon512Signer::generate();
        let charlie = MlDsa44Signer::generate();

        let tx1 = create_test_tx_ed25519(&alice, 1, 100, 5);

        let intent_bob = TxIntent {
            nonce: 1,
            sender_address: bob.address(),
            recipient_address: [1u8; 20],
            amount: 200,
            fee: 10,
        };
        let tx2 = Transaction::new(
            intent_bob.clone(),
            WitnessProof::Falcon512 {
                public_key: bob.public_key_bytes(),
                signature: bob.sign(&intent_bob.hash()).unwrap(),
            },
        );

        let intent_charlie = TxIntent {
            nonce: 1,
            sender_address: charlie.address(),
            recipient_address: [2u8; 20],
            amount: 300,
            fee: 15,
        };
        let tx3 = Transaction::new(
            intent_charlie.clone(),
            WitnessProof::MlDsa44 {
                public_key: charlie.public_key_bytes(),
                signature: charlie.sign(&intent_charlie.hash()).unwrap(),
            },
        );

        let batch = vec![tx1, tx2, tx3];

        // All valid signatures verify in parallel
        assert!(verifier.verify_all(&batch).is_ok());

        // Tamper one signature and verify detection
        let mut tampered_batch = batch.clone();
        tampered_batch[1].intent.amount = 999999; // Corrupts intent hash binding
        assert!(verifier.verify_all(&tampered_batch).is_err());
    }
}
