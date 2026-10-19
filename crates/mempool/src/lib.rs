//! Transaction mempool admission filtering and parallel batch verification for QR-DLT.

pub mod admission;
pub mod batch_verifier;
pub mod error;
pub mod pool;

pub use admission::{validate_admission, validate_falcon_evm_admission};
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

    fn create_test_falcon_tx(
        signer: &Falcon512Signer,
        nonce: u64,
        gas_fee: u128,
        gas_limit: u64,
        value: u128,
        data: Vec<u8>,
    ) -> qr_dlt_types::FalconTransaction {
        let pk = signer.public_key_bytes();
        let mut tx = qr_dlt_types::FalconTransaction::new(
            1, // chain_id
            nonce,
            gas_fee,
            gas_limit,
            Some([0x42u8; 20]),
            value,
            data,
            pk,
            Vec::new(),
        );
        let sig = signer.sign(&tx.signing_hash()).unwrap();
        tx.falcon_signature = sig;
        tx
    }

    #[test]
    fn test_falcon_evm_mempool_admission_and_rejection() {
        let store = LedgerStore::open_temporary().unwrap();
        let mempool = Mempool::new();
        let signer = Falcon512Signer::generate();
        let addr = qr_dlt_crypto::evm_address_from_falcon_pubkey(&signer.public_key_bytes());

        // 1. Unfunded account fails
        let tx0 = create_test_falcon_tx(&signer, 0, 10, 50_000, 1_000, vec![]);
        assert!(matches!(
            mempool.admit_falcon_evm(tx0.clone(), &store),
            Err(MempoolError::InsufficientBalance { .. })
        ));

        // 2. Fund account in store and re-admit nonce 0
        store.put_account(&addr, &AccountState::new(10_000_000, 0)).unwrap();
        let hash0 = mempool.admit_falcon_evm(tx0.clone(), &store).expect("admit nonce 0");
        assert_eq!(mempool.falcon_len(), 1);
        assert_eq!(mempool.get_falcon_tx(&hash0).unwrap().tx_hash(), hash0);

        // 3. Duplicate rejected
        assert!(matches!(
            mempool.admit_falcon_evm(tx0, &store),
            Err(MempoolError::DuplicateTransaction(_))
        ));

        // 4. Gas limit too low rejected (21k base + 4k falcon = 25k intrinsic)
        let tx_low_gas = create_test_falcon_tx(&signer, 1, 10, 20_000, 100, vec![]);
        assert!(matches!(
            mempool.admit_falcon_evm(tx_low_gas, &store),
            Err(MempoolError::GasLimitTooLow { intrinsic: 25000, limit: 20000 })
        ));

        // 5. Zero fee rejected
        let tx_zero_fee = create_test_falcon_tx(&signer, 1, 0, 50_000, 100, vec![]);
        assert!(matches!(
            mempool.admit_falcon_evm(tx_zero_fee, &store),
            Err(MempoolError::ZeroFee)
        ));

        // 6. Nonce gap rejected: nonce 2 when pending is 0 (expected 1)
        let tx2 = create_test_falcon_tx(&signer, 2, 10, 50_000, 100, vec![]);
        assert!(matches!(
            mempool.admit_falcon_evm(tx2, &store),
            Err(MempoolError::InvalidNonce { expected: 1, actual: 2 })
        ));

        // 7. Nonce sequence continuation: admit nonce 1
        let tx1 = create_test_falcon_tx(&signer, 1, 10, 50_000, 100, vec![]);
        assert!(mempool.admit_falcon_evm(tx1, &store).is_ok());
        assert_eq!(mempool.falcon_len(), 2);

        // 8. Tampered signature rejected
        let mut tx_tampered = create_test_falcon_tx(&signer, 2, 10, 50_000, 100, vec![]);
        tx_tampered.falcon_signature[0] ^= 0xff;
        assert!(matches!(
            mempool.admit_falcon_evm(tx_tampered, &store),
            Err(MempoolError::InvalidSignature(_))
        ));
    }

    #[test]
    fn test_falcon_evm_parallel_batch_verification() {
        let verifier = BatchVerifier::with_thread_count(4).unwrap();
        let alice = Falcon512Signer::generate();
        let bob = Falcon512Signer::generate();
        let charlie = Falcon512Signer::generate();

        let tx1 = create_test_falcon_tx(&alice, 0, 20, 60_000, 500, vec![1, 2, 3]);
        let tx2 = create_test_falcon_tx(&bob, 0, 30, 70_000, 1000, vec![4, 5, 6]);
        let tx3 = create_test_falcon_tx(&charlie, 0, 40, 80_000, 1500, vec![7, 8, 9]);

        let batch = vec![tx1, tx2, tx3];

        // All valid signatures verify in parallel
        assert!(verifier.verify_falcon_evm_all(&batch).is_ok());
        let failures = verifier.verify_falcon_evm_batch(&batch);
        assert!(failures.is_empty());

        // Tamper transaction at index 1
        let mut tampered_batch = batch.clone();
        tampered_batch[1].value = 999_999_999; // Corrupts signing hash
        let failed_res = verifier.verify_falcon_evm_all(&tampered_batch);
        assert!(failed_res.is_err());
        let (idx, _err) = failed_res.err().unwrap();
        assert_eq!(idx, 1);
    }

    #[test]
    fn test_falcon_evm_proposal_batch_and_confirmation() {
        let store = LedgerStore::open_temporary().unwrap();
        let mempool = Mempool::new();

        let s1 = Falcon512Signer::generate();
        let s2 = Falcon512Signer::generate();
        let s3 = Falcon512Signer::generate();

        for s in &[&s1, &s2, &s3] {
            let addr = qr_dlt_crypto::evm_address_from_falcon_pubkey(&s.public_key_bytes());
            store.put_account(&addr, &AccountState::new(100_000_000, 0)).unwrap();
        }

        // Admit 3 transactions with different gas fees: 10, 50, 25
        let tx_low = create_test_falcon_tx(&s1, 0, 10, 50_000, 100, vec![]);
        let tx_high = create_test_falcon_tx(&s2, 0, 50, 50_000, 100, vec![]);
        let tx_mid = create_test_falcon_tx(&s3, 0, 25, 50_000, 100, vec![]);

        let h_low = mempool.admit_falcon_evm(tx_low, &store).unwrap();
        let h_high = mempool.admit_falcon_evm(tx_high, &store).unwrap();
        let h_mid = mempool.admit_falcon_evm(tx_mid, &store).unwrap();

        assert_eq!(mempool.falcon_len(), 3);

        // Batch proposal with limit 2 must return [tx_high (50), tx_mid (25)]
        let proposal = mempool.get_falcon_proposal_batch(2);
        assert_eq!(proposal.len(), 2);
        assert_eq!(proposal[0].gas_fee, 50);
        assert_eq!(proposal[1].gas_fee, 25);

        // Confirm tx_high
        mempool.remove_confirmed_falcon(&[h_high]);
        assert_eq!(mempool.falcon_len(), 2);
        assert!(mempool.get_falcon_tx(&h_high).is_none());
        assert!(mempool.get_falcon_tx(&h_mid).is_some());
        assert!(mempool.get_falcon_tx(&h_low).is_some());
    }
}
