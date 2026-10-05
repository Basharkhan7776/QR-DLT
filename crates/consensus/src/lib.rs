//! Proof-of-Authority (PoA) consensus engine for QR-DLT.

pub mod engine;
pub mod error;
pub mod validator;

pub use engine::ConsensusEngine;
pub use error::ConsensusError;
pub use validator::ValidatorSet;

#[cfg(test)]
mod tests {
    use super::*;
    use qr_dlt_crypto::{CryptoSigner, Ed25519Signer, Falcon512Signer};
    use qr_dlt_mempool::Mempool;
    use qr_dlt_storage::{AccountState, LedgerStore};
    use qr_dlt_types::{Transaction, TxIntent, WitnessProof};
    use std::sync::Arc;

    #[test]
    fn test_poa_round_robin_consensus() {
        let val1 = Ed25519Signer::generate();
        let val2 = Falcon512Signer::generate();

        let val_set = ValidatorSet::new(vec![val1.address(), val2.address()]);
        let store = Arc::new(LedgerStore::open_temporary().unwrap());
        let mempool = Arc::new(Mempool::new());

        let engine = ConsensusEngine::new(val_set, store.clone(), mempool.clone());

        // Fund an account to issue transactions
        let sender = Ed25519Signer::generate();
        store.put_account(&sender.address(), &AccountState::new(10000, 0)).unwrap();

        let intent1 = TxIntent {
            nonce: 1,
            sender_address: sender.address(),
            recipient_address: [5u8; 20],
            amount: 500,
            fee: 10,
        };
        let sig1 = sender.sign(&intent1.hash()).unwrap();
        let tx1 = Transaction::new(
            intent1,
            WitnessProof::Ed25519 {
                public_key: sender.public_key_bytes().try_into().unwrap(),
                signature: sig1.try_into().unwrap(),
            },
        );

        mempool.admit(tx1, &store).unwrap();
        assert_eq!(mempool.len(), 1);

        // Turn 1 (Height 1) belongs to val1
        // Out-of-turn proposal by val2 should fail
        assert!(engine.propose_block(&val2, 10).is_err());

        // Correct proposal by val1 succeeds
        let block1 = engine.propose_block(&val1, 10).unwrap();
        assert_eq!(block1.header.height, 1);
        assert_eq!(block1.transactions.len(), 1);
        assert_eq!(mempool.len(), 0); // Confirmed tx purged

        // Turn 2 (Height 2) belongs to val2
        assert!(engine.propose_block(&val1, 10).is_err());
        let block2 = engine.propose_block(&val2, 10).unwrap();
        assert_eq!(block2.header.height, 2);
        assert_eq!(store.get_latest_height().unwrap(), 2);
    }
}
