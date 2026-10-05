//! Embedded ledger storage engine and epoch-based witness pruning for QR-DLT.

pub mod account;
pub mod error;
pub mod store;

pub use account::AccountState;
pub use error::StorageError;
pub use store::LedgerStore;

#[cfg(test)]
mod tests {
    use super::*;
    use qr_dlt_crypto::{CryptoSigner, Ed25519Signer, Falcon512Signer};
    use qr_dlt_types::{Block, Transaction, TxIntent, WitnessProof};

    #[test]
    fn test_account_state_debit_credit() {
        let store = LedgerStore::open_temporary().unwrap();
        let alice = [1u8; 20];
        let bob = [2u8; 20];

        // Seed Alice with balance 1000
        store.put_account(&alice, &AccountState::new(1000, 0)).unwrap();

        let tx = TxIntent {
            nonce: 1,
            sender_address: alice,
            recipient_address: bob,
            amount: 300,
            fee: 10,
        };

        store.apply_tx_intent(&tx).unwrap();

        let alice_state = store.get_account(&alice).unwrap();
        let bob_state = store.get_account(&bob).unwrap();

        assert_eq!(alice_state.balance, 690);
        assert_eq!(alice_state.nonce, 1);
        assert_eq!(bob_state.balance, 300);
        assert_eq!(bob_state.nonce, 0);
    }

    #[test]
    fn test_commit_block_and_epoch_witness_pruning() {
        let store = LedgerStore::open_temporary().unwrap();
        let alice_signer = Ed25519Signer::generate();
        let bob_signer = Falcon512Signer::generate();

        let alice_addr = alice_signer.address();
        let bob_addr = bob_signer.address();

        // Seed accounts
        store.put_account(&alice_addr, &AccountState::new(5000, 0)).unwrap();

        let intent1 = TxIntent {
            nonce: 1,
            sender_address: alice_addr,
            recipient_address: bob_addr,
            amount: 1000,
            fee: 5,
        };
        let sig1 = alice_signer.sign(&intent1.hash()).unwrap();
        let tx1 = Transaction::new(
            intent1,
            WitnessProof::Ed25519 {
                public_key: alice_signer.public_key_bytes().try_into().unwrap(),
                signature: sig1.try_into().unwrap(),
            },
        );

        let block1 = Block::new([0u8; 32], 1, 1000, [0u8; 20], vec![tx1]);
        store.commit_block(&block1).unwrap();

        assert_eq!(store.get_latest_height().unwrap(), 1);

        // Before pruning: full block is retrievable
        let retrieved_block = store.get_block(1).unwrap().expect("block 1 must exist");
        assert_eq!(retrieved_block.header.height, 1);
        assert_eq!(retrieved_block.transactions.len(), 1);

        // Execute epoch pruning for height <= 1
        let pruned_count = store.prune_witnesses_older_than(1).unwrap();
        assert_eq!(pruned_count, 1);
        assert!(store.is_witness_pruned(1).unwrap());

        // Full block should now error due to pruned witness
        assert!(store.get_block(1).is_err());

        // Pruned block is still intact with verified intent root
        let pruned_block = store.get_pruned_block(1).unwrap().expect("pruned block must exist");
        assert_eq!(pruned_block.header.height, 1);
        assert_eq!(pruned_block.intents.len(), 1);
        assert!(pruned_block.verify_intent_root());
    }
}
