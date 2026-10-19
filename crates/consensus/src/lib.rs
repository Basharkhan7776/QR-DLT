pub mod engine;
pub mod error;
pub mod evm_engine;
pub mod validator;

pub use engine::ConsensusEngine;
pub use error::ConsensusError;
pub use evm_engine::EvmConsensusEngine;
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

    #[test]
    fn test_evm_poa_round_robin_consensus() {
        use qr_dlt_crypto::evm_address_from_falcon_pubkey;
        use qr_dlt_evm::revm::primitives::{hardfork::SpecId, Address as RevmAddress, U256};
        use qr_dlt_evm::FalconEvmEngine;
        use qr_dlt_types::FalconTransaction;

        let val1 = Ed25519Signer::generate();
        let val2 = Falcon512Signer::generate();

        let val_set = ValidatorSet::new(vec![val1.address(), val2.address()]);
        let store = Arc::new(LedgerStore::open_temporary().unwrap());
        let mempool = Arc::new(Mempool::new());
        let mut evm_engine = FalconEvmEngine::new_in_memory(SpecId::CANCUN);

        // Fund Alice in LedgerStore and in EVM state
        let alice = Falcon512Signer::generate();
        let bob = Falcon512Signer::generate();
        let alice_addr = evm_address_from_falcon_pubkey(&alice.public_key_bytes());
        let bob_addr = evm_address_from_falcon_pubkey(&bob.public_key_bytes());

        store
            .put_account(&alice_addr, &AccountState::new(100_000_000_000_000_000, 0))
            .unwrap();
        evm_engine.set_balance(
            RevmAddress::from_slice(&alice_addr),
            U256::from(100_000_000_000_000_000u64),
        );

        let mut consensus =
            EvmConsensusEngine::new(val_set, store.clone(), mempool.clone(), evm_engine);

        // Admit Falcon EVM transaction to mempool
        let mut tx = FalconTransaction::new(
            1,
            0,
            20_000_000_000,
            60_000,
            Some(bob_addr),
            10_000_000_000,
            vec![1, 2, 3],
            alice.public_key_bytes(),
            vec![],
        );
        let sig = alice.sign(&tx.signing_hash()).unwrap();
        tx.falcon_signature = sig;

        mempool
            .admit_falcon_evm(tx.clone(), &store)
            .expect("admit falcon tx");
        assert_eq!(mempool.falcon_len(), 1);

        // Turn 1 (Height 1) belongs to val1
        // Out-of-turn proposal by val2 should fail
        assert!(consensus.propose_evm_block(&val2, 10, 30_000_000).is_err());

        // Proposer val1 succeeds
        let block1 = consensus
            .propose_evm_block(&val1, 10, 30_000_000)
            .expect("propose block 1");
        assert_eq!(block1.header.height, 1);
        assert_eq!(block1.transactions.len(), 1);
        assert_eq!(mempool.falcon_len(), 0); // Confirmed tx purged

        // Storage verification
        assert_eq!(store.get_latest_evm_height().unwrap(), 1);
        let stored_block = store.get_evm_block(1).unwrap().expect("block 1 exists");
        assert!(stored_block.verify_roots());

        // Peer node network validation: process incoming block on a fresh replica
        let val_set_peer = ValidatorSet::new(vec![val1.address(), val2.address()]);
        let store_peer = Arc::new(LedgerStore::open_temporary().unwrap());
        let mempool_peer = Arc::new(Mempool::new());
        let mut evm_engine_peer = FalconEvmEngine::new_in_memory(SpecId::CANCUN);
        evm_engine_peer.set_balance(
            RevmAddress::from_slice(&alice_addr),
            U256::from(100_000_000_000_000_000u64),
        );
        let mut peer_consensus = EvmConsensusEngine::new(
            val_set_peer,
            store_peer.clone(),
            mempool_peer.clone(),
            evm_engine_peer,
        );

        assert!(peer_consensus.process_incoming_evm_block(&block1).is_ok());
        assert_eq!(store_peer.get_latest_evm_height().unwrap(), 1);

        // Turn 2 (Height 2) belongs to val2
        assert!(consensus.propose_evm_block(&val1, 10, 30_000_000).is_err());
        let block2 = consensus
            .propose_evm_block(&val2, 10, 30_000_000)
            .expect("propose block 2");
        assert_eq!(block2.header.height, 2);
        assert_eq!(store.get_latest_evm_height().unwrap(), 2);

        // Epoch pruning verification: prune height <= 1
        let purged = store.prune_evm_witnesses_older_than(1).unwrap();
        assert_eq!(purged, 1, "Must purge 1 Falcon witness proof from block 1");
        assert!(store.is_evm_witness_pruned(1).unwrap());
        assert!(store.get_evm_block(1).is_err());
        let pruned_block = store.get_pruned_evm_block(1).unwrap().unwrap();
        assert!(pruned_block.verify_txs_root());
    }
}
