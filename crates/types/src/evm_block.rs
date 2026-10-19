use crate::falcon_tx::{FalconTransaction, UnsignedFalconTx};
use crate::merkle::compute_merkle_root;
use qr_dlt_crypto::{keccak256, Address};
use serde::{Deserialize, Serialize};

/// Lightweight EVM block header committing to both state transitions and prunable Falcon witness proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmBlockHeader {
    pub prev_hash: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub proposer: Address,
    pub gas_limit: u64,
    pub gas_used: u64,
    pub txs_root: [u8; 32],
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
    pub witness_root: [u8; 32],
}

impl EvmBlockHeader {
    /// Computes the unique deterministic 32-byte block identifier hash via Keccak-256.
    pub fn hash(&self) -> [u8; 32] {
        let serialized = bincode::serialize(self).expect("serialization of EvmBlockHeader cannot fail");
        keccak256(&serialized)
    }
}

/// Full sovereign EVM block carrying header and complete Falcon-512 enveloped transactions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvmBlock {
    pub header: EvmBlockHeader,
    pub transactions: Vec<FalconTransaction>,
}

impl EvmBlock {
    /// Constructs a new sovereign EVM block, computing transaction intent and witness Merkle roots deterministically.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        prev_hash: [u8; 32],
        height: u64,
        timestamp: u64,
        proposer: Address,
        gas_limit: u64,
        gas_used: u64,
        state_root: [u8; 32],
        receipts_root: [u8; 32],
        transactions: Vec<FalconTransaction>,
    ) -> Self {
        let txs_hashes: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.intent_hash()).collect();
        let witness_hashes: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.witness_hash()).collect();

        let txs_root = compute_merkle_root(&txs_hashes);
        let witness_root = compute_merkle_root(&witness_hashes);

        let header = EvmBlockHeader {
            prev_hash,
            height,
            timestamp,
            proposer,
            gas_limit,
            gas_used,
            txs_root,
            state_root,
            receipts_root,
            witness_root,
        };

        Self {
            header,
            transactions,
        }
    }

    /// Verifies that the header's `txs_root` and `witness_root` match the contained transactions.
    pub fn verify_roots(&self) -> bool {
        let txs_hashes: Vec<[u8; 32]> = self.transactions.iter().map(|tx| tx.intent_hash()).collect();
        let witness_hashes: Vec<[u8; 32]> = self.transactions.iter().map(|tx| tx.witness_hash()).collect();

        compute_merkle_root(&txs_hashes) == self.header.txs_root
            && compute_merkle_root(&witness_hashes) == self.header.witness_root
    }

    /// Strips the bulky ~1.56 KB Falcon witness proofs (public key + signature),
    /// producing an epoch-pruned block that retains full execution auditability.
    pub fn to_pruned(&self) -> PrunedEvmBlock {
        PrunedEvmBlock {
            header: self.header.clone(),
            transactions: self.transactions.iter().map(|tx| tx.unsigned_payload()).collect(),
        }
    }

    /// Measures the total byte size of raw Falcon witnesses contained in this block.
    pub fn witness_bytes_size(&self) -> usize {
        self.transactions
            .iter()
            .map(|tx| tx.falcon_public_key.len() + tx.falcon_signature.len())
            .sum()
    }
}

/// Epoch-pruned EVM block retaining the dual-root header and execution payloads (Falcon witnesses purged).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunedEvmBlock {
    pub header: EvmBlockHeader,
    pub transactions: Vec<UnsignedFalconTx>,
}

impl PrunedEvmBlock {
    /// Verifies that the header's `txs_root` matches the retained unsigned transactions.
    pub fn verify_txs_root(&self) -> bool {
        let txs_hashes: Vec<[u8; 32]> = self.transactions.iter().map(|tx| tx.hash()).collect();
        compute_merkle_root(&txs_hashes) == self.header.txs_root
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use qr_dlt_crypto::{CryptoSigner, Falcon512Signer};

    fn make_test_falcon_tx(signer: &Falcon512Signer, nonce: u64, value: u128) -> FalconTransaction {
        let pk = signer.public_key_bytes();
        let mut tx = FalconTransaction::new(
            1,
            nonce,
            20_000_000_000,
            60_000,
            Some([0x11u8; 20]),
            value,
            vec![1, 2, 3],
            pk,
            Vec::new(),
        );
        let sig = signer.sign(&tx.signing_hash()).unwrap();
        tx.falcon_signature = sig;
        tx
    }

    #[test]
    fn test_evm_block_dual_roots_and_pruning() {
        let alice = Falcon512Signer::generate();
        let bob = Falcon512Signer::generate();

        let tx1 = make_test_falcon_tx(&alice, 0, 100);
        let tx2 = make_test_falcon_tx(&bob, 0, 200);

        let proposer = [0x99u8; 20];
        let state_root = [0x55u8; 32];
        let receipts_root = [0x77u8; 32];

        let block = EvmBlock::new(
            [0u8; 32],
            1,
            1_700_000_000,
            proposer,
            30_000_000,
            120_000,
            state_root,
            receipts_root,
            vec![tx1.clone(), tx2.clone()],
        );

        // 1. Verify roots
        assert!(block.verify_roots());
        assert_eq!(block.header.height, 1);
        assert_eq!(block.header.state_root, state_root);
        assert_eq!(block.header.receipts_root, receipts_root);

        // 2. Measure witness overhead: 2 txs * ~1,563 bytes = > 3,000 bytes
        let witness_size = block.witness_bytes_size();
        assert!(witness_size > 3000, "Witness size was {}", witness_size);

        // 3. Convert to pruned block
        let pruned = block.to_pruned();
        assert!(pruned.verify_txs_root());
        assert_eq!(pruned.transactions.len(), 2);
        assert_eq!(pruned.header.witness_root, block.header.witness_root);

        // 4. Tampering detection on full block
        let mut tampered_block = block.clone();
        tampered_block.transactions[0].falcon_signature[0] ^= 0xff;
        assert!(!tampered_block.verify_roots());

        // 5. Tampering detection on pruned block
        let mut tampered_pruned = pruned.clone();
        tampered_pruned.transactions[0].value = 999_999;
        assert!(!tampered_pruned.verify_txs_root());
    }
}
