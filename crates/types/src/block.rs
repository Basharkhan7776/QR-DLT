use crate::intent::TxIntent;
use crate::merkle::compute_merkle_root;
use crate::transaction::Transaction;
use serde::{Deserialize, Serialize};

/// Lightweight block header committing to both transaction intents and prunable witness proofs.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BlockHeader {
    pub prev_hash: [u8; 32],
    pub height: u64,
    pub timestamp: u64,
    pub intent_root: [u8; 32],
    pub witness_root: [u8; 32],
    pub proposer: [u8; 20],
}

impl BlockHeader {
    /// Computes the unique deterministic BLAKE3 block identifier hash.
    pub fn hash(&self) -> [u8; 32] {
        let serialized = bincode::serialize(self).expect("serialization of BlockHeader cannot fail");
        *blake3::hash(&serialized).as_bytes()
    }
}

/// Full block containing header and full decoupled transactions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Block {
    pub header: BlockHeader,
    pub transactions: Vec<Transaction>,
}

impl Block {
    /// Constructs a new block, computing intent and witness Merkle roots deterministically.
    pub fn new(
        prev_hash: [u8; 32],
        height: u64,
        timestamp: u64,
        proposer: [u8; 20],
        transactions: Vec<Transaction>,
    ) -> Self {
        let intent_hashes: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.intent_hash()).collect();
        let witness_hashes: Vec<[u8; 32]> = transactions.iter().map(|tx| tx.witness_hash()).collect();

        let intent_root = compute_merkle_root(&intent_hashes);
        let witness_root = compute_merkle_root(&witness_hashes);

        let header = BlockHeader {
            prev_hash,
            height,
            timestamp,
            intent_root,
            witness_root,
            proposer,
        };

        Self {
            header,
            transactions,
        }
    }

    /// Verifies that the header's intent and witness roots match the contained transactions.
    pub fn verify_roots(&self) -> bool {
        let intent_hashes: Vec<[u8; 32]> = self.transactions.iter().map(|tx| tx.intent_hash()).collect();
        let witness_hashes: Vec<[u8; 32]> = self.transactions.iter().map(|tx| tx.witness_hash()).collect();

        compute_merkle_root(&intent_hashes) == self.header.intent_root
            && compute_merkle_root(&witness_hashes) == self.header.witness_root
    }

    /// Strips the bulky witness proofs, converting this block into an epoch-pruned block.
    pub fn to_pruned(&self) -> PrunedBlock {
        PrunedBlock {
            header: self.header.clone(),
            intents: self.transactions.iter().map(|tx| tx.intent.clone()).collect(),
        }
    }
}

/// Epoch-pruned block retaining only the header and transaction intents (witnesses purged).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunedBlock {
    pub header: BlockHeader,
    pub intents: Vec<TxIntent>,
}

impl PrunedBlock {
    /// Verifies that the intent Merkle root in the header matches the retained transaction intents.
    pub fn verify_intent_root(&self) -> bool {
        let intent_hashes: Vec<[u8; 32]> = self.intents.iter().map(|it| it.hash()).collect();
        compute_merkle_root(&intent_hashes) == self.header.intent_root
    }
}
