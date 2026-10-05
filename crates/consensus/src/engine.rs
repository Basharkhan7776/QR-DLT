use crate::error::ConsensusError;
use crate::validator::ValidatorSet;
use qr_dlt_crypto::CryptoSigner;
use qr_dlt_mempool::{BatchVerifier, Mempool};
use qr_dlt_storage::LedgerStore;
use qr_dlt_types::Block;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Proof-of-Authority consensus engine coordinating block proposals and validations.
pub struct ConsensusEngine {
    validators: ValidatorSet,
    store: Arc<LedgerStore>,
    mempool: Arc<Mempool>,
    verifier: BatchVerifier,
}

impl ConsensusEngine {
    pub fn new(validators: ValidatorSet, store: Arc<LedgerStore>, mempool: Arc<Mempool>) -> Self {
        Self {
            validators,
            store,
            mempool,
            verifier: BatchVerifier::new(),
        }
    }

    /// Assembles and commits a new block proposal if the signer is the scheduled proposer.
    pub fn propose_block(
        &self,
        proposer: &dyn CryptoSigner,
        max_txs: usize,
    ) -> Result<Block, ConsensusError> {
        if self.validators.is_empty() {
            return Err(ConsensusError::EmptyValidatorSet);
        }

        let latest_height = self.store.get_latest_height()?;
        let target_height = latest_height + 1;

        let expected_proposer = self
            .validators
            .get_proposer_for_height(target_height)
            .ok_or(ConsensusError::EmptyValidatorSet)?;

        let proposer_addr = proposer.address();
        if proposer_addr != expected_proposer {
            return Err(ConsensusError::InvalidProposer {
                expected: hex::encode(&expected_proposer),
                actual: hex::encode(&proposer_addr),
            });
        }

        let prev_hash = if latest_height == 0 {
            [0u8; 32]
        } else {
            self.store
                .get_block_header(latest_height)?
                .ok_or(ConsensusError::InvalidPrevHash {
                    expected: format!("Height {}", latest_height),
                    actual: "None".into(),
                })?
                .hash()
        };

        // Extract transactions from mempool
        let txs = self.mempool.get_proposal_batch(max_txs);

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let block = Block::new(prev_hash, target_height, timestamp, proposer_addr, txs);

        // Commit block into state storage
        self.store.commit_block(&block)?;

        // Remove confirmed transactions from mempool
        let confirmed_hashes: Vec<[u8; 32]> =
            block.transactions.iter().map(|tx| tx.intent_hash()).collect();
        self.mempool.remove_confirmed(&confirmed_hashes);

        Ok(block)
    }

    /// Validates an incoming block from the network and commits it if valid.
    pub fn process_incoming_block(&self, block: &Block) -> Result<(), ConsensusError> {
        let latest_height = self.store.get_latest_height()?;
        let expected_height = latest_height + 1;

        if block.header.height != expected_height {
            return Err(ConsensusError::InvalidHeight {
                expected: expected_height,
                actual: block.header.height,
            });
        }

        let expected_prev_hash = if latest_height == 0 {
            [0u8; 32]
        } else {
            self.store
                .get_block_header(latest_height)?
                .ok_or(ConsensusError::InvalidPrevHash {
                    expected: format!("Header at height {}", latest_height),
                    actual: "None".into(),
                })?
                .hash()
        };

        if block.header.prev_hash != expected_prev_hash {
            return Err(ConsensusError::InvalidPrevHash {
                expected: hex::encode(&expected_prev_hash),
                actual: hex::encode(&block.header.prev_hash),
            });
        }

        let expected_proposer = self
            .validators
            .get_proposer_for_height(block.header.height)
            .ok_or(ConsensusError::EmptyValidatorSet)?;

        if block.header.proposer != expected_proposer {
            return Err(ConsensusError::InvalidProposer {
                expected: hex::encode(&expected_proposer),
                actual: hex::encode(&block.header.proposer),
            });
        }

        // Verify dual Merkle roots
        if !block.verify_roots() {
            return Err(ConsensusError::InvalidMerkleRoots);
        }

        // Parallel verify all transaction signatures
        if let Err((fail_idx, _)) = self.verifier.verify_all(&block.transactions) {
            return Err(ConsensusError::InvalidSignatures(fail_idx));
        }

        // Commit to state database
        self.store.commit_block(block)?;

        // Purge confirmed transactions from mempool
        let confirmed_hashes: Vec<[u8; 32]> =
            block.transactions.iter().map(|tx| tx.intent_hash()).collect();
        self.mempool.remove_confirmed(&confirmed_hashes);

        Ok(())
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
