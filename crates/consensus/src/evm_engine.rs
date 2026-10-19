use crate::error::ConsensusError;
use crate::validator::ValidatorSet;
use qr_dlt_crypto::CryptoSigner;
use qr_dlt_evm::FalconEvmEngine;
use qr_dlt_mempool::{BatchVerifier, Mempool};
use qr_dlt_storage::LedgerStore;
use qr_dlt_types::EvmBlock;
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

/// Proof-of-Authority sovereign EVM consensus engine coordinating
/// parallel signature verification, sequential revm state transitions,
/// and dual-root block assembly.
pub struct EvmConsensusEngine {
    validators: ValidatorSet,
    store: Arc<LedgerStore>,
    mempool: Arc<Mempool>,
    verifier: BatchVerifier,
    evm_engine: FalconEvmEngine,
}

impl EvmConsensusEngine {
    /// Creates a new sovereign EVM consensus engine instance.
    pub fn new(
        validators: ValidatorSet,
        store: Arc<LedgerStore>,
        mempool: Arc<Mempool>,
        evm_engine: FalconEvmEngine,
    ) -> Self {
        Self {
            validators,
            store,
            mempool,
            verifier: BatchVerifier::new(),
            evm_engine,
        }
    }

    /// Returns a reference to the underlying EVM engine.
    pub fn evm_engine(&self) -> &FalconEvmEngine {
        &self.evm_engine
    }

    /// Returns a mutable reference to the underlying EVM engine.
    pub fn evm_engine_mut(&mut self) -> &mut FalconEvmEngine {
        &mut self.evm_engine
    }

    /// Returns a reference to the storage engine.
    pub fn store(&self) -> &Arc<LedgerStore> {
        &self.store
    }

    /// Returns a reference to the mempool.
    pub fn mempool(&self) -> &Arc<Mempool> {
        &self.mempool
    }

    /// Proposes and commits a new sovereign EVM block containing Falcon transactions:
    /// 1. Validates round-robin proposer turn
    /// 2. Extracts highest-paying Falcon transactions from mempool
    /// 3. Parallel verifies all Falcon-512 signatures using Rayon work-stealing threads
    /// 4. Sequentially executes bytecode transitions in `revm`
    /// 5. Derives deterministic state and receipts roots
    /// 6. Commits dual-root block to storage and purges confirmed transactions from mempool
    pub fn propose_evm_block(
        &mut self,
        proposer: &dyn CryptoSigner,
        max_txs: usize,
        gas_limit: u64,
    ) -> Result<EvmBlock, ConsensusError> {
        if self.validators.is_empty() {
            return Err(ConsensusError::EmptyValidatorSet);
        }

        let latest_height = self.store.get_latest_evm_height()?;
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
                .get_evm_block_header(latest_height)?
                .ok_or_else(|| ConsensusError::InvalidPrevHash {
                    expected: format!("EVM Header at height {}", latest_height),
                    actual: "None".into(),
                })?
                .hash()
        };

        // 1. Extract transactions from mempool
        let txs = self.mempool.get_falcon_proposal_batch(max_txs);

        // 2. Parallel Rayon batch verification of all Falcon-512 signatures
        if let Err((fail_idx, _)) = self.verifier.verify_falcon_evm_all(&txs) {
            return Err(ConsensusError::InvalidSignatures(fail_idx));
        }

        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // 3. Sequential revm block execution
        let exec_res = self.evm_engine.execute_block_transactions(
            &txs,
            proposer_addr,
            target_height,
            timestamp,
            gas_limit,
        )?;

        // 4. Construct dual-root EVM block
        let block = EvmBlock::new(
            prev_hash,
            target_height,
            timestamp,
            proposer_addr,
            gas_limit,
            exec_res.gas_used,
            exec_res.state_root,
            exec_res.receipts_root,
            txs,
        );

        // 5. Commit block to ledger store (Segregated Witness layout)
        self.store.commit_evm_block(&block)?;

        // 6. Purge confirmed transactions from mempool
        let confirmed_hashes: Vec<[u8; 32]> =
            block.transactions.iter().map(|tx| tx.tx_hash()).collect();
        self.mempool.remove_confirmed_falcon(&confirmed_hashes);

        Ok(block)
    }

    /// Validates an incoming sovereign EVM block from the network and commits it if valid:
    /// - Height sequence check
    /// - Parent block hash continuity
    /// - Proposer authorization against PoA validator set
    /// - Dual-root verification (intent/execution root & witness root)
    /// - Parallel Rayon signature verification
    /// - Deterministic `revm` state re-execution (asserting state root, receipts root, gas used)
    pub fn process_incoming_evm_block(&mut self, block: &EvmBlock) -> Result<(), ConsensusError> {
        let latest_height = self.store.get_latest_evm_height()?;
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
                .get_evm_block_header(latest_height)?
                .ok_or_else(|| ConsensusError::InvalidPrevHash {
                    expected: format!("EVM Header at height {}", latest_height),
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

        // 1. Verify dual Merkle roots (execution intents and Falcon witnesses)
        if !block.verify_roots() {
            return Err(ConsensusError::InvalidMerkleRoots);
        }

        // 2. Parallel verify all Falcon-512 signatures using Rayon work-stealing
        if let Err((fail_idx, _)) = self.verifier.verify_falcon_evm_all(&block.transactions) {
            return Err(ConsensusError::InvalidSignatures(fail_idx));
        }

        // 3. Deterministic state re-execution
        let exec_res = self.evm_engine.execute_block_transactions(
            &block.transactions,
            block.header.proposer,
            block.header.height,
            block.header.timestamp,
            block.header.gas_limit,
        )?;

        if exec_res.state_root != block.header.state_root {
            return Err(ConsensusError::StateRootMismatch {
                expected: hex::encode(&block.header.state_root),
                actual: hex::encode(&exec_res.state_root),
            });
        }

        if exec_res.receipts_root != block.header.receipts_root {
            return Err(ConsensusError::ReceiptsRootMismatch {
                expected: hex::encode(&block.header.receipts_root),
                actual: hex::encode(&exec_res.receipts_root),
            });
        }

        if exec_res.gas_used != block.header.gas_used {
            return Err(ConsensusError::GasUsedMismatch {
                expected: block.header.gas_used,
                actual: exec_res.gas_used,
            });
        }

        // 4. Commit to storage
        self.store.commit_evm_block(block)?;

        // 5. Purge confirmed transactions from mempool
        let confirmed_hashes: Vec<[u8; 32]> =
            block.transactions.iter().map(|tx| tx.tx_hash()).collect();
        self.mempool.remove_confirmed_falcon(&confirmed_hashes);

        Ok(())
    }
}

mod hex {
    pub fn encode(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
