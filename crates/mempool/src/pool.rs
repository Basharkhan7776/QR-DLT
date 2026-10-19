use crate::admission::{validate_admission, validate_falcon_evm_admission};
use crate::error::MempoolError;
use qr_dlt_crypto::Address;
use qr_dlt_storage::LedgerStore;
use qr_dlt_types::{FalconTransaction, Transaction};
use std::collections::HashMap;
use std::sync::RwLock;

/// Thread-safe in-memory transaction pool prioritized by transaction fees.
pub struct Mempool {
    transactions: RwLock<HashMap<[u8; 32], Transaction>>,
    highest_pending_nonce: RwLock<HashMap<[u8; 20], u64>>,
    falcon_transactions: RwLock<HashMap<[u8; 32], FalconTransaction>>,
    highest_pending_falcon_nonce: RwLock<HashMap<Address, u64>>,
}

impl Mempool {
    pub fn new() -> Self {
        Self {
            transactions: RwLock::new(HashMap::new()),
            highest_pending_nonce: RwLock::new(HashMap::new()),
            falcon_transactions: RwLock::new(HashMap::new()),
            highest_pending_falcon_nonce: RwLock::new(HashMap::new()),
        }
    }

    /// Validates an incoming transaction and admits it into the pending pool.
    pub fn admit(&self, tx: Transaction, store: &LedgerStore) -> Result<[u8; 32], MempoolError> {
        let tx_hash = tx.intent_hash();

        // 1. Check for duplicates in pool
        {
            let txs = self.transactions.read().unwrap();
            if txs.contains_key(&tx_hash) {
                return Err(MempoolError::DuplicateTransaction(format!(
                    "0x{}",
                    hex::encode(&tx_hash)
                )));
            }
        }

        // 2. Fetch pending nonce for sender
        let pending_nonce = {
            let nonces = self.highest_pending_nonce.read().unwrap();
            nonces.get(&tx.intent.sender_address).copied()
        };

        // 3. Validate admission rules
        validate_admission(&tx, store, pending_nonce)?;

        // 4. Update pool and sender nonce
        {
            let mut nonces = self.highest_pending_nonce.write().unwrap();
            nonces.insert(tx.intent.sender_address, tx.intent.nonce);
        }

        {
            let mut txs = self.transactions.write().unwrap();
            txs.insert(tx_hash, tx);
        }

        Ok(tx_hash)
    }

    /// Extracts up to `limit` highest-paying transactions to assemble a new block proposal.
    pub fn get_proposal_batch(&self, limit: usize) -> Vec<Transaction> {
        let txs = self.transactions.read().unwrap();
        let mut candidates: Vec<Transaction> = txs.values().cloned().collect();

        // Sort by fee descending
        candidates.sort_by(|a, b| b.intent.fee.cmp(&a.intent.fee));

        candidates.into_iter().take(limit).collect()
    }

    /// Purges confirmed transactions from the mempool after a block is committed.
    pub fn remove_confirmed(&self, confirmed_hashes: &[[u8; 32]]) {
        let mut txs = self.transactions.write().unwrap();
        let mut nonces = self.highest_pending_nonce.write().unwrap();

        for hash in confirmed_hashes {
            if let Some(removed_tx) = txs.remove(hash) {
                // If this was the sender's pending transaction, clean or reset
                nonces.remove(&removed_tx.intent.sender_address);
            }
        }
    }

    /// Number of transactions currently pending in the mempool.
    pub fn len(&self) -> usize {
        self.transactions.read().unwrap().len()
    }

    /// Checks if the mempool is currently empty.
    pub fn is_empty(&self) -> bool {
        self.len() == 0 && self.falcon_len() == 0
    }

    /// Validates an incoming EIP-2718 Type 0x46 Falcon EVM transaction and admits it into the pending pool.
    pub fn admit_falcon_evm(
        &self,
        tx: FalconTransaction,
        store: &LedgerStore,
    ) -> Result<[u8; 32], MempoolError> {
        let tx_hash = tx.tx_hash();

        // 1. Check for duplicates in pool
        {
            let txs = self.falcon_transactions.read().unwrap();
            if txs.contains_key(&tx_hash) {
                return Err(MempoolError::DuplicateTransaction(format!(
                    "0x{}",
                    hex::encode(&tx_hash)
                )));
            }
        }

        // 2. Fetch sender and pending nonce
        let sender = tx
            .sender()
            .map_err(|e| MempoolError::AddressMismatch(format!("{:?}", e)))?;

        let pending_nonce = {
            let nonces = self.highest_pending_falcon_nonce.read().unwrap();
            nonces.get(&sender).copied()
        };

        // 3. Validate admission rules
        validate_falcon_evm_admission(&tx, store, pending_nonce)?;

        // 4. Update pool and sender nonce
        {
            let mut nonces = self.highest_pending_falcon_nonce.write().unwrap();
            nonces.insert(sender, tx.nonce);
        }

        {
            let mut txs = self.falcon_transactions.write().unwrap();
            txs.insert(tx_hash, tx);
        }

        Ok(tx_hash)
    }

    /// Extracts up to `limit` highest-paying Falcon EVM transactions to assemble an EVM block proposal.
    pub fn get_falcon_proposal_batch(&self, limit: usize) -> Vec<FalconTransaction> {
        let txs = self.falcon_transactions.read().unwrap();
        let mut candidates: Vec<FalconTransaction> = txs.values().cloned().collect();

        // Sort by gas fee descending, then by nonce ascending
        candidates.sort_by(|a, b| {
            b.gas_fee
                .cmp(&a.gas_fee)
                .then_with(|| a.nonce.cmp(&b.nonce))
        });

        candidates.into_iter().take(limit).collect()
    }

    /// Purges confirmed Falcon EVM transactions from the mempool after a block is committed.
    pub fn remove_confirmed_falcon(&self, confirmed_hashes: &[[u8; 32]]) {
        let mut txs = self.falcon_transactions.write().unwrap();
        let mut nonces = self.highest_pending_falcon_nonce.write().unwrap();

        for hash in confirmed_hashes {
            if let Some(removed_tx) = txs.remove(hash)
                && let Ok(sender) = removed_tx.sender()
            {
                let remaining_max = txs
                    .values()
                    .filter_map(|t| {
                        if t.sender().ok() == Some(sender) {
                            Some(t.nonce)
                        } else {
                            None
                        }
                    })
                    .max();

                match remaining_max {
                    Some(max_nonce) => {
                        nonces.insert(sender, max_nonce);
                    }
                    None => {
                        nonces.remove(&sender);
                    }
                }
            }
        }
    }

    /// Number of Falcon EVM transactions currently pending in the mempool.
    pub fn falcon_len(&self) -> usize {
        self.falcon_transactions.read().unwrap().len()
    }

    /// Total number of pending transactions across all execution models.
    pub fn total_len(&self) -> usize {
        self.len() + self.falcon_len()
    }

    /// Fetches a Falcon EVM transaction by its canonical transaction hash.
    pub fn get_falcon_tx(&self, hash: &[u8; 32]) -> Option<FalconTransaction> {
        self.falcon_transactions.read().unwrap().get(hash).cloned()
    }
}

impl Default for Mempool {
    fn default() -> Self {
        Self::new()
    }
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
