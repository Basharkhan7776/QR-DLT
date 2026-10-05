use crate::account::AccountState;
use crate::error::StorageError;
use qr_dlt_types::{Block, BlockHeader, PrunedBlock, Transaction, TxIntent, WitnessProof};
use sled::{Db, Tree};
use std::path::Path;

/// High-performance embedded storage engine managing ledger state and block persistence.
#[derive(Clone)]
pub struct LedgerStore {
    db: Db,
    accounts: Tree,
    headers: Tree,
    hash_to_height: Tree,
    intents: Tree,
    witnesses: Tree,
    block_tx_hashes: Tree,
    metadata: Tree,
}

impl LedgerStore {
    /// Opens or creates a ledger database at the given filesystem path.
    pub fn open(path: impl AsRef<Path>) -> Result<Self, StorageError> {
        let db = sled::Config::default()
            .path(path)
            .cache_capacity(512 * 1024 * 1024) // 512 MB cache buffer
            .open()?;
        Self::init_trees(db)
    }

    /// Opens a lightweight temporary ledger database in RAM for unit tests.
    pub fn open_temporary() -> Result<Self, StorageError> {
        let db = sled::Config::default()
            .temporary(true)
            .cache_capacity(64 * 1024 * 1024)
            .open()?;
        Self::init_trees(db)
    }

    fn init_trees(db: Db) -> Result<Self, StorageError> {
        let accounts = db.open_tree(b"accounts")?;
        let headers = db.open_tree(b"headers")?;
        let hash_to_height = db.open_tree(b"hash_to_height")?;
        let intents = db.open_tree(b"intents")?;
        let witnesses = db.open_tree(b"witnesses")?;
        let block_tx_hashes = db.open_tree(b"block_tx_hashes")?;
        let metadata = db.open_tree(b"metadata")?;

        Ok(Self {
            db,
            accounts,
            headers,
            hash_to_height,
            intents,
            witnesses,
            block_tx_hashes,
            metadata,
        })
    }

    /// Flushes all memory buffers to disk.
    pub fn flush(&self) -> Result<(), StorageError> {
        self.db.flush()?;
        Ok(())
    }

    // --- Account State Methods ---

    /// Retrieves the current account state, returning a default empty account if uninitialized.
    pub fn get_account(&self, address: &[u8; 20]) -> Result<AccountState, StorageError> {
        match self.accounts.get(address)? {
            Some(bytes) => {
                let state: AccountState = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(state)
            }
            None => Ok(AccountState::default()),
        }
    }

    /// Saves or updates the account state.
    pub fn put_account(&self, address: &[u8; 20], state: &AccountState) -> Result<(), StorageError> {
        let bytes = bincode::serialize(state)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.accounts.insert(address, bytes)?;
        Ok(())
    }

    /// Applies a transaction intent to the account ledger: debits sender, credits recipient.
    pub fn apply_tx_intent(&self, intent: &TxIntent) -> Result<(), StorageError> {
        let mut sender = self.get_account(&intent.sender_address)?;
        let mut recipient = self.get_account(&intent.recipient_address)?;

        sender.apply_debit(intent)?;
        recipient.apply_credit(intent.amount)?;

        self.put_account(&intent.sender_address, &sender)?;
        self.put_account(&intent.recipient_address, &recipient)?;

        Ok(())
    }

    // --- Block & Transaction Persistence ---

    /// Commits a validated block: updates state for all transactions, stores header, intents, and witnesses.
    pub fn commit_block(&self, block: &Block) -> Result<(), StorageError> {
        let height_bytes = block.header.height.to_be_bytes();
        let block_hash = block.header.hash();

        // 1. Apply transaction state transitions
        for tx in &block.transactions {
            self.apply_tx_intent(&tx.intent)?;
        }

        // 2. Persist header and hash index
        let header_bytes = bincode::serialize(&block.header)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.headers.insert(&height_bytes, header_bytes)?;
        self.hash_to_height.insert(&block_hash, &height_bytes)?;

        // 3. Persist intents and witnesses separately (Segregated Witness layout)
        let mut tx_hashes = Vec::with_capacity(block.transactions.len());
        for tx in &block.transactions {
            let tx_hash = tx.intent_hash();
            tx_hashes.push(tx_hash);

            let intent_bytes = bincode::serialize(&tx.intent)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.intents.insert(&tx_hash, intent_bytes)?;

            let witness_bytes = bincode::serialize(&tx.witness)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            self.witnesses.insert(&tx_hash, witness_bytes)?;
        }

        let tx_hashes_bytes = bincode::serialize(&tx_hashes)
            .map_err(|e| StorageError::Serialization(e.to_string()))?;
        self.block_tx_hashes.insert(&height_bytes, tx_hashes_bytes)?;

        // 4. Update latest height
        self.metadata.insert(b"latest_height", &height_bytes)?;

        Ok(())
    }

    /// Retrieves the highest block height currently committed to the ledger.
    pub fn get_latest_height(&self) -> Result<u64, StorageError> {
        match self.metadata.get(b"latest_height")? {
            Some(bytes) => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                Ok(u64::from_be_bytes(arr))
            }
            None => Ok(0),
        }
    }

    /// Retrieves the block header at a given height.
    pub fn get_block_header(&self, height: u64) -> Result<Option<BlockHeader>, StorageError> {
        let height_bytes = height.to_be_bytes();
        match self.headers.get(&height_bytes)? {
            Some(bytes) => {
                let header: BlockHeader = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;
                Ok(Some(header))
            }
            None => Ok(None),
        }
    }

    /// Retrieves the full block (header + transactions + witness proofs) if not yet pruned.
    pub fn get_block(&self, height: u64) -> Result<Option<Block>, StorageError> {
        let header = match self.get_block_header(height)? {
            Some(h) => h,
            None => return Ok(None),
        };

        let height_bytes = height.to_be_bytes();
        let tx_hashes: Vec<[u8; 32]> = match self.block_tx_hashes.get(&height_bytes)? {
            Some(bytes) => bincode::deserialize(&bytes)
                .map_err(|e| StorageError::Serialization(e.to_string()))?,
            None => return Ok(None),
        };

        let mut transactions = Vec::with_capacity(tx_hashes.len());
        for hash in tx_hashes {
            let intent_bytes = self.intents.get(&hash)?
                .ok_or_else(|| StorageError::Serialization("Missing intent for transaction".into()))?;
            let intent: TxIntent = bincode::deserialize(&intent_bytes)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;

            let witness_bytes = self.witnesses.get(&hash)?
                .ok_or_else(|| StorageError::Serialization("Witness has been pruned or is missing".into()))?;
            let witness: WitnessProof = bincode::deserialize(&witness_bytes)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;

            transactions.push(Transaction::new(intent, witness));
        }

        Ok(Some(Block {
            header,
            transactions,
        }))
    }

    /// Retrieves a pruned block (header + transaction intents, without witness proofs).
    pub fn get_pruned_block(&self, height: u64) -> Result<Option<PrunedBlock>, StorageError> {
        let header = match self.get_block_header(height)? {
            Some(h) => h,
            None => return Ok(None),
        };

        let height_bytes = height.to_be_bytes();
        let tx_hashes: Vec<[u8; 32]> = match self.block_tx_hashes.get(&height_bytes)? {
            Some(bytes) => bincode::deserialize(&bytes)
                .map_err(|e| StorageError::Serialization(e.to_string()))?,
            None => return Ok(None),
        };

        let mut intents = Vec::with_capacity(tx_hashes.len());
        for hash in tx_hashes {
            let intent_bytes = self.intents.get(&hash)?
                .ok_or_else(|| StorageError::Serialization("Missing intent for transaction".into()))?;
            let intent: TxIntent = bincode::deserialize(&intent_bytes)
                .map_err(|e| StorageError::Serialization(e.to_string()))?;
            intents.push(intent);
        }

        Ok(Some(PrunedBlock { header, intents }))
    }

    // --- Epoch-Based Witness Pruning Protocol ---

    /// Prunes heavy post-quantum witness proofs for all blocks up to `cutoff_height`.
    ///
    /// Leaves headers, intent roots, and transaction intents completely intact,
    /// purging only raw signature witness proofs to prevent disk and cache bloat.
    /// Returns the number of witness records purged.
    pub fn prune_witnesses_older_than(&self, cutoff_height: u64) -> Result<usize, StorageError> {
        let last_pruned: u64 = match self.metadata.get(b"pruned_height")? {
            Some(bytes) => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                u64::from_be_bytes(arr)
            }
            None => 0,
        };

        let start_height = if last_pruned == 0 { 1 } else { last_pruned + 1 };
        if start_height > cutoff_height {
            return Ok(0);
        }

        let mut purged_count = 0;

        for height in start_height..=cutoff_height {
            let height_bytes = height.to_be_bytes();
            if let Some(bytes) = self.block_tx_hashes.get(&height_bytes)? {
                let tx_hashes: Vec<[u8; 32]> = bincode::deserialize(&bytes)
                    .map_err(|e| StorageError::Serialization(e.to_string()))?;

                for hash in tx_hashes {
                    if self.witnesses.remove(&hash)?.is_some() {
                        purged_count += 1;
                    }
                }
            }
        }

        self.metadata.insert(b"pruned_height", &cutoff_height.to_be_bytes())?;
        self.db.flush()?;

        Ok(purged_count)
    }

    /// Checks whether witnesses at `height` have been pruned.
    pub fn is_witness_pruned(&self, height: u64) -> Result<bool, StorageError> {
        match self.metadata.get(b"pruned_height")? {
            Some(bytes) => {
                let mut arr = [0u8; 8];
                arr.copy_from_slice(&bytes);
                let pruned_height = u64::from_be_bytes(arr);
                Ok(height <= pruned_height)
            }
            None => Ok(false),
        }
    }
}
