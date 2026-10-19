//! QR-DLT Sovereign EVM Execution Engine.
//!
//! Embeds `revm` with native support for the Falcon-512 precompile (`0x15`),
//! state management, transaction execution, block execution, and smart contract execution.

use crate::error::EvmEngineError;
use crate::provider::FalconPrecompileProvider;
use revm::{
    context::{
        result::{ExecutionResult, Output},
        BlockEnv, CfgEnv, Context, Evm, FrameStack, Journal, TxEnv,
    },
    database::InMemoryDB,
    database_interface::{Database, DatabaseCommit},
    handler::{instructions::EthInstructions, EthFrame, ExecuteEvm},
    interpreter::interpreter::EthInterpreter,
    primitives::{hardfork::SpecId, Address, Bytes, Log, TxKind, U256},
    state::AccountInfo,
};

/// Type alias for the Falcon-enabled EVM instance.
pub type FalconEvm<CTX, INSP = ()> = Evm<
    CTX,
    INSP,
    EthInstructions<EthInterpreter, CTX>,
    FalconPrecompileProvider,
    EthFrame<EthInterpreter>,
>;

use qr_dlt_types::FalconTransaction;

/// Execution receipt returned by the EVM engine after transacting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmExecutionReceipt {
    pub success: bool,
    pub gas_used: u64,
    pub output: Bytes,
    pub logs: Vec<Log>,
    pub revert_reason: Option<String>,
}

/// Result of executing a batch of block transactions through the EVM engine.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BlockExecutionResult {
    pub receipts: Vec<EvmExecutionReceipt>,
    pub gas_used: u64,
    pub state_root: [u8; 32],
    pub receipts_root: [u8; 32],
}

/// Sovereign Falcon EVM Engine managing execution context and database state.
pub struct FalconEvmEngine<DB = InMemoryDB> {
    db: DB,
    spec_id: SpecId,
    block_env: BlockEnv,
    cfg_env: CfgEnv,
}

struct AccountStateEntry {
    address: [u8; 20],
    balance: [u8; 32],
    nonce: u64,
    code_hash: [u8; 32],
    storage: Vec<([u8; 32], [u8; 32])>,
}

impl FalconEvmEngine<InMemoryDB> {
    /// Creates a new in-memory Falcon EVM engine.
    pub fn new_in_memory(spec_id: SpecId) -> Self {
        Self {
            db: InMemoryDB::default(),
            spec_id,
            block_env: BlockEnv::default(),
            cfg_env: CfgEnv::default(),
        }
    }

    /// Computes a deterministic 32-byte cryptographic state root over all accounts and storage in the database.
    pub fn compute_state_root(&self) -> [u8; 32] {
        let mut entries: Vec<AccountStateEntry> = self
            .db
            .cache
            .accounts
            .iter()
            .map(|(addr, acc)| {
                let mut address = [0u8; 20];
                address.copy_from_slice(addr.as_slice());

                let mut code_hash = [0u8; 32];
                code_hash.copy_from_slice(acc.info.code_hash.as_slice());

                let mut storage: Vec<([u8; 32], [u8; 32])> = acc
                    .storage
                    .iter()
                    .map(|(k, v)| (k.to_be_bytes::<32>(), v.to_be_bytes::<32>()))
                    .collect();
                storage.sort_by_key(|a| a.0);

                AccountStateEntry {
                    address,
                    balance: acc.info.balance.to_be_bytes::<32>(),
                    nonce: acc.info.nonce,
                    code_hash,
                    storage,
                }
            })
            .collect();

        entries.sort_by_key(|a| a.address);

        let mut leaf_hashes = Vec::with_capacity(entries.len());
        for entry in entries {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&entry.address);
            hasher.update(&entry.balance);
            hasher.update(&entry.nonce.to_be_bytes());
            hasher.update(&entry.code_hash);
            for (slot, val) in &entry.storage {
                hasher.update(slot);
                hasher.update(val);
            }
            leaf_hashes.push(*hasher.finalize().as_bytes());
        }

        qr_dlt_types::compute_merkle_root(&leaf_hashes)
    }

    /// Sequentially executes a block's Falcon EVM transactions, accumulates gas,
    /// and derives deterministic state and receipts Merkle roots.
    pub fn execute_block_transactions(
        &mut self,
        txs: &[FalconTransaction],
        proposer: [u8; 20],
        block_number: u64,
        timestamp: u64,
        gas_limit: u64,
    ) -> Result<BlockExecutionResult, EvmEngineError> {
        self.block_env.number = U256::from(block_number);
        self.block_env.timestamp = U256::from(timestamp);
        self.block_env.beneficiary = Address::from_slice(&proposer);
        self.block_env.gas_limit = gas_limit;

        let mut receipts = Vec::with_capacity(txs.len());
        let mut total_gas_used: u64 = 0;

        for tx in txs {
            let receipt = self.execute_falcon_tx(tx)?;
            total_gas_used = total_gas_used.saturating_add(receipt.gas_used);
            receipts.push(receipt);
        }

        let state_root = self.compute_state_root();
        let receipts_root = Self::compute_receipts_root(&receipts);

        Ok(BlockExecutionResult {
            receipts,
            gas_used: total_gas_used,
            state_root,
            receipts_root,
        })
    }
}

impl<DB> FalconEvmEngine<DB>
where
    DB: Database + DatabaseCommit + Clone,
    <DB as Database>::Error: core::fmt::Debug + Send + Sync + 'static,
{
    /// Creates a new Falcon EVM engine backed by the provided database.
    pub fn new(db: DB, spec_id: SpecId) -> Self {
        Self {
            db,
            spec_id,
            block_env: BlockEnv::default(),
            cfg_env: CfgEnv::default(),
        }
    }

    /// Returns a reference to the underlying database.
    pub fn db(&self) -> &DB {
        &self.db
    }

    /// Returns a mutable reference to the underlying database.
    pub fn db_mut(&mut self) -> &mut DB {
        &mut self.db
    }

    /// Sets the current block environment (number, timestamp, gas limit, coinbase).
    pub fn set_block_env(&mut self, block_env: BlockEnv) {
        self.block_env = block_env;
    }

    /// Builds a fresh `FalconEvm` instance wired with the Falcon-512 precompile provider.
    fn build_evm(&self) -> FalconEvm<Context<BlockEnv, TxEnv, CfgEnv, DB, Journal<DB>, ()>> {
        let mut ctx = Context::new(self.db.clone(), self.spec_id);
        ctx.block = self.block_env.clone();
        ctx.cfg = self.cfg_env.clone();

        let spec = *ctx.cfg.spec();
        Evm {
            ctx,
            inspector: (),
            instruction: EthInstructions::new_mainnet_with_spec(spec),
            precompiles: FalconPrecompileProvider::new(spec),
            frame_stack: FrameStack::new_prealloc(8),
        }
    }

    /// Simulates a call without committing state changes (read-only execution).
    pub fn call(
        &self,
        caller: Address,
        to: Address,
        data: Bytes,
        value: U256,
        gas_limit: u64,
    ) -> Result<EvmExecutionReceipt, EvmEngineError> {
        let mut evm = self.build_evm();
        let nonce = self
            .db
            .clone()
            .basic(caller)
            .ok()
            .flatten()
            .map(|i| i.nonce)
            .unwrap_or(0);

        let tx = TxEnv {
            caller,
            kind: TxKind::Call(to),
            data,
            value,
            gas_limit,
            nonce,
            ..Default::default()
        };

        let result = evm
            .transact_one(tx)
            .map_err(|e| EvmEngineError::InvalidTransaction(format!("{:?}", e)))?;

        // Finalize without committing
        let _ = evm.finalize();
        Self::receipt_from_result(result)
    }

    /// Executes a transaction and commits the resulting state mutations to the database.
    pub fn transact_commit(
        &mut self,
        mut tx: TxEnv,
    ) -> Result<EvmExecutionReceipt, EvmEngineError> {
        if tx.nonce == 0
            && let Ok(current_nonce) = self.get_nonce(tx.caller)
            && current_nonce > 0
        {
            tx.nonce = current_nonce;
        }

        let mut evm = self.build_evm();

        let result = evm
            .transact_one(tx)
            .map_err(|e| EvmEngineError::InvalidTransaction(format!("{:?}", e)))?;

        let state = evm.finalize();
        self.db.commit(state);

        Self::receipt_from_result(result)
    }

    /// Executes a single EIP-2718 Type 0x46 Falcon EVM transaction and commits state changes.
    pub fn execute_falcon_tx(
        &mut self,
        tx: &FalconTransaction,
    ) -> Result<EvmExecutionReceipt, EvmEngineError> {
        let sender = tx
            .sender()
            .map_err(|e| EvmEngineError::InvalidTransaction(format!("{:?}", e)))?;
        let caller = Address::from_slice(&sender);

        let kind = match tx.to_address() {
            Some(to) => TxKind::Call(Address::from_slice(&to)),
            None => TxKind::Create,
        };

        let tx_env = TxEnv {
            caller,
            gas_limit: tx.gas_limit,
            gas_price: tx.gas_fee,
            value: U256::from(tx.value),
            data: Bytes::copy_from_slice(&tx.data),
            nonce: tx.nonce,
            kind,
            ..Default::default()
        };

        self.transact_commit(tx_env)
    }

    /// Computes a deterministic 32-byte BLAKE3 Merkle root over the execution receipts.
    pub fn compute_receipts_root(receipts: &[EvmExecutionReceipt]) -> [u8; 32] {
        let receipt_hashes: Vec<[u8; 32]> = receipts
            .iter()
            .map(|r| {
                let mut hasher = blake3::Hasher::new();
                hasher.update(&[if r.success { 1u8 } else { 0u8 }]);
                hasher.update(&r.gas_used.to_be_bytes());
                hasher.update(&r.output);
                *hasher.finalize().as_bytes()
            })
            .collect();
        qr_dlt_types::compute_merkle_root(&receipt_hashes)
    }

    /// Convenience method to transfer balance or call a contract and commit.
    pub fn execute_call(
        &mut self,
        caller: Address,
        to: Address,
        data: Bytes,
        value: U256,
        gas_limit: u64,
    ) -> Result<EvmExecutionReceipt, EvmEngineError> {
        let nonce = self.get_nonce(caller).unwrap_or(0);
        let tx = TxEnv {
            caller,
            kind: TxKind::Call(to),
            data,
            value,
            gas_limit,
            nonce,
            ..Default::default()
        };
        self.transact_commit(tx)
    }

    /// Deploys bytecode to the EVM and commits the new contract account to the database.
    pub fn deploy_contract(
        &mut self,
        caller: Address,
        bytecode: Bytes,
        gas_limit: u64,
    ) -> Result<(Address, EvmExecutionReceipt), EvmEngineError> {
        let nonce = self.get_nonce(caller).unwrap_or(0);
        let tx = TxEnv {
            caller,
            kind: TxKind::Create,
            data: bytecode,
            gas_limit,
            nonce,
            ..Default::default()
        };

        let receipt = self.transact_commit(tx)?;
        if !receipt.success {
            return Err(EvmEngineError::Reverted(
                receipt
                    .revert_reason
                    .unwrap_or_else(|| "Contract deployment reverted".to_string()),
            ));
        }

        let caller_nonce = self
            .get_nonce(caller)
            .unwrap_or(1)
            .saturating_sub(1);
        let deployed_address = caller.create(caller_nonce);

        Ok((deployed_address, receipt))
    }

    /// Retrieves an account balance from the database.
    pub fn get_balance(&mut self, address: Address) -> Result<U256, EvmEngineError> {
        let info = self
            .db
            .basic(address)
            .map_err(|e| EvmEngineError::DatabaseError(format!("{:?}", e)))?;
        Ok(info.map(|i| i.balance).unwrap_or(U256::ZERO))
    }

    /// Retrieves an account nonce from the database.
    pub fn get_nonce(&mut self, address: Address) -> Result<u64, EvmEngineError> {
        let info = self
            .db
            .basic(address)
            .map_err(|e| EvmEngineError::DatabaseError(format!("{:?}", e)))?;
        Ok(info.map(|i| i.nonce).unwrap_or(0))
    }

    /// Sets an account balance directly in the database.
    pub fn set_balance(&mut self, address: Address, balance: U256)
    where
        DB: DatabaseCommit,
    {
        let mut state = revm::state::EvmState::default();
        let mut account = revm::state::Account::from(AccountInfo {
            balance,
            ..Default::default()
        });
        account.mark_touch();
        state.insert(address, account);
        self.db.commit(state);
    }

    /// Sets account bytecode directly in the database.
    pub fn set_code(&mut self, address: Address, bytecode: Bytes)
    where
        DB: DatabaseCommit,
    {
        let mut state = revm::state::EvmState::default();
        let code = revm::state::Bytecode::new_raw(bytecode);
        let code_hash = code.hash_slow();
        let mut account = revm::state::Account::from(AccountInfo {
            balance: U256::ZERO,
            nonce: 1,
            code_hash,
            code: Some(code),
            ..Default::default()
        });
        account.mark_touch();
        state.insert(address, account);
        self.db.commit(state);
    }

    /// Helper converting `ExecutionResult` to `EvmExecutionReceipt`.
    fn receipt_from_result(
        result: ExecutionResult<revm::context::result::HaltReason>,
    ) -> Result<EvmExecutionReceipt, EvmEngineError> {
        let gas_used = result.tx_gas_used();
        match result {
            ExecutionResult::Success {
                output,
                logs,
                ..
            } => {
                let bytes = match output {
                    Output::Call(b) => b,
                    Output::Create(b, _) => b,
                };
                Ok(EvmExecutionReceipt {
                    success: true,
                    gas_used,
                    output: bytes,
                    logs,
                    revert_reason: None,
                })
            }
            ExecutionResult::Revert { output, logs, .. } => {
                let reason = String::from_utf8(output.to_vec())
                    .unwrap_or_else(|_| format!("0x{}", hex::encode(&output)));
                Ok(EvmExecutionReceipt {
                    success: false,
                    gas_used,
                    output,
                    logs,
                    revert_reason: Some(reason),
                })
            }
            ExecutionResult::Halt { reason, .. } => Err(EvmEngineError::Reverted(format!(
                "Execution halted: {:?}",
                reason
            ))),
        }
    }
}
