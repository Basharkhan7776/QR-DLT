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

/// Execution receipt returned by the EVM engine after transacting.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EvmExecutionReceipt {
    pub success: bool,
    pub gas_used: u64,
    pub output: Bytes,
    pub logs: Vec<Log>,
    pub revert_reason: Option<String>,
}

/// Sovereign Falcon EVM Engine managing execution context and database state.
pub struct FalconEvmEngine<DB = InMemoryDB> {
    db: DB,
    spec_id: SpecId,
    block_env: BlockEnv,
    cfg_env: CfgEnv,
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

        let spec = (*ctx.cfg.spec()).into();
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
        if tx.nonce == 0 {
            if let Ok(current_nonce) = self.get_nonce(tx.caller) {
                if current_nonce > 0 {
                    tx.nonce = current_nonce;
                }
            }
        }

        let mut evm = self.build_evm();

        let result = evm
            .transact_one(tx)
            .map_err(|e| EvmEngineError::InvalidTransaction(format!("{:?}", e)))?;

        let state = evm.finalize();
        self.db.commit(state);

        Self::receipt_from_result(result)
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
