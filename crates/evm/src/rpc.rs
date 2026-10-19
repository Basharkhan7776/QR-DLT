//! Sovereign Falcon-EVM Ethereum JSON-RPC 2.0 Server.
//!
//! Exposes standard Ethereum endpoints (`eth_chainId`, `eth_sendRawTransaction`, `eth_call`,
//! `eth_getBalance`, `eth_estimateGas`, `eth_blockNumber`, `eth_getBlockByNumber`) powered by `jsonrpsee`.

use crate::engine::FalconEvmEngine;
use jsonrpsee::core::RpcResult;
use jsonrpsee::proc_macros::rpc;
use jsonrpsee::server::{ServerBuilder, ServerHandle};
use jsonrpsee::types::error::ErrorCode;
use jsonrpsee::types::ErrorObject;
use qr_dlt_mempool::Mempool;
use qr_dlt_storage::LedgerStore;
use qr_dlt_types::FalconTransaction;
use revm::primitives::{Address as RevmAddress, Bytes, U256};
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

/// Standard Ethereum call/transaction parameter object.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct CallRequest {
    #[serde(default)]
    pub from: Option<String>,
    #[serde(default)]
    pub to: Option<String>,
    #[serde(default)]
    pub gas: Option<String>,
    #[serde(default)]
    pub gas_price: Option<String>,
    #[serde(default)]
    pub value: Option<String>,
    #[serde(default)]
    pub data: Option<String>,
}

/// Ethereum JSON-RPC API specification.
#[rpc(server, namespace = "eth")]
pub trait EthRpc {
    #[method(name = "chainId")]
    fn chain_id(&self) -> RpcResult<String>;

    #[method(name = "sendRawTransaction")]
    fn send_raw_transaction(&self, raw_tx: String) -> RpcResult<String>;

    #[method(name = "call")]
    fn call(&self, request: CallRequest, block_number: Option<String>) -> RpcResult<String>;

    #[method(name = "getBalance")]
    fn get_balance(&self, address: String, block_number: Option<String>) -> RpcResult<String>;

    #[method(name = "estimateGas")]
    fn estimate_gas(&self, request: CallRequest) -> RpcResult<String>;

    #[method(name = "blockNumber")]
    fn block_number(&self) -> RpcResult<String>;

    #[method(name = "getBlockByNumber")]
    fn get_block_by_number(
        &self,
        number: String,
        full_txs: bool,
    ) -> RpcResult<Option<serde_json::Value>>;
}

/// JSON-RPC Server implementation backed by the Sovereign EVM engine, LedgerStore, and Mempool.
pub struct EthRpcImpl {
    chain_id: u64,
    mempool: Arc<Mempool>,
    store: Arc<LedgerStore>,
    engine: Arc<RwLock<FalconEvmEngine>>,
}

impl EthRpcImpl {
    pub fn new(
        chain_id: u64,
        mempool: Arc<Mempool>,
        store: Arc<LedgerStore>,
        engine: Arc<RwLock<FalconEvmEngine>>,
    ) -> Self {
        Self {
            chain_id,
            mempool,
            store,
            engine,
        }
    }
}

impl EthRpcServer for EthRpcImpl {
    fn chain_id(&self) -> RpcResult<String> {
        Ok(format!("0x{:x}", self.chain_id))
    }

    fn send_raw_transaction(&self, raw_tx: String) -> RpcResult<String> {
        let clean_hex = raw_tx.trim().strip_prefix("0x").unwrap_or(&raw_tx);
        let bytes = hex::decode(clean_hex).map_err(|e| {
            ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                format!("Invalid raw transaction hex: {}", e),
                None::<()>,
            )
        })?;

        let tx = FalconTransaction::decode_enveloped(&bytes).map_err(|e| {
            ErrorObject::owned(
                ErrorCode::InvalidParams.code(),
                format!("Failed to decode Type 0x46 Falcon transaction: {}", e),
                None::<()>,
            )
        })?;

        let tx_hash = self.mempool.admit_falcon_evm(tx, &self.store).map_err(|e| {
            ErrorObject::owned(
                ErrorCode::InvalidRequest.code(),
                format!("Mempool admission rejected: {}", e),
                None::<()>,
            )
        })?;

        Ok(format!("0x{}", hex::encode(tx_hash)))
    }

    fn call(&self, request: CallRequest, _block_number: Option<String>) -> RpcResult<String> {
        let caller = match request.from {
            Some(f) => parse_revm_address(&f)?,
            None => RevmAddress::ZERO,
        };

        let to = match request.to {
            Some(t) => parse_revm_address(&t)?,
            None => RevmAddress::ZERO,
        };

        let data = match request.data {
            Some(d) => parse_bytes(&d)?,
            None => Bytes::new(),
        };

        let value = match request.value {
            Some(v) => parse_u256(&v)?,
            None => U256::ZERO,
        };

        let gas_limit = match request.gas {
            Some(g) => parse_u64(&g)?,
            None => 10_000_000,
        };

        let engine = self.engine.read().map_err(|_| {
            ErrorObject::owned(
                ErrorCode::InternalError.code(),
                "EVM engine lock poisoned",
                None::<()>,
            )
        })?;

        let receipt = engine
            .call(caller, to, data, value, gas_limit)
            .map_err(|e| {
                ErrorObject::owned(
                    ErrorCode::InternalError.code(),
                    format!("EVM call execution failed: {}", e),
                    None::<()>,
                )
            })?;

        Ok(format!("0x{}", hex::encode(&receipt.output)))
    }

    fn get_balance(&self, address: String, _block_number: Option<String>) -> RpcResult<String> {
        let revm_addr = parse_revm_address(&address)?;
        let mut engine = self.engine.write().map_err(|_| {
            ErrorObject::owned(
                ErrorCode::InternalError.code(),
                "EVM engine lock poisoned",
                None::<()>,
            )
        })?;

        let balance = engine.get_balance(revm_addr).unwrap_or(U256::ZERO);
        Ok(format!("0x{:x}", balance))
    }

    fn estimate_gas(&self, request: CallRequest) -> RpcResult<String> {
        let caller = match request.from {
            Some(f) => parse_revm_address(&f)?,
            None => RevmAddress::ZERO,
        };

        let to = match request.to {
            Some(t) => parse_revm_address(&t)?,
            None => RevmAddress::ZERO,
        };

        let data = match request.data {
            Some(d) => parse_bytes(&d)?,
            None => Bytes::new(),
        };

        let value = match request.value {
            Some(v) => parse_u256(&v)?,
            None => U256::ZERO,
        };

        let engine = self.engine.read().map_err(|_| {
            ErrorObject::owned(
                ErrorCode::InternalError.code(),
                "EVM engine lock poisoned",
                None::<()>,
            )
        })?;

        let receipt = engine
            .call(caller, to, data, value, 10_000_000)
            .map_err(|e| {
                ErrorObject::owned(
                    ErrorCode::InternalError.code(),
                    format!("Gas estimation simulation failed: {}", e),
                    None::<()>,
                )
            })?;

        let gas = receipt.gas_used.max(25_000);
        Ok(format!("0x{:x}", gas))
    }

    fn block_number(&self) -> RpcResult<String> {
        let height = self.store.get_latest_evm_height().map_err(|e| {
            ErrorObject::owned(
                ErrorCode::InternalError.code(),
                format!("Failed to retrieve latest EVM height: {}", e),
                None::<()>,
            )
        })?;
        Ok(format!("0x{:x}", height))
    }

    fn get_block_by_number(
        &self,
        number: String,
        full_txs: bool,
    ) -> RpcResult<Option<serde_json::Value>> {
        let height = if number == "latest" {
            self.store.get_latest_evm_height().unwrap_or(0)
        } else {
            parse_u64(&number)?
        };

        if height == 0 {
            return Ok(None);
        }

        if full_txs {
            match self.store.get_evm_block(height) {
                Ok(Some(block)) => {
                    let val = serde_json::json!({
                        "number": format!("0x{:x}", block.header.height),
                        "hash": format!("0x{}", hex::encode(block.header.hash())),
                        "parentHash": format!("0x{}", hex::encode(block.header.prev_hash)),
                        "timestamp": format!("0x{:x}", block.header.timestamp),
                        "proposer": format!("0x{}", hex::encode(block.header.proposer)),
                        "gasLimit": format!("0x{:x}", block.header.gas_limit),
                        "gasUsed": format!("0x{:x}", block.header.gas_used),
                        "stateRoot": format!("0x{}", hex::encode(block.header.state_root)),
                        "receiptsRoot": format!("0x{}", hex::encode(block.header.receipts_root)),
                        "witnessRoot": format!("0x{}", hex::encode(block.header.witness_root)),
                        "transactions": block.transactions.iter().map(|tx| {
                            serde_json::json!({
                                "hash": format!("0x{}", hex::encode(tx.tx_hash())),
                                "nonce": format!("0x{:x}", tx.nonce),
                                "gasFee": format!("0x{:x}", tx.gas_fee),
                                "gasLimit": format!("0x{:x}", tx.gas_limit),
                                "to": tx.to_address().map(|a| format!("0x{}", hex::encode(a))),
                                "value": format!("0x{:x}", tx.value),
                                "data": format!("0x{}", hex::encode(&tx.data)),
                                "falconPublicKeyLength": tx.falcon_public_key.len(),
                                "falconSignatureLength": tx.falcon_signature.len(),
                            })
                        }).collect::<Vec<_>>()
                    });
                    Ok(Some(val))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(ErrorObject::owned(
                    ErrorCode::InternalError.code(),
                    format!("Failed to retrieve EVM block: {}", e),
                    None::<()>,
                )),
            }
        } else {
            match self.store.get_evm_block_header(height) {
                Ok(Some(header)) => {
                    let val = serde_json::json!({
                        "number": format!("0x{:x}", header.height),
                        "hash": format!("0x{}", hex::encode(header.hash())),
                        "parentHash": format!("0x{}", hex::encode(header.prev_hash)),
                        "timestamp": format!("0x{:x}", header.timestamp),
                        "proposer": format!("0x{}", hex::encode(header.proposer)),
                        "gasLimit": format!("0x{:x}", header.gas_limit),
                        "gasUsed": format!("0x{:x}", header.gas_used),
                        "stateRoot": format!("0x{}", hex::encode(header.state_root)),
                        "receiptsRoot": format!("0x{}", hex::encode(header.receipts_root)),
                        "witnessRoot": format!("0x{}", hex::encode(header.witness_root)),
                    });
                    Ok(Some(val))
                }
                Ok(None) => Ok(None),
                Err(e) => Err(ErrorObject::owned(
                    ErrorCode::InternalError.code(),
                    format!("Failed to retrieve EVM block header: {}", e),
                    None::<()>,
                )),
            }
        }
    }
}

/// Spawns a sovereign Falcon-EVM JSON-RPC 2.0 server listening on `addr`.
pub async fn start_falcon_rpc_server(
    addr: SocketAddr,
    chain_id: u64,
    mempool: Arc<Mempool>,
    store: Arc<LedgerStore>,
    engine: Arc<RwLock<FalconEvmEngine>>,
) -> Result<(SocketAddr, ServerHandle), anyhow::Error> {
    let server = ServerBuilder::default().build(addr).await?;
    let local_addr = server.local_addr()?;
    let rpc_impl = EthRpcImpl::new(chain_id, mempool, store, engine);
    let handle = server.start(rpc_impl.into_rpc());
    Ok((local_addr, handle))
}

fn parse_revm_address(s: &str) -> Result<RevmAddress, ErrorObject<'static>> {
    let clean = s.trim().strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(clean).map_err(|e| {
        ErrorObject::owned(
            ErrorCode::InvalidParams.code(),
            format!("Invalid address hex: {}", e),
            None::<()>,
        )
    })?;
    if bytes.len() != 20 {
        return Err(ErrorObject::owned(
            ErrorCode::InvalidParams.code(),
            format!("Address must be 20 bytes, got {}", bytes.len()),
            None::<()>,
        ));
    }
    Ok(RevmAddress::from_slice(&bytes))
}

fn parse_bytes(s: &str) -> Result<Bytes, ErrorObject<'static>> {
    let clean = s.trim().strip_prefix("0x").unwrap_or(s);
    let raw = hex::decode(clean).map_err(|e| {
        ErrorObject::owned(
            ErrorCode::InvalidParams.code(),
            format!("Invalid data hex: {}", e),
            None::<()>,
        )
    })?;
    Ok(Bytes::from(raw))
}

fn parse_u64(s: &str) -> Result<u64, ErrorObject<'static>> {
    let clean = s.trim().strip_prefix("0x").unwrap_or(s);
    u64::from_str_radix(clean, 16).map_err(|e| {
        ErrorObject::owned(
            ErrorCode::InvalidParams.code(),
            format!("Invalid hex integer: {}", e),
            None::<()>,
        )
    })
}

fn parse_u256(s: &str) -> Result<U256, ErrorObject<'static>> {
    let clean = s.trim().strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(clean).map_err(|e| {
        ErrorObject::owned(
            ErrorCode::InvalidParams.code(),
            format!("Invalid U256 hex: {}", e),
            None::<()>,
        )
    })?;
    Ok(U256::from_be_slice(&bytes))
}
