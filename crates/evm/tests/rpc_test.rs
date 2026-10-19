//! JSON-RPC 2.0 Integration Tests for Falcon-EVM.

use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;
use qr_dlt_crypto::{evm_address_from_falcon_pubkey, CryptoSigner, Falcon512Signer};
use qr_dlt_evm::{start_falcon_rpc_server, FalconEvmEngine};
use qr_dlt_mempool::Mempool;
use qr_dlt_storage::LedgerStore;
use qr_dlt_types::FalconTransaction;
use revm::primitives::{hardfork::SpecId, Address as RevmAddress, U256};
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};

#[tokio::test]
async fn test_json_rpc_server_flow() {
    let store = Arc::new(LedgerStore::open_temporary().unwrap());
    let mempool = Arc::new(Mempool::new());
    let engine = Arc::new(RwLock::new(FalconEvmEngine::new_in_memory(SpecId::CANCUN)));

    // Generate signer and derive address
    let signer = Falcon512Signer::generate();
    let sender_addr = evm_address_from_falcon_pubkey(&signer.public_key_bytes());
    let revm_sender = RevmAddress::from_slice(&sender_addr);

    // Seed engine with balance for address
    {
        let mut eng = engine.write().unwrap();
        eng.set_balance(revm_sender, U256::from(10_000_000_000_000_000_000u128)); // 10 ETH
    }

    // Also seed storage account state so mempool balance check passes
    store
        .put_account(
            &sender_addr,
            &qr_dlt_storage::AccountState {
                balance: 10_000_000_000_000_000_000,
                nonce: 0,
            },
        )
        .unwrap();

    // Start server on an ephemeral port
    let addr: SocketAddr = "127.0.0.1:0".parse().unwrap();
    let (local_addr, _handle) =
        start_falcon_rpc_server(addr, 1337, mempool.clone(), store.clone(), engine.clone())
            .await
            .expect("Failed to start JSON-RPC server");

    let client = HttpClientBuilder::default()
        .build(format!("http://{}", local_addr))
        .expect("Failed to build RPC client");

    // 1. eth_chainId
    let chain_id: String = client
        .request("eth_chainId", rpc_params![])
        .await
        .expect("eth_chainId failed");
    assert_eq!(chain_id, "0x539");

    // 2. eth_getBalance
    let balance_hex: String = client
        .request(
            "eth_getBalance",
            rpc_params![format!("0x{}", hex::encode(sender_addr)), "latest"],
        )
        .await
        .expect("eth_getBalance failed");
    assert_eq!(
        balance_hex,
        format!("0x{:x}", 10_000_000_000_000_000_000u128)
    );

    // 3. eth_estimateGas
    let gas_est: String = client
        .request(
            "eth_estimateGas",
            rpc_params![serde_json::json!({
                "from": format!("0x{}", hex::encode(sender_addr)),
                "to": "0x0000000000000000000000000000000000000015",
                "data": "0x",
            })],
        )
        .await
        .expect("eth_estimateGas failed");
    assert!(gas_est.starts_with("0x"));

    // 4. eth_sendRawTransaction
    let recipient = [0x42u8; 20];
    let pk = signer.public_key_bytes();
    let mut tx = FalconTransaction::new(
        1337,
        0,
        1_000_000_000,
        50_000,
        Some(recipient),
        1_000_000,
        vec![0xaa, 0xbb],
        pk,
        Vec::new(),
    );
    let sig = signer.sign(&tx.signing_hash()).expect("sign falcon tx");
    tx.falcon_signature = sig;

    let raw_hex = format!("0x{}", hex::encode(tx.encode_enveloped()));
    let tx_hash_hex: String = client
        .request("eth_sendRawTransaction", rpc_params![raw_hex])
        .await
        .expect("eth_sendRawTransaction failed");

    assert_eq!(tx_hash_hex, format!("0x{}", hex::encode(tx.tx_hash())));
    assert_eq!(mempool.falcon_len(), 1);

    // 5. eth_blockNumber
    let block_num: String = client
        .request("eth_blockNumber", rpc_params![])
        .await
        .expect("eth_blockNumber failed");
    assert_eq!(block_num, "0x0");

    // Commit a block to test getBlockByNumber
    let block = qr_dlt_types::EvmBlock::new(
        [0u8; 32],
        1,
        1_700_000_000,
        [0x01; 20],
        30_000_000,
        25_000,
        [0x04; 32],
        [0x05; 32],
        vec![tx.clone()],
    );
    store.commit_evm_block(&block).unwrap();

    let block_val: Option<serde_json::Value> = client
        .request("eth_getBlockByNumber", rpc_params!["latest", true])
        .await
        .expect("eth_getBlockByNumber failed");
    assert!(block_val.is_some());
    let obj = block_val.unwrap();
    assert_eq!(obj["number"], "0x1");
    assert_eq!(obj["transactions"].as_array().unwrap().len(), 1);
}
