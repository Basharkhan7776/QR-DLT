use qr_dlt_crypto::{evm_address_from_falcon_pubkey, CryptoSigner, Falcon512Signer};
use qr_dlt_mempool::{BatchVerifier, Mempool, MempoolError};
use qr_dlt_storage::{AccountState, LedgerStore};
use qr_dlt_types::FalconTransaction;
use std::sync::Arc;
use std::thread;

fn create_signed_falcon_tx(
    signer: &Falcon512Signer,
    nonce: u64,
    gas_fee: u128,
    gas_limit: u64,
    to: Option<[u8; 20]>,
    value: u128,
    data: Vec<u8>,
) -> FalconTransaction {
    let pk = signer.public_key_bytes();
    let mut tx = FalconTransaction::new(
        1, nonce, gas_fee, gas_limit, to, value, data, pk, Vec::new(),
    );
    let sig = signer.sign(&tx.signing_hash()).expect("sign falcon tx");
    tx.falcon_signature = sig;
    tx
}

#[test]
fn test_parallel_batch_verification_scaling() {
    let verifier = BatchVerifier::with_thread_count(8).unwrap();
    let count = 16;
    let mut txs = Vec::with_capacity(count);

    for i in 0..count {
        let signer = Falcon512Signer::generate();
        let tx = create_signed_falcon_tx(
            &signer,
            0,
            20_000_000_000,
            100_000,
            Some([i as u8; 20]),
            1000 * (i as u128 + 1),
            vec![i as u8; 32],
        );
        txs.push(tx);
    }

    // Parallel verification of 16 transactions
    let start = std::time::Instant::now();
    let res = verifier.verify_falcon_evm_all(&txs);
    let duration = start.elapsed();
    assert!(res.is_ok(), "All 16 signatures must verify");
    println!("Verified {} Falcon-512 signatures in parallel in {:?}", count, duration);

    // Corrupt signature at index 7
    let mut corrupted = txs.clone();
    corrupted[7].falcon_signature[10] ^= 0xaa;
    let err = verifier.verify_falcon_evm_all(&corrupted);
    assert!(err.is_err());
    assert_eq!(err.unwrap_err().0, 7);
}

#[test]
fn test_concurrent_mempool_admission() {
    let store = Arc::new(LedgerStore::open_temporary().unwrap());
    let mempool = Arc::new(Mempool::new());

    let num_senders = 8;
    let mut handles = Vec::new();

    // Pre-fund all senders (seed with 10 quadrillion units to cover gas_limit * gas_fee)
    let mut signers = Vec::new();
    for _ in 0..num_senders {
        let signer = Falcon512Signer::generate();
        let addr = evm_address_from_falcon_pubkey(&signer.public_key_bytes());
        store.put_account(&addr, &AccountState::new(10_000_000_000_000_000, 0)).unwrap();
        signers.push(Arc::new(signer));
    }

    // Spawn concurrent threads submitting transactions from different accounts
    for signer in signers {
        let store_clone = Arc::clone(&store);
        let mempool_clone = Arc::clone(&mempool);

        let handle = thread::spawn(move || {
            // Each sender submits 2 sequential transactions (nonce 0 and nonce 1)
            let tx0 = create_signed_falcon_tx(
                &signer,
                0,
                30_000_000_000,
                60_000,
                Some([0xaa; 20]),
                10_000,
                vec![],
            );
            mempool_clone.admit_falcon_evm(tx0, &store_clone).expect("admit nonce 0");

            let tx1 = create_signed_falcon_tx(
                &signer,
                1,
                30_000_000_000,
                60_000,
                Some([0xbb; 20]),
                20_000,
                vec![],
            );
            mempool_clone.admit_falcon_evm(tx1, &store_clone).expect("admit nonce 1");
        });

        handles.push(handle);
    }

    for h in handles {
        h.join().unwrap();
    }

    assert_eq!(mempool.falcon_len(), num_senders * 2);
}

#[test]
fn test_contract_deployment_intrinsic_gas_accounting() {
    let store = LedgerStore::open_temporary().unwrap();
    let mempool = Mempool::new();
    let signer = Falcon512Signer::generate();
    let addr = evm_address_from_falcon_pubkey(&signer.public_key_bytes());
    store.put_account(&addr, &AccountState::new(10_000_000_000_000_000, 0)).unwrap();

    let bytecode = vec![0x60, 0x80, 0x60, 0x40, 0x52, 0x34, 0x80, 0x15];
    // Intrinsic gas = 21,000 + 4,000 + 32,000 (create) + (8 non-zero bytes * 16 = 128) = 57,128
    let tx_create = create_signed_falcon_tx(
        &signer,
        0,
        15_000_000_000,
        57_128,
        None, // Contract creation
        0,
        bytecode.clone(),
    );
    assert_eq!(tx_create.intrinsic_gas(), 57_128);
    assert!(mempool.admit_falcon_evm(tx_create, &store).is_ok());

    // With gas limit 57,127 (1 less than intrinsic), admission must fail
    let tx_create_insufficient = create_signed_falcon_tx(
        &signer,
        1,
        15_000_000_000,
        57_127,
        None,
        0,
        bytecode,
    );
    let err = mempool.admit_falcon_evm(tx_create_insufficient, &store);
    assert!(matches!(
        err,
        Err(MempoolError::GasLimitTooLow { intrinsic: 57128, limit: 57127 })
    ));
}
