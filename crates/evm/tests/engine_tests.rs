//! Integration tests for FalconEvmEngine and EVM Bytecode Contract Execution.

use qr_dlt_crypto::traits::CryptoSigner;
use qr_dlt_crypto::Falcon512Signer;
use qr_dlt_evm::{
    FalconEvmEngine, FALCON512_PRECOMPILE_ADDRESS, FALCON512_PRECOMPILE_GAS,
};
use revm::primitives::{address, hardfork::SpecId, Bytes, U256};

#[test]
fn test_evm_engine_balance_transfer() {
    let mut engine = FalconEvmEngine::new_in_memory(SpecId::CANCUN);
    let alice = address!("1000000000000000000000000000000000000001");
    let bob = address!("2000000000000000000000000000000000000002");

    let initial_balance = U256::from(100_000_000_000u64);
    engine.set_balance(alice, initial_balance);

    assert_eq!(engine.get_balance(alice).unwrap(), initial_balance);
    assert_eq!(engine.get_balance(bob).unwrap(), U256::ZERO);

    // Transfer 1,000 wei from Alice to Bob
    let transfer_amount = U256::from(1_000u64);
    let receipt = engine
        .execute_call(alice, bob, Bytes::new(), transfer_amount, 100_000)
        .expect("transfer failed");

    assert!(receipt.success);
    assert_eq!(
        engine.get_balance(bob).unwrap(),
        transfer_amount,
        "Bob should receive transferred amount"
    );
}

#[test]
fn test_evm_engine_direct_call_to_precompile() {
    let mut engine = FalconEvmEngine::new_in_memory(SpecId::CANCUN);
    let caller = address!("1111111111111111111111111111111111111111");
    engine.set_balance(caller, U256::from(1_000_000_000u64));

    let signer = Falcon512Signer::generate();
    let msg_hash = [0x99u8; 32];
    let sig = signer.sign(&msg_hash).expect("signing failed");
    let pk = signer.public_key_bytes();

    // Construct packed calldata: [hash (32)] [pk (897)] [sig]
    let mut calldata = Vec::new();
    calldata.extend_from_slice(&msg_hash);
    calldata.extend_from_slice(&pk);
    calldata.extend_from_slice(&sig);

    // Call precompile directly at 0x15
    let receipt = engine
        .execute_call(
            caller,
            FALCON512_PRECOMPILE_ADDRESS,
            Bytes::from(calldata),
            U256::ZERO,
            100_000,
        )
        .expect("call to 0x15 failed");

    assert!(receipt.success);
    let mut expected_output = [0u8; 32];
    expected_output[31] = 1;
    assert_eq!(receipt.output.as_ref(), &expected_output);
    assert!(receipt.gas_used >= FALCON512_PRECOMPILE_GAS);
}

#[test]
fn test_evm_smart_contract_staticcall_to_falcon_precompile() {
    let mut engine = FalconEvmEngine::new_in_memory(SpecId::CANCUN);
    let caller = address!("9999999999999999999999999999999999999999");
    let contract_addr = address!("8888888888888888888888888888888888888888");
    engine.set_balance(caller, U256::from(10_000_000_000u64));

    // Construct a proxy EVM contract in runtime bytecode:
    // It forwards all incoming calldata to STATICCALL(address 0x15) and returns the result.
    // Opcode breakdown:
    // 0x36: CALLDATASIZE
    // 0x60 0x00: PUSH1 0x00
    // 0x60 0x00: PUSH1 0x00
    // 0x37: CALLDATACOPY (destOffset=0, offset=0, size=calldatasize)
    // 0x60 0x20: PUSH1 32 (retSize=32)
    // 0x60 0x00: PUSH1 0 (retOffset=0)
    // 0x36: CALLDATASIZE (argsSize=calldatasize)
    // 0x60 0x00: PUSH1 0 (argsOffset=0)
    // 0x60 0x15: PUSH1 0x15 (target=Falcon Precompile)
    // 0x5a: GAS (gasLimit=remaining gas)
    // 0xfa: STATICCALL
    // 0x50: POP (drop status boolean from stack)
    // 0x60 0x20: PUSH1 32 (return size=32)
    // 0x60 0x00: PUSH1 0 (return offset=0)
    // 0xf3: RETURN (return memory[0..32])
    let proxy_runtime_code: Vec<u8> = vec![
        0x36, 0x60, 0x00, 0x60, 0x00, 0x37, 0x60, 0x20, 0x60, 0x00, 0x36, 0x60, 0x00, 0x60, 0x15,
        0x5a, 0xfa, 0x50, 0x60, 0x20, 0x60, 0x00, 0xf3,
    ];

    engine.set_code(contract_addr, Bytes::from(proxy_runtime_code));

    // Test 1: Valid signature via smart contract proxy
    let signer = Falcon512Signer::generate();
    let msg_hash = [0xab; 32];
    let sig = signer.sign(&msg_hash).expect("signing failed");
    let pk = signer.public_key_bytes();

    let mut valid_calldata = Vec::new();
    valid_calldata.extend_from_slice(&msg_hash);
    valid_calldata.extend_from_slice(&pk);
    valid_calldata.extend_from_slice(&sig);

    let receipt = engine
        .execute_call(
            caller,
            contract_addr,
            Bytes::from(valid_calldata),
            U256::ZERO,
            200_000,
        )
        .expect("contract call failed");

    assert!(receipt.success);
    let mut expected_valid = [0u8; 32];
    expected_valid[31] = 1;
    assert_eq!(
        receipt.output.as_ref(),
        &expected_valid,
        "Contract call should return 1 for valid Falcon-512 signature"
    );

    // Test 2: Tampered signature via smart contract proxy
    let mut invalid_calldata = Vec::new();
    let mut tampered_hash = msg_hash;
    tampered_hash[0] ^= 0x01; // tamper
    invalid_calldata.extend_from_slice(&tampered_hash);
    invalid_calldata.extend_from_slice(&pk);
    invalid_calldata.extend_from_slice(&sig);

    let receipt_invalid = engine
        .execute_call(
            caller,
            contract_addr,
            Bytes::from(invalid_calldata),
            U256::ZERO,
            200_000,
        )
        .expect("contract call failed");

    assert!(receipt_invalid.success);
    let expected_invalid = [0u8; 32];
    assert_eq!(
        receipt_invalid.output.as_ref(),
        &expected_invalid,
        "Contract call should return 0 for tampered Falcon-512 signature"
    );
}

#[test]
fn test_evm_engine_block_transactions_and_state_root() {
    use qr_dlt_crypto::evm_address_from_falcon_pubkey;
    use qr_dlt_types::FalconTransaction;

    let mut engine = FalconEvmEngine::new_in_memory(SpecId::CANCUN);
    let alice = Falcon512Signer::generate();
    let bob = Falcon512Signer::generate();

    let alice_addr = evm_address_from_falcon_pubkey(&alice.public_key_bytes());
    let bob_addr = evm_address_from_falcon_pubkey(&bob.public_key_bytes());

    let alice_revm_addr = revm::primitives::Address::from_slice(&alice_addr);
    let bob_revm_addr = revm::primitives::Address::from_slice(&bob_addr);

    // Fund Alice with 10 ETH (in wei)
    let initial_balance = U256::from(10_000_000_000_000_000_000u128);
    engine.set_balance(alice_revm_addr, initial_balance);

    // 1. Transaction 1: Alice sends 1 ETH to Bob
    let mut tx1 = FalconTransaction::new(
        1,
        0, // nonce 0
        10_000_000_000,
        50_000,
        Some(bob_addr),
        1_000_000_000_000_000_000, // 1 ETH
        vec![],
        alice.public_key_bytes(),
        vec![],
    );
    let sig1 = alice.sign(&tx1.signing_hash()).unwrap();
    tx1.falcon_signature = sig1;

    // 2. Transaction 2: Alice sends 2 ETH to Bob
    let mut tx2 = FalconTransaction::new(
        1,
        1, // nonce 1
        10_000_000_000,
        50_000,
        Some(bob_addr),
        2_000_000_000_000_000_000, // 2 ETH
        vec![],
        alice.public_key_bytes(),
        vec![],
    );
    let sig2 = alice.sign(&tx2.signing_hash()).unwrap();
    tx2.falcon_signature = sig2;

    let proposer = [0x77u8; 20];
    let res = engine
        .execute_block_transactions(&[tx1, tx2], proposer, 1, 1_700_000_000, 30_000_000)
        .expect("block execution must succeed");

    assert_eq!(res.receipts.len(), 2);
    assert!(res.receipts[0].success);
    assert!(res.receipts[1].success);
    assert!(res.gas_used > 0);
    assert_ne!(res.state_root, [0u8; 32]);
    assert_ne!(res.receipts_root, [0u8; 32]);

    // Verify Bob's final balance is 3 ETH
    let bob_balance = engine.get_balance(bob_revm_addr).unwrap();
    assert_eq!(bob_balance, U256::from(3_000_000_000_000_000_000u128));
}

