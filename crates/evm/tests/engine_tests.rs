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
