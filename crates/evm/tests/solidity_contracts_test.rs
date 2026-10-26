//! Deployment and Execution Integration Tests for Solidity Contracts on Falcon-EVM:
//! 1. ERC-20 Token (Standard fungible token)
//! 2. AMM DEX (Constant-product automated market maker $x \cdot y = k$)
//! 3. Post-Quantum Account Abstraction (ERC-4337 style using native Falcon-512 precompile 0x15)

use qr_dlt_crypto::traits::CryptoSigner;
use qr_dlt_crypto::Falcon512Signer;
use qr_dlt_evm::FalconEvmEngine;
use revm::primitives::{address, hardfork::SpecId, keccak256, Address, Bytes, U256};
use std::fs;

fn load_contract_bin(filename: &str) -> Vec<u8> {
    let path = format!("contracts/build/{}", filename);
    let hex_str = fs::read_to_string(&path)
        .or_else(|_| fs::read_to_string(format!("crates/evm/{}", path)))
        .unwrap_or_else(|e| panic!("Failed to read contract bin from {}: {}", path, e));
    hex::decode(hex_str.trim()).expect("Failed to decode contract bin hex")
}

fn encode_address(a: Address) -> [u8; 32] {
    let mut word = [0u8; 32];
    word[12..32].copy_from_slice(a.as_slice());
    word
}

fn encode_u256(u: U256) -> [u8; 32] {
    u.to_be_bytes::<32>()
}

fn encode_string(s: &str) -> Vec<u8> {
    let bytes = s.as_bytes();
    let len = bytes.len();
    let padded_len = len.div_ceil(32) * 32;
    let mut out = Vec::with_capacity(32 + padded_len);
    out.extend_from_slice(&encode_u256(U256::from(len)));
    out.extend_from_slice(bytes);
    out.resize(32 + padded_len, 0);
    out
}

fn encode_bytes(bytes: &[u8]) -> Vec<u8> {
    let len = bytes.len();
    let padded_len = len.div_ceil(32) * 32;
    let mut out = Vec::with_capacity(32 + padded_len);
    out.extend_from_slice(&encode_u256(U256::from(len)));
    out.extend_from_slice(bytes);
    out.resize(32 + padded_len, 0);
    out
}

#[test]
fn test_solidity_erc20_deployment_and_transfers() {
    let mut engine = FalconEvmEngine::new_in_memory(SpecId::CANCUN);
    let deployer = address!("1000000000000000000000000000000000000001");
    let alice = address!("2000000000000000000000000000000000000002");

    engine.set_balance(deployer, U256::from(100_000_000_000_000_000_000u128));

    let bin = load_contract_bin("crates_evm_contracts_ERC20Token_sol_ERC20Token.bin");

    // Constructor: string _name, string _symbol, uint256 _initialSupply
    let initial_supply = U256::from(1_000_000) * U256::from(10).pow(U256::from(18));
    let name = "FalconCoin";
    let symbol = "FALC";

    // ABI encode constructor args:
    // [offset name: 0x60 (96)] [offset symbol: 0xa0 (160)] [initialSupply] [len name] [name bytes] [len symbol] [symbol bytes]
    let mut init_code = bin;
    let name_encoded = encode_string(name);
    let symbol_encoded = encode_string(symbol);

    let offset_name = 32 * 3;
    let offset_symbol = offset_name + name_encoded.len();

    init_code.extend_from_slice(&encode_u256(U256::from(offset_name)));
    init_code.extend_from_slice(&encode_u256(U256::from(offset_symbol)));
    init_code.extend_from_slice(&encode_u256(initial_supply));
    init_code.extend_from_slice(&name_encoded);
    init_code.extend_from_slice(&symbol_encoded);

    let (token_addr, deploy_receipt) = engine
        .deploy_contract(deployer, Bytes::from(init_code), 5_000_000)
        .expect("ERC20 deployment failed");
    assert!(deploy_receipt.success, "Deployment must succeed");
    assert!(deploy_receipt.gas_used > 50_000);

    // 1. Query balanceOf(deployer)
    let bal_selector = &keccak256(b"balanceOf(address)")[0..4];
    let mut calldata = Vec::new();
    calldata.extend_from_slice(bal_selector);
    calldata.extend_from_slice(&encode_address(deployer));

    let receipt = engine
        .call(deployer, token_addr, Bytes::from(calldata), U256::ZERO, 100_000)
        .expect("balanceOf call failed");
    assert_eq!(receipt.output.as_ref(), encode_u256(initial_supply).as_slice());

    // 2. Transfer 250,000 FALC to Alice
    let transfer_amount = U256::from(250_000) * U256::from(10).pow(U256::from(18));
    let transfer_selector = &keccak256(b"transfer(address,uint256)")[0..4];
    let mut transfer_calldata = Vec::new();
    transfer_calldata.extend_from_slice(transfer_selector);
    transfer_calldata.extend_from_slice(&encode_address(alice));
    transfer_calldata.extend_from_slice(&encode_u256(transfer_amount));

    let tx_receipt = engine
        .execute_call(
            deployer,
            token_addr,
            Bytes::from(transfer_calldata),
            U256::ZERO,
            200_000,
        )
        .expect("transfer execution failed");
    assert!(tx_receipt.success);

    // 3. Verify Alice's balance
    let mut alice_bal_calldata = Vec::new();
    alice_bal_calldata.extend_from_slice(bal_selector);
    alice_bal_calldata.extend_from_slice(&encode_address(alice));
    let receipt_alice = engine
        .call(deployer, token_addr, Bytes::from(alice_bal_calldata), U256::ZERO, 100_000)
        .expect("Alice balanceOf call failed");
    assert_eq!(receipt_alice.output.as_ref(), encode_u256(transfer_amount).as_slice());

    // 4. Verify deployer's balance = 750,000 FALC
    let remaining_supply = initial_supply - transfer_amount;
    let mut dep_bal_calldata = Vec::new();
    dep_bal_calldata.extend_from_slice(bal_selector);
    dep_bal_calldata.extend_from_slice(&encode_address(deployer));
    let receipt_dep = engine
        .call(deployer, token_addr, Bytes::from(dep_bal_calldata), U256::ZERO, 100_000)
        .expect("Deployer remaining balanceOf call failed");
    assert_eq!(receipt_dep.output.as_ref(), encode_u256(remaining_supply).as_slice());
}

#[test]
fn test_solidity_amm_dex_constant_product_swaps() {
    let mut engine = FalconEvmEngine::new_in_memory(SpecId::CANCUN);
    let deployer = address!("1000000000000000000000000000000000000001");
    let trader = address!("2000000000000000000000000000000000000002");

    engine.set_balance(deployer, U256::from(100_000_000_000_000_000_000u128));
    engine.set_balance(trader, U256::from(100_000_000_000_000_000_000u128));

    let erc20_bin = load_contract_bin("crates_evm_contracts_ERC20Token_sol_ERC20Token.bin");

    // Deploy Token0 (TokenA)
    let initial_supply = U256::from(10_000_000) * U256::from(10).pow(U256::from(18));
    let mut init_code_a = erc20_bin.clone();
    let name_a = encode_string("TokenA");
    let sym_a = encode_string("TKNA");
    init_code_a.extend_from_slice(&encode_u256(U256::from(96)));
    init_code_a.extend_from_slice(&encode_u256(U256::from(96 + name_a.len())));
    init_code_a.extend_from_slice(&encode_u256(initial_supply));
    init_code_a.extend_from_slice(&name_a);
    init_code_a.extend_from_slice(&sym_a);

    let (token_a, _) = engine
        .deploy_contract(deployer, Bytes::from(init_code_a), 5_000_000)
        .expect("TokenA deploy failed");

    // Deploy Token1 (TokenB)
    let mut init_code_b = erc20_bin.clone();
    let name_b = encode_string("TokenB");
    let sym_b = encode_string("TKNB");
    init_code_b.extend_from_slice(&encode_u256(U256::from(96)));
    init_code_b.extend_from_slice(&encode_u256(U256::from(96 + name_b.len())));
    init_code_b.extend_from_slice(&encode_u256(initial_supply));
    init_code_b.extend_from_slice(&name_b);
    init_code_b.extend_from_slice(&sym_b);

    let (token_b, _) = engine
        .deploy_contract(deployer, Bytes::from(init_code_b), 5_000_000)
        .expect("TokenB deploy failed");

    // Deploy AMM DEX(token_a, token_b)
    let dex_bin = load_contract_bin("crates_evm_contracts_AmmDex_sol_AmmDex.bin");
    let mut dex_init_code = dex_bin;
    dex_init_code.extend_from_slice(&encode_address(token_a));
    dex_init_code.extend_from_slice(&encode_address(token_b));

    let (dex_addr, _) = engine
        .deploy_contract(deployer, Bytes::from(dex_init_code), 5_000_000)
        .expect("DEX deploy failed");

    // Approve DEX on TokenA and TokenB for deployer
    let approve_selector = &keccak256(b"approve(address,uint256)")[0..4];
    let max_allowance = U256::MAX;

    let mut approve_a = Vec::new();
    approve_a.extend_from_slice(approve_selector);
    approve_a.extend_from_slice(&encode_address(dex_addr));
    approve_a.extend_from_slice(&encode_u256(max_allowance));
    engine
        .execute_call(deployer, token_a, Bytes::from(approve_a), U256::ZERO, 100_000)
        .expect("approve TokenA failed");

    let mut approve_b = Vec::new();
    approve_b.extend_from_slice(approve_selector);
    approve_b.extend_from_slice(&encode_address(dex_addr));
    approve_b.extend_from_slice(&encode_u256(max_allowance));
    engine
        .execute_call(deployer, token_b, Bytes::from(approve_b), U256::ZERO, 100_000)
        .expect("approve TokenB failed");

    // Add liquidity: 100,000 TokenA and 200,000 TokenB
    let liq_a = U256::from(100_000) * U256::from(10).pow(U256::from(18));
    let liq_b = U256::from(200_000) * U256::from(10).pow(U256::from(18));
    let add_liq_selector = &keccak256(b"addLiquidity(uint256,uint256)")[0..4];
    let mut add_liq_calldata = Vec::new();
    add_liq_calldata.extend_from_slice(add_liq_selector);
    add_liq_calldata.extend_from_slice(&encode_u256(liq_a));
    add_liq_calldata.extend_from_slice(&encode_u256(liq_b));

    let receipt = engine
        .execute_call(deployer, dex_addr, Bytes::from(add_liq_calldata), U256::ZERO, 500_000)
        .expect("addLiquidity failed");
    assert!(receipt.success, "Liquidity addition must succeed");

    // Verify AMM reserves: reserve0 and reserve1
    let res0_selector = &keccak256(b"reserve0()")[0..4];
    let rec0 = engine
        .call(deployer, dex_addr, Bytes::from(res0_selector.to_vec()), U256::ZERO, 100_000)
        .unwrap();
    assert_eq!(rec0.output.as_ref(), encode_u256(liq_a).as_slice());

    let res1_selector = &keccak256(b"reserve1()")[0..4];
    let rec1 = engine
        .call(deployer, dex_addr, Bytes::from(res1_selector.to_vec()), U256::ZERO, 100_000)
        .unwrap();
    assert_eq!(rec1.output.as_ref(), encode_u256(liq_b).as_slice());

    // Give Trader 10,000 TokenA and approve DEX
    let transfer_selector = &keccak256(b"transfer(address,uint256)")[0..4];
    let trader_amount_a = U256::from(10_000) * U256::from(10).pow(U256::from(18));
    let mut give_trader = Vec::new();
    give_trader.extend_from_slice(transfer_selector);
    give_trader.extend_from_slice(&encode_address(trader));
    give_trader.extend_from_slice(&encode_u256(trader_amount_a));
    engine
        .execute_call(deployer, token_a, Bytes::from(give_trader), U256::ZERO, 100_000)
        .unwrap();

    let mut trader_approve = Vec::new();
    trader_approve.extend_from_slice(approve_selector);
    trader_approve.extend_from_slice(&encode_address(dex_addr));
    trader_approve.extend_from_slice(&encode_u256(max_allowance));
    engine
        .execute_call(trader, token_a, Bytes::from(trader_approve), U256::ZERO, 100_000)
        .unwrap();

    // Trader Swaps 1,000 TokenA for TokenB
    let swap_in_a = U256::from(1_000) * U256::from(10).pow(U256::from(18));
    let swap_selector = &keccak256(b"swap(address,uint256)")[0..4];
    let mut swap_calldata = Vec::new();
    swap_calldata.extend_from_slice(swap_selector);
    swap_calldata.extend_from_slice(&encode_address(token_a));
    swap_calldata.extend_from_slice(&encode_u256(swap_in_a));

    let swap_receipt = engine
        .execute_call(trader, dex_addr, Bytes::from(swap_calldata), U256::ZERO, 500_000)
        .expect("swap failed");
    assert!(swap_receipt.success, "Swap execution must succeed");

    // Verify Trader now holds TokenB
    let bal_selector = &keccak256(b"balanceOf(address)")[0..4];
    let mut trader_b_bal = Vec::new();
    trader_b_bal.extend_from_slice(bal_selector);
    trader_b_bal.extend_from_slice(&encode_address(trader));
    let b_bal_rec = engine
        .call(trader, token_b, Bytes::from(trader_b_bal), U256::ZERO, 100_000)
        .unwrap();
    let trader_b_out = U256::from_be_slice(&b_bal_rec.output);
    assert!(trader_b_out > U256::ZERO, "Trader must receive TokenB output");

    // Theoretical output calculation with 0.3% fee:
    // dy = (200,000 * 997 * 1,000) / (100,000 * 1000 + 997 * 1,000) = 199,400,000 / 100,997,000 ≈ 1,974.31 TokenB
    let expected_approx = U256::from(1_974) * U256::from(10).pow(U256::from(18));
    assert!(
        trader_b_out > expected_approx,
        "Output TokenB ({}) should match constant-product curve",
        trader_b_out
    );
}

#[test]
fn test_solidity_post_quantum_account_abstraction_precompile_0x15() {
    let mut engine = FalconEvmEngine::new_in_memory(SpecId::CANCUN);
    let deployer = address!("1000000000000000000000000000000000000001");
    let recipient = address!("5555555555555555555555555555555555555555");

    engine.set_balance(deployer, U256::from(100_000_000_000_000_000_000u128));

    // Generate post-quantum Falcon-512 owner keypair
    let signer = Falcon512Signer::generate();
    let falcon_pubkey = signer.public_key_bytes();
    assert_eq!(falcon_pubkey.len(), 897);

    // Deploy FalconAccountAbstraction contract with 10 ETH initial balance
    let aa_bin = load_contract_bin("crates_evm_contracts_FalconAccountAbstraction_sol_FalconAccountAbstraction.bin");
    let mut aa_init_code = aa_bin;
    // Constructor parameter: bytes _falconPublicKey (dynamic bytes: offset = 0x20 = 32, len = 897, bytes padded)
    let pk_encoded = encode_bytes(&falcon_pubkey);
    aa_init_code.extend_from_slice(&encode_u256(U256::from(32)));
    aa_init_code.extend_from_slice(&pk_encoded);

    let (aa_addr, _) = engine
        .deploy_contract(deployer, Bytes::from(aa_init_code), 5_000_000)
        .expect("Falcon AA deploy failed");

    // Fund the AA contract with 5 ETH
    engine.set_balance(aa_addr, U256::from(5_000_000_000_000_000_000u128));
    assert_eq!(engine.get_balance(recipient).unwrap(), U256::ZERO);

    // 1. Construct User Operation: send 1 ETH to recipient
    let value_to_send = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
    let call_data = Bytes::new();

    // Compute expected opHash matching contract:
    // keccak256(abi.encode(block.chainid, address(this), nonce, target, value, keccak256(data)))
    let chain_id = U256::from(1);
    let nonce = U256::ZERO;
    let data_hash = keccak256(&call_data);

    let mut op_preimage = Vec::new();
    op_preimage.extend_from_slice(&encode_u256(chain_id));
    op_preimage.extend_from_slice(&encode_address(aa_addr));
    op_preimage.extend_from_slice(&encode_u256(nonce));
    op_preimage.extend_from_slice(&encode_address(recipient));
    op_preimage.extend_from_slice(&encode_u256(value_to_send));
    op_preimage.extend_from_slice(data_hash.as_slice());

    let op_hash = keccak256(&op_preimage);

    // Sign op_hash with Falcon-512 private key
    let falcon_sig = signer.sign(op_hash.as_slice()).expect("Falcon signing failed");

    // Call executeUserOp(address target, uint256 value, bytes calldata data, bytes calldata falconSignature)
    // Selector: keccak256("executeUserOp(address,uint256,bytes,bytes)")[0..4]
    let exec_selector = &keccak256(b"executeUserOp(address,uint256,bytes,bytes)")[0..4];

    let data_enc = encode_bytes(&call_data);
    let sig_enc = encode_bytes(&falcon_sig);

    let offset_data = 32 * 4;
    let offset_sig = offset_data + data_enc.len();

    let mut exec_calldata = Vec::new();
    exec_calldata.extend_from_slice(exec_selector);
    exec_calldata.extend_from_slice(&encode_address(recipient));
    exec_calldata.extend_from_slice(&encode_u256(value_to_send));
    exec_calldata.extend_from_slice(&encode_u256(U256::from(offset_data)));
    exec_calldata.extend_from_slice(&encode_u256(U256::from(offset_sig)));
    exec_calldata.extend_from_slice(&data_enc);
    exec_calldata.extend_from_slice(&sig_enc);

    // Execute via relayer/bundler (e.g. deployer)
    let receipt = engine
        .execute_call(
            deployer,
            aa_addr,
            Bytes::from(exec_calldata),
            U256::ZERO,
            1_000_000,
        )
        .expect("AA executeUserOp call failed");

    assert!(receipt.success, "executeUserOp with valid Falcon-512 signature must succeed");
    assert!(receipt.gas_used >= 3_000, "Must consume precompile gas");
    println!("  -> Falcon-512 AA executeUserOp Gas Used: {}", receipt.gas_used);

    // Verify recipient received 1 ETH
    assert_eq!(
        engine.get_balance(recipient).unwrap(),
        value_to_send,
        "Recipient must receive transferred ETH from AA wallet"
    );

    // 2. Tampered signature test: should revert with InvalidFalconSignature()
    let mut corrupted_sig = falcon_sig.clone();
    corrupted_sig[10] ^= 0x55;
    let corrupted_sig_enc = encode_bytes(&corrupted_sig);

    let offset_corrupt_sig = offset_data + data_enc.len();
    let mut corrupt_calldata = Vec::new();
    corrupt_calldata.extend_from_slice(exec_selector);
    corrupt_calldata.extend_from_slice(&encode_address(recipient));
    corrupt_calldata.extend_from_slice(&encode_u256(value_to_send));
    corrupt_calldata.extend_from_slice(&encode_u256(U256::from(offset_data)));
    corrupt_calldata.extend_from_slice(&encode_u256(U256::from(offset_corrupt_sig)));
    corrupt_calldata.extend_from_slice(&data_enc);
    corrupt_calldata.extend_from_slice(&corrupted_sig_enc);

    let corrupt_receipt = engine
        .execute_call(
            deployer,
            aa_addr,
            Bytes::from(corrupt_calldata),
            U256::ZERO,
            1_000_000,
        )
        .expect("Call should return receipt");

    assert!(
        !corrupt_receipt.success,
        "executeUserOp with tampered Falcon-512 signature must revert"
    );
}

#[test]
fn test_solidity_ecdsa_account_abstraction_baseline() {
    let mut engine = FalconEvmEngine::new_in_memory(SpecId::CANCUN);
    let deployer = address!("1000000000000000000000000000000000000001");
    let recipient = address!("5555555555555555555555555555555555555555");

    engine.set_balance(deployer, U256::from(100_000_000_000_000_000_000u128));

    // Generate classical ECDSA secp256k1 keypair
    let secp = secp256k1::Secp256k1::new();
    let mut rng = secp256k1::rand::rng();
    let (sk, pk) = secp.generate_keypair(&mut rng);
    let pk_uncompressed = pk.serialize_uncompressed();
    let owner = Address::from_slice(&keccak256(&pk_uncompressed[1..])[12..32]);

    // Deploy EcdsaAccountAbstraction contract
    let aa_bin = load_contract_bin("crates_evm_contracts_EcdsaAccountAbstraction_sol_EcdsaAccountAbstraction.bin");
    let mut aa_init_code = aa_bin;
    aa_init_code.extend_from_slice(&encode_address(owner));

    let (aa_addr, deploy_receipt) = engine
        .deploy_contract(deployer, Bytes::from(aa_init_code), 5_000_000)
        .expect("ECDSA AA deploy failed");
    assert!(deploy_receipt.success);

    // Fund the AA contract with 5 ETH
    engine.set_balance(aa_addr, U256::from(5_000_000_000_000_000_000u128));
    assert_eq!(engine.get_balance(recipient).unwrap(), U256::ZERO);

    // Construct User Operation: send 1 ETH to recipient
    let value_to_send = U256::from(1_000_000_000_000_000_000u128); // 1 ETH
    let call_data = Bytes::new();

    let chain_id = U256::from(1);
    let nonce = U256::ZERO;
    let data_hash = keccak256(&call_data);

    let mut op_preimage = Vec::new();
    op_preimage.extend_from_slice(&encode_u256(chain_id));
    op_preimage.extend_from_slice(&encode_address(aa_addr));
    op_preimage.extend_from_slice(&encode_u256(nonce));
    op_preimage.extend_from_slice(&encode_address(recipient));
    op_preimage.extend_from_slice(&encode_u256(value_to_send));
    op_preimage.extend_from_slice(data_hash.as_slice());

    let op_hash = keccak256(&op_preimage);

    // Standard Ethereum Signed Message: "\x19Ethereum Signed Message:\n32" + op_hash
    let mut eth_signed_preimage = Vec::new();
    eth_signed_preimage.extend_from_slice(b"\x19Ethereum Signed Message:\n32");
    eth_signed_preimage.extend_from_slice(op_hash.as_slice());
    let eth_signed_hash = keccak256(&eth_signed_preimage);

    let msg = secp256k1::Message::from_digest(eth_signed_hash.0);
    let recoverable_sig = secp.sign_ecdsa_recoverable(msg, &sk);
    let (rec_id, sig_bytes) = recoverable_sig.serialize_compact();

    let mut ecdsa_sig = Vec::with_capacity(65);
    ecdsa_sig.extend_from_slice(&sig_bytes);
    ecdsa_sig.push(i32::from(rec_id) as u8 + 27);

    // Call executeUserOp(address target, uint256 value, bytes calldata data, bytes calldata ecdsaSignature)
    let exec_selector = &keccak256(b"executeUserOp(address,uint256,bytes,bytes)")[0..4];

    let data_enc = encode_bytes(&call_data);
    let sig_enc = encode_bytes(&ecdsa_sig);

    let offset_data = 32 * 4;
    let offset_sig = offset_data + data_enc.len();

    let mut exec_calldata = Vec::new();
    exec_calldata.extend_from_slice(exec_selector);
    exec_calldata.extend_from_slice(&encode_address(recipient));
    exec_calldata.extend_from_slice(&encode_u256(value_to_send));
    exec_calldata.extend_from_slice(&encode_u256(U256::from(offset_data)));
    exec_calldata.extend_from_slice(&encode_u256(U256::from(offset_sig)));
    exec_calldata.extend_from_slice(&data_enc);
    exec_calldata.extend_from_slice(&sig_enc);

    let receipt = engine
        .execute_call(
            deployer,
            aa_addr,
            Bytes::from(exec_calldata),
            U256::ZERO,
            1_000_000,
        )
        .expect("ECDSA AA executeUserOp call failed");

    assert!(receipt.success, "executeUserOp with valid ECDSA signature must succeed");
    println!("  -> ECDSA AA executeUserOp Gas Used: {}", receipt.gas_used);

    // Verify recipient received 1 ETH
    assert_eq!(
        engine.get_balance(recipient).unwrap(),
        value_to_send,
        "Recipient must receive transferred ETH from AA wallet"
    );

    // Verify tampered signature reverts
    let mut corrupted_sig = ecdsa_sig.clone();
    corrupted_sig[5] ^= 0xff;
    let corrupted_sig_enc = encode_bytes(&corrupted_sig);

    let offset_corrupt_sig = offset_data + data_enc.len();
    let mut corrupt_calldata = Vec::new();
    corrupt_calldata.extend_from_slice(exec_selector);
    corrupt_calldata.extend_from_slice(&encode_address(recipient));
    corrupt_calldata.extend_from_slice(&encode_u256(value_to_send));
    corrupt_calldata.extend_from_slice(&encode_u256(U256::from(offset_data)));
    corrupt_calldata.extend_from_slice(&encode_u256(U256::from(offset_corrupt_sig)));
    corrupt_calldata.extend_from_slice(&data_enc);
    corrupt_calldata.extend_from_slice(&corrupted_sig_enc);

    let corrupt_receipt = engine
        .execute_call(
            deployer,
            aa_addr,
            Bytes::from(corrupt_calldata),
            U256::ZERO,
            1_000_000,
        )
        .expect("Call should return receipt");

    assert!(!corrupt_receipt.success, "Tampered ECDSA signature must revert");
}
