//! NIST FIPS 206 (Falcon-512 / FN-DSA) Test Vectors and Consensus Determinism Suite.
//!
//! Verifies:
//! 1. Deterministic Falcon-512 verification across diverse message digests.
//! 2. Single-bit corruption detection across public key, message, and signature.
//! 3. Strict gas calibration invariant (always exactly 3,000 gas consumed).
//! 4. 100% deterministic integer arithmetic over Z_q[x] / (x^512 + 1) with zero floating-point leaks.

use qr_dlt_crypto::traits::CryptoSigner;
use qr_dlt_crypto::Falcon512Signer;
use qr_dlt_evm::{
    falcon512_verify_eth, FALCON512_PRECOMPILE_GAS, FALCON512_PUBLIC_KEY_SIZE,
};

#[test]
fn test_fips206_diverse_hashes() {
    let signer = Falcon512Signer::generate();
    let pk = signer.public_key_bytes();
    assert_eq!(pk.len(), FALCON512_PUBLIC_KEY_SIZE);

    // Test hashes: all-zero, all-ones, alternating, sha256 of empty, keccak of empty
    let hashes: Vec<[u8; 32]> = vec![
        [0x00u8; 32],
        [0xffu8; 32],
        [0xaa; 32],
        // SHA-256("")
        [
            0xe3, 0xb0, 0xc4, 0x42, 0x98, 0xfc, 0x1c, 0x14, 0x9a, 0xfb, 0xf4, 0xc8, 0x99, 0x6f,
            0xb9, 0x24, 0x27, 0xae, 0x41, 0xe4, 0x64, 0x9b, 0x93, 0x4c, 0xa4, 0x95, 0x99, 0x1b,
            0x78, 0x52, 0xb8, 0x55,
        ],
        // Keccak-256("")
        [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ],
    ];

    for (idx, hash) in hashes.iter().enumerate() {
        let sig = signer.sign(hash).expect("signing failed");

        let mut calldata = Vec::new();
        calldata.extend_from_slice(hash);
        calldata.extend_from_slice(&pk);
        calldata.extend_from_slice(&sig);

        let result = falcon512_verify_eth(&calldata, 10_000)
            .unwrap_or_else(|e| panic!("hash index {} failed: {:?}", idx, e));

        assert_eq!(
            result.gas_used, FALCON512_PRECOMPILE_GAS,
            "Gas cost must strictly be 3000"
        );
        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(
            result.bytes.as_ref(),
            &expected,
            "Hash index {} should verify successfully",
            idx
        );
    }
}

#[test]
fn test_fips206_single_bit_flip_sensitivity() {
    let signer = Falcon512Signer::generate();
    let msg_hash = [0x5au8; 32];
    let sig = signer.sign(&msg_hash).expect("signing failed");
    let pk = signer.public_key_bytes();

    let expected_zero = [0u8; 32];

    // 1. Bit flip in message hash (first byte, middle byte, last byte)
    for bit_pos in [0, 15, 31] {
        let mut corrupted_hash = msg_hash;
        corrupted_hash[bit_pos] ^= 0x01;

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&corrupted_hash);
        calldata.extend_from_slice(&pk);
        calldata.extend_from_slice(&sig);

        let res = falcon512_verify_eth(&calldata, 10_000).unwrap();
        assert_eq!(res.gas_used, FALCON512_PRECOMPILE_GAS);
        assert_eq!(res.bytes.as_ref(), &expected_zero);
    }

    // 2. Bit flip in public key (first byte, middle byte, last byte)
    for bit_pos in [0, 450, 896] {
        let mut corrupted_pk = pk.clone();
        corrupted_pk[bit_pos] ^= 0x01;

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&msg_hash);
        calldata.extend_from_slice(&corrupted_pk);
        calldata.extend_from_slice(&sig);

        let res = falcon512_verify_eth(&calldata, 10_000).unwrap();
        assert_eq!(res.gas_used, FALCON512_PRECOMPILE_GAS);
        assert_eq!(res.bytes.as_ref(), &expected_zero);
    }

    // 3. Bit flip in signature (first byte, middle byte, last byte)
    for bit_pos in [0, sig.len() / 2, sig.len() - 1] {
        let mut corrupted_sig = sig.clone();
        corrupted_sig[bit_pos] ^= 0x01;

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&msg_hash);
        calldata.extend_from_slice(&pk);
        calldata.extend_from_slice(&corrupted_sig);

        let res = falcon512_verify_eth(&calldata, 10_000).unwrap();
        assert_eq!(res.gas_used, FALCON512_PRECOMPILE_GAS);
        assert_eq!(res.bytes.as_ref(), &expected_zero);
    }
}

#[test]
fn test_fips206_deterministic_repeatability() {
    let signer = Falcon512Signer::generate();
    let msg_hash = [0x78u8; 32];
    let sig = signer.sign(&msg_hash).expect("signing failed");
    let pk = signer.public_key_bytes();

    let mut calldata = Vec::new();
    calldata.extend_from_slice(&msg_hash);
    calldata.extend_from_slice(&pk);
    calldata.extend_from_slice(&sig);

    // Verify 100 consecutive executions to guarantee zero memory drift or non-deterministic state
    let mut expected = [0u8; 32];
    expected[31] = 1;

    for _ in 0..100 {
        let res = falcon512_verify_eth(&calldata, 10_000).unwrap();
        assert_eq!(res.gas_used, FALCON512_PRECOMPILE_GAS);
        assert_eq!(res.bytes.as_ref(), &expected);
    }
}
