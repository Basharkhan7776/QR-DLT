//! Native Falcon-512 Verification Precompile for EVM (Address 0x15).
//!
//! # Specification
//! - **Address:** `0x0000000000000000000000000000000000000015`
//! - **Base Gas:** 3,000 gas (calibrated to AVX2 SIMD integer polynomial verification cycles).
//! - **Input Formats Supported:**
//!   1. **Packed Format:** `[32 B msg_hash][897 B public_key][~666 B signature]`
//!   2. **Length-Prefixed Format:** `[32 B msg_hash][2 B pk_len][897 B pk][2 B sig_len][sig]`
//!   3. **Solidity ABI Encoded Format:** `abi.encode(bytes32 msg_hash, bytes public_key, bytes signature)`
//! - **Output:** 32-byte word:
//!   - `0x00...01` (value 1) if the signature is cryptographically valid.
//!   - `0x00...00` (value 0) if the signature is invalid or input is malformed.
//! - **Gas Failure:** Halts with `PrecompileHalt::OutOfGas` if available gas < 3,000.
//!
//! # Determinism Guarantee
//! Falcon-512 verification employs 100% deterministic integer arithmetic over the ring
//! Z_q[x] / (x^512 + 1) with modulus q = 12289, Number Theoretic Transforms (NTT),
//! and fixed-point constant-time Euclidean norm checking (||(s1, s2)||^2 <= beta^2).
//! It contains zero floating-point instructions in verification, preventing consensus forks.

use qr_dlt_crypto::traits::CryptoVerifier;
use qr_dlt_crypto::Falcon512Verifier;
use revm::precompile::{
    call_eth_precompile, EthPrecompileOutput, EthPrecompileResult, Precompile, PrecompileHalt,
    PrecompileId, PrecompileResult,
};
use revm::primitives::{address, Address, Bytes};

/// Canonical EVM address of the Falcon-512 verification precompile.
pub const FALCON512_PRECOMPILE_ADDRESS: Address =
    address!("0000000000000000000000000000000000000015");

/// Base gas cost for executing Falcon-512 verification in the EVM.
pub const FALCON512_PRECOMPILE_GAS: u64 = 3_000;

/// Expected public key size for Falcon-512 (FIPS 206 / FN-DSA).
pub const FALCON512_PUBLIC_KEY_SIZE: usize = 897;

/// Decoded input parameters for Falcon-512 verification.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Falcon512CallData<'a> {
    pub message_hash: &'a [u8],
    pub public_key: &'a [u8],
    pub signature: &'a [u8],
}

impl<'a> Falcon512CallData<'a> {
    /// Decodes raw calldata from any of the three supported layouts:
    /// 1. Packed (`32 B hash || 897 B pk || sig`)
    /// 2. Length-prefixed (`32 B hash || 2 B pk_len || pk || 2 B sig_len || sig`)
    /// 3. Solidity ABI-encoded (`bytes32, bytes, bytes`)
    pub fn decode(input: &'a [u8]) -> Option<Self> {
        // Try decoding direct payload first
        if let Some(decoded) = Self::decode_payload(input) {
            return Some(decoded);
        }

        // If direct decode failed, try stripping optional 4-byte selector
        if input.len() >= 4
            && let Some(decoded) = Self::decode_payload(&input[4..])
        {
            return Some(decoded);
        }

        None
    }

    /// Internal decoder for a calldata slice
    fn decode_payload(data: &'a [u8]) -> Option<Self> {
        if data.len() < 32 {
            return None;
        }

        // Try Format 3: Solidity ABI encoded (bytes32, bytes, bytes)
        if let Some(abi_decoded) = Self::decode_abi(data) {
            return Some(abi_decoded);
        }

        // Try Format 2: Length-prefixed with 2-byte lengths
        if data.len() >= 34 {
            let pk_len = u16::from_be_bytes([data[32], data[33]]) as usize;
            if pk_len == FALCON512_PUBLIC_KEY_SIZE && data.len() >= 34 + pk_len + 2 {
                let msg_hash = &data[0..32];
                let pk = &data[34..34 + pk_len];
                let sig_offset = 34 + pk_len;
                let sig_len = u16::from_be_bytes([data[sig_offset], data[sig_offset + 1]]) as usize;
                let sig_start = sig_offset + 2;
                if data.len() >= sig_start + sig_len && sig_len > 0 {
                    return Some(Self {
                        message_hash: msg_hash,
                        public_key: pk,
                        signature: &data[sig_start..sig_start + sig_len],
                    });
                }
            }
        }

        // Try Format 1: Direct packed (32 B hash || 897 B pk || sig)
        if data.len() > 32 + FALCON512_PUBLIC_KEY_SIZE {
            let msg_hash = &data[0..32];
            let pk = &data[32..32 + FALCON512_PUBLIC_KEY_SIZE];
            let sig = &data[32 + FALCON512_PUBLIC_KEY_SIZE..];
            if !sig.is_empty() {
                return Some(Self {
                    message_hash: msg_hash,
                    public_key: pk,
                    signature: sig,
                });
            }
        }

        None
    }

    /// Decodes standard Solidity ABI encoding: `(bytes32, bytes, bytes)`
    fn decode_abi(data: &'a [u8]) -> Option<Self> {
        // Minimum ABI payload: 3 head words = 96 bytes
        if data.len() < 96 {
            return None;
        }

        let msg_hash = &data[0..32];

        // Word 1: offset of public_key (must be >= 96)
        let pk_offset = read_u32_offset(&data[32..64])?;
        // Word 2: offset of signature (must be >= 96)
        let sig_offset = read_u32_offset(&data[64..96])?;

        if pk_offset >= data.len() || sig_offset >= data.len() || pk_offset + 32 > data.len() {
            return None;
        }

        // Read pk length
        let pk_len = read_u32_offset(&data[pk_offset..pk_offset + 32])?;
        if pk_len != FALCON512_PUBLIC_KEY_SIZE || pk_offset + 32 + pk_len > data.len() {
            return None;
        }
        let pk = &data[pk_offset + 32..pk_offset + 32 + pk_len];

        // Read sig length
        if sig_offset + 32 > data.len() {
            return None;
        }
        let sig_len = read_u32_offset(&data[sig_offset..sig_offset + 32])?;
        if sig_len == 0 || sig_offset + 32 + sig_len > data.len() {
            return None;
        }
        let sig = &data[sig_offset + 32..sig_offset + 32 + sig_len];

        Some(Self {
            message_hash: msg_hash,
            public_key: pk,
            signature: sig,
        })
    }
}

/// Helper to read a 32-byte big-endian ABI word as a usize offset/length
fn read_u32_offset(slice: &[u8]) -> Option<usize> {
    if slice.len() != 32 {
        return None;
    }
    // High 28 bytes must be 0 for realistic in-memory calldata offsets
    if slice[0..28].iter().any(|&b| b != 0) {
        return None;
    }
    let val = u32::from_be_bytes([slice[28], slice[29], slice[30], slice[31]]) as usize;
    Some(val)
}

/// Ethereum-level precompile function for Falcon-512 verification.
pub fn falcon512_verify_eth(input: &[u8], gas_limit: u64) -> EthPrecompileResult {
    // 1. Gas check
    if gas_limit < FALCON512_PRECOMPILE_GAS {
        return Err(PrecompileHalt::OutOfGas);
    }

    // 2. Decode and verify calldata:
    // Try candidate 1: direct unstripped payload
    let mut is_valid = false;
    let verifier = Falcon512Verifier;

    if let Some(calldata) = Falcon512CallData::decode_payload(input)
        && verifier
            .verify(
                calldata.message_hash,
                calldata.signature,
                calldata.public_key,
            )
            .is_ok()
    {
        is_valid = true;
    }

    // Try candidate 2: payload with 4-byte selector stripped
    if !is_valid
        && input.len() >= 4
        && let Some(calldata) = Falcon512CallData::decode_payload(&input[4..])
        && verifier
            .verify(
                calldata.message_hash,
                calldata.signature,
                calldata.public_key,
            )
            .is_ok()
    {
        is_valid = true;
    }

    // 3. Return 32-byte EVM boolean result word (1 = valid, 0 = invalid)
    let mut output = [0u8; 32];
    if is_valid {
        output[31] = 1;
    }

    Ok(EthPrecompileOutput::new(
        FALCON512_PRECOMPILE_GAS,
        Bytes::copy_from_slice(&output),
    ))
}

/// Top-level precompile function returning a full [`PrecompileOutput`].
pub fn falcon512_precompile_fn(
    input: &[u8],
    gas_limit: u64,
    reservoir: u64,
) -> PrecompileResult {
    Ok(call_eth_precompile(
        falcon512_verify_eth,
        input,
        gas_limit,
        reservoir,
    ))
}

/// Constructs a revm `Precompile` instance for Falcon-512 verification.
pub fn falcon512_precompile() -> Precompile {
    Precompile::new(
        PrecompileId::custom("falcon512_verify"),
        FALCON512_PRECOMPILE_ADDRESS,
        falcon512_precompile_fn,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use qr_dlt_crypto::traits::CryptoSigner;
    use qr_dlt_crypto::Falcon512Signer;

    #[test]
    fn test_precompile_valid_signature_packed() {
        let signer = Falcon512Signer::generate();
        let msg_hash = [0x42u8; 32];
        let sig = signer.sign(&msg_hash).expect("signing failed");
        let pk = signer.public_key_bytes();

        // Construct packed calldata: [hash (32)] [pk (897)] [sig]
        let mut calldata = Vec::new();
        calldata.extend_from_slice(&msg_hash);
        calldata.extend_from_slice(&pk);
        calldata.extend_from_slice(&sig);

        let result = falcon512_verify_eth(&calldata, 10_000).expect("execution failed");
        assert_eq!(result.gas_used, FALCON512_PRECOMPILE_GAS);

        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(result.bytes.as_ref(), &expected);
    }

    #[test]
    fn test_precompile_valid_signature_length_prefixed() {
        let signer = Falcon512Signer::generate();
        let msg_hash = [0x33u8; 32];
        let sig = signer.sign(&msg_hash).expect("signing failed");
        let pk = signer.public_key_bytes();

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&msg_hash);
        calldata.extend_from_slice(&(pk.len() as u16).to_be_bytes());
        calldata.extend_from_slice(&pk);
        calldata.extend_from_slice(&(sig.len() as u16).to_be_bytes());
        calldata.extend_from_slice(&sig);

        let result = falcon512_verify_eth(&calldata, 10_000).expect("execution failed");
        assert_eq!(result.gas_used, FALCON512_PRECOMPILE_GAS);

        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(result.bytes.as_ref(), &expected);
    }

    #[test]
    fn test_precompile_tampered_message_returns_zero() {
        let signer = Falcon512Signer::generate();
        let msg_hash = [0x42u8; 32];
        let sig = signer.sign(&msg_hash).expect("signing failed");
        let pk = signer.public_key_bytes();

        let mut tampered_hash = msg_hash;
        tampered_hash[0] ^= 0xff; // Tamper with message hash

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&tampered_hash);
        calldata.extend_from_slice(&pk);
        calldata.extend_from_slice(&sig);

        let result = falcon512_verify_eth(&calldata, 10_000).expect("execution failed");
        assert_eq!(result.gas_used, FALCON512_PRECOMPILE_GAS);

        let expected = [0u8; 32];
        assert_eq!(result.bytes.as_ref(), &expected);
    }

    #[test]
    fn test_precompile_tampered_signature_returns_zero() {
        let signer = Falcon512Signer::generate();
        let msg_hash = [0x42u8; 32];
        let mut sig = signer.sign(&msg_hash).expect("signing failed");
        let pk = signer.public_key_bytes();

        sig[10] ^= 0xaa; // Corrupt signature byte

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&msg_hash);
        calldata.extend_from_slice(&pk);
        calldata.extend_from_slice(&sig);

        let result = falcon512_verify_eth(&calldata, 10_000).expect("execution failed");
        assert_eq!(result.gas_used, FALCON512_PRECOMPILE_GAS);

        let expected = [0u8; 32];
        assert_eq!(result.bytes.as_ref(), &expected);
    }

    #[test]
    fn test_precompile_out_of_gas() {
        let calldata = vec![0u8; 1000];
        let err = falcon512_verify_eth(&calldata, FALCON512_PRECOMPILE_GAS - 1).unwrap_err();
        assert_eq!(err, PrecompileHalt::OutOfGas);
    }

    #[test]
    fn test_precompile_malformed_input_returns_zero() {
        let malformed = vec![0x12; 50]; // Too short for Falcon-512
        let result = falcon512_verify_eth(&malformed, 10_000).expect("execution failed");
        assert_eq!(result.gas_used, FALCON512_PRECOMPILE_GAS);

        let expected = [0u8; 32];
        assert_eq!(result.bytes.as_ref(), &expected);
    }

    #[test]
    fn test_precompile_with_4byte_function_selector() {
        let signer = Falcon512Signer::generate();
        let msg_hash = [0x55u8; 32];
        let sig = signer.sign(&msg_hash).expect("signing failed");
        let pk = signer.public_key_bytes();

        let mut calldata = Vec::new();
        calldata.extend_from_slice(&[0x12, 0x34, 0x56, 0x78]); // 4-byte selector
        calldata.extend_from_slice(&msg_hash);
        calldata.extend_from_slice(&pk);
        calldata.extend_from_slice(&sig);

        let result = falcon512_verify_eth(&calldata, 10_000).expect("execution failed");
        assert_eq!(result.gas_used, FALCON512_PRECOMPILE_GAS);

        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(result.bytes.as_ref(), &expected);
    }

    #[test]
    fn test_precompile_solidity_abi_encoded() {
        let signer = Falcon512Signer::generate();
        let msg_hash = [0x77u8; 32];
        let sig = signer.sign(&msg_hash).expect("signing failed");
        let pk = signer.public_key_bytes();

        let mut calldata = Vec::new();

        // 1. Head: msg_hash (word 0, bytes 0..32)
        calldata.extend_from_slice(&msg_hash);

        // 2. Head: offset of pk (word 1, bytes 32..64) -> 96 (0x60)
        let mut pk_offset_word = [0u8; 32];
        pk_offset_word[31] = 96;
        calldata.extend_from_slice(&pk_offset_word);

        // Calculate pk length padded to 32 bytes:
        // pk len = 897. 897 + 31 / 32 * 32 = 928 bytes.
        // sig offset = 96 (head end) + 32 (pk len word) + 928 (pk data) = 1056.
        let sig_offset = 1056usize;
        let mut sig_offset_word = [0u8; 32];
        sig_offset_word[30] = (sig_offset >> 8) as u8;
        sig_offset_word[31] = (sig_offset & 0xff) as u8;
        calldata.extend_from_slice(&sig_offset_word);

        // 3. Tail: pk length (word at 96..128)
        let mut pk_len_word = [0u8; 32];
        pk_len_word[30] = (pk.len() >> 8) as u8;
        pk_len_word[31] = (pk.len() & 0xff) as u8;
        calldata.extend_from_slice(&pk_len_word);

        // 4. Tail: pk bytes + padding to 32 bytes
        calldata.extend_from_slice(&pk);
        let pk_pad = 928 - pk.len();
        calldata.extend(std::iter::repeat_n(0u8, pk_pad));

        // 5. Tail: sig length (word at 1056..1088)
        let mut sig_len_word = [0u8; 32];
        sig_len_word[30] = (sig.len() >> 8) as u8;
        sig_len_word[31] = (sig.len() & 0xff) as u8;
        calldata.extend_from_slice(&sig_len_word);

        // 6. Tail: sig bytes + padding to 32 bytes
        calldata.extend_from_slice(&sig);
        let sig_padded_len = sig.len().div_ceil(32) * 32;
        let sig_pad = sig_padded_len - sig.len();
        calldata.extend(std::iter::repeat_n(0u8, sig_pad));

        let result = falcon512_verify_eth(&calldata, 10_000).expect("execution failed");
        assert_eq!(result.gas_used, FALCON512_PRECOMPILE_GAS);

        let mut expected = [0u8; 32];
        expected[31] = 1;
        assert_eq!(result.bytes.as_ref(), &expected);
    }
}
