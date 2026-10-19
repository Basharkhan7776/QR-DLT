//! Address generation: 20-byte BLAKE3 truncated hash and Ethereum Keccak-256 address derivation.

use sha3::{Digest, Keccak256};

pub type Address = [u8; 20];

/// Derives a 20-byte deterministic account address from public key bytes using BLAKE3.
/// Used in the baseline QR-DLT PoA ledger.
pub fn address_from_public_key(public_key_bytes: &[u8]) -> Address {
    let hash = blake3::hash(public_key_bytes);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash.as_bytes()[0..20]);
    address
}

/// Derives an Ethereum-standard 20-byte account address from a Falcon-512 public key:
/// Address = keccak256(falcon_pubkey)[12..32]
pub fn evm_address_from_falcon_pubkey(falcon_public_key_bytes: &[u8]) -> Address {
    let digest = keccak256(falcon_public_key_bytes);
    let mut address = [0u8; 20];
    address.copy_from_slice(&digest[12..32]);
    address
}

/// Computes the standard Keccak-256 32-byte digest of arbitrary bytes.
pub fn keccak256(data: &[u8]) -> [u8; 32] {
    let mut hasher = Keccak256::new();
    hasher.update(data);
    let digest = hasher.finalize();
    let mut out = [0u8; 32];
    out.copy_from_slice(&digest);
    out
}

/// Formats an address into a hex string with `0x` prefix.
pub fn address_to_hex(address: &Address) -> String {
    format!("0x{}", hex::encode(address))
}

mod hex {
    pub fn encode(data: &[u8]) -> String {
        data.iter().map(|b| format!("{:02x}", b)).collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_address_derivation_deterministic() {
        let pk1 = b"sample_public_key_bytes_1234567890";
        let addr1 = address_from_public_key(pk1);
        let addr2 = address_from_public_key(pk1);
        assert_eq!(addr1, addr2);
        assert_eq!(addr1.len(), 20);

        let pk2 = b"different_public_key_bytes_1234567890";
        let addr3 = address_from_public_key(pk2);
        assert_ne!(addr1, addr3);
    }

    #[test]
    fn test_evm_address_derivation_keccak() {
        // Standard Keccak-256 of empty bytes
        let empty_hash = keccak256(b"");
        let expected_empty_hash = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(empty_hash, expected_empty_hash);

        // EVM address must be the last 20 bytes (indices 12..32)
        let addr = evm_address_from_falcon_pubkey(b"");
        assert_eq!(addr, expected_empty_hash[12..32]);

        // Non-empty public key derivation
        let fake_pk = vec![0x42u8; 897];
        let addr1 = evm_address_from_falcon_pubkey(&fake_pk);
        let addr2 = evm_address_from_falcon_pubkey(&fake_pk);
        assert_eq!(addr1, addr2);
        assert_eq!(addr1.len(), 20);
        assert_ne!(addr1, [0u8; 20]);
    }
}
