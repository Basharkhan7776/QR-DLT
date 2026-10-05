//! Address generation: 20-byte BLAKE3 truncated hash of public key bytes.

pub type Address = [u8; 20];

/// Derives a 20-byte deterministic account address from any public key bytes using BLAKE3.
pub fn address_from_public_key(public_key_bytes: &[u8]) -> Address {
    let hash = blake3::hash(public_key_bytes);
    let mut address = [0u8; 20];
    address.copy_from_slice(&hash.as_bytes()[0..20]);
    address
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
}
