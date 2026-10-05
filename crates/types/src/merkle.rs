use serde::{Deserialize, Serialize};

/// Computes the deterministic BLAKE3 Merkle root from a slice of 32-byte leaf hashes.
///
/// Implements domain-separated internal node hashing to prevent second-preimage attacks:
/// - Empty set yields `[0u8; 32]`.
/// - Single leaf returns the leaf itself.
/// - Internal nodes hash `0x01 || left || right`.
pub fn compute_merkle_root(leaves: &[[u8; 32]]) -> [u8; 32] {
    if leaves.is_empty() {
        return [0u8; 32];
    }
    if leaves.len() == 1 {
        return leaves[0];
    }

    let mut current_layer: Vec<[u8; 32]> = leaves.to_vec();

    while current_layer.len() > 1 {
        let mut next_layer = Vec::with_capacity((current_layer.len() + 1) / 2);

        for chunk in current_layer.chunks(2) {
            let left = chunk[0];
            let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };

            let mut hasher = blake3::Hasher::new();
            hasher.update(&[0x01]); // Domain separation for internal nodes
            hasher.update(&left);
            hasher.update(&right);
            next_layer.push(*hasher.finalize().as_bytes());
        }

        current_layer = next_layer;
    }

    current_layer[0]
}

/// Cryptographic Merkle inclusion proof for a leaf in the BLAKE3 Merkle tree.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MerkleProof {
    pub leaf_index: usize,
    pub total_leaves: usize,
    pub audit_path: Vec<[u8; 32]>,
}

impl MerkleProof {
    /// Generates an audit proof for the given leaf index.
    pub fn generate(leaves: &[[u8; 32]], index: usize) -> Option<Self> {
        if index >= leaves.len() {
            return None;
        }

        let total_leaves = leaves.len();
        let mut audit_path = Vec::new();
        let mut current_layer = leaves.to_vec();
        let mut current_idx = index;

        while current_layer.len() > 1 {
            let sibling_idx = if current_idx % 2 == 0 {
                if current_idx + 1 < current_layer.len() {
                    current_idx + 1
                } else {
                    current_idx // Duplicate self if odd last leaf
                }
            } else {
                current_idx - 1
            };

            audit_path.push(current_layer[sibling_idx]);

            let mut next_layer = Vec::with_capacity((current_layer.len() + 1) / 2);
            for chunk in current_layer.chunks(2) {
                let left = chunk[0];
                let right = if chunk.len() > 1 { chunk[1] } else { chunk[0] };

                let mut hasher = blake3::Hasher::new();
                hasher.update(&[0x01]);
                hasher.update(&left);
                hasher.update(&right);
                next_layer.push(*hasher.finalize().as_bytes());
            }

            current_layer = next_layer;
            current_idx /= 2;
        }

        Some(Self {
            leaf_index: index,
            total_leaves,
            audit_path,
        })
    }

    /// Verifies the Merkle inclusion proof against a known Merkle root.
    pub fn verify(&self, root: &[u8; 32], leaf_hash: &[u8; 32]) -> bool {
        if self.total_leaves == 0 {
            return false;
        }
        if self.total_leaves == 1 {
            return self.audit_path.is_empty() && root == leaf_hash;
        }

        let mut current = *leaf_hash;
        let mut idx = self.leaf_index;

        for sibling in &self.audit_path {
            let mut hasher = blake3::Hasher::new();
            hasher.update(&[0x01]);

            if idx % 2 == 0 {
                hasher.update(&current);
                hasher.update(sibling);
            } else {
                hasher.update(sibling);
                hasher.update(&current);
            }

            current = *hasher.finalize().as_bytes();
            idx /= 2;
        }

        &current == root
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_merkle_tree_empty_and_single() {
        assert_eq!(compute_merkle_root(&[]), [0u8; 32]);

        let single = [42u8; 32];
        assert_eq!(compute_merkle_root(&[single]), single);
    }

    #[test]
    fn test_merkle_proof_verification() {
        let mut leaves = Vec::new();
        for i in 0..7 {
            let mut leaf = [0u8; 32];
            leaf[0] = i as u8;
            leaves.push(leaf);
        }

        let root = compute_merkle_root(&leaves);

        for i in 0..leaves.len() {
            let proof = MerkleProof::generate(&leaves, i).expect("Proof generation must succeed");
            assert!(proof.verify(&root, &leaves[i]));

            // Tamper leaf check
            let mut tampered = leaves[i];
            tampered[1] ^= 0xff;
            assert!(!proof.verify(&root, &tampered));
        }
    }
}
