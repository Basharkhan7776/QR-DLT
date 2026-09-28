# Quantum-Resilient Distributed Ledger (QR-DLT)

**Project Title:** Empirical Evaluation and Systems Optimization of Lattice-Based Digital Signatures in a From-Scratch Rust Blockchain Architecture

**Principal Investigators:** Bashar Khan & Zaheer Khan  
**Target Environment:** Bare-Metal Linux (Ubuntu 22.04/24.04 LTS or WSL2) on Intel Core i5 (12th Gen Alder Lake, AVX2/BMI2/SHA-NI), 16 GB DDR4/DDR5 RAM, Integrated Graphics.

---

## 1. Project Motivation: The Previous Scenario vs. The Post-Quantum Imperative

### 1.1 The Previous Scenario (The Classical Status Quo)

Contemporary distributed ledger technologies (DLTs)—including Bitcoin, Ethereum, Solana, and Polkadot—anchor their fundamental security guarantees in classical public-key cryptography. Specifically:

* **Bitcoin & Ethereum:** Rely on the Elliptic Curve Digital Signature Algorithm (ECDSA) instantiated over the Koblitz curve $\text{secp256k1}$.
* **Solana, Cardano, & Near:** Rely on the Edwards-curve Digital Signature Algorithm (EdDSA) over Curve25519 ($\text{Ed25519}$).
* **Legacy & Enterprise Ledgers:** Periodically rely on RSA ($2048\text{ to }4096\text{ bits}$).

All these primitives depend on two foundational computational hardness assumptions:
1. **The Integer Factorization Problem (IFP)** (e.g., RSA).
2. **The Discrete Logarithm Problem (DLP)** and its elliptic-curve equivalent, the **Elliptic Curve Discrete Logarithm Problem (ECDLP)**.

On classical von Neumann computing architectures, the best generic attack against ECDLP is Pollard's rho algorithm, which requires fully exponential time:

$$
\mathcal{O}\left(\sqrt{n}\right) \approx \mathcal{O}\left(2^{128}\right) \text{ operations for a 256-bit elliptic curve}
$$

Because of this exponential barrier, classical blockchains enjoy exceptionally compact operational parameters:
* An $\text{Ed25519}$ public key requires just $32\text{ bytes}$, and its signature is $64\text{ bytes}$.
* An ECDSA $\text{secp256k1}$ public key requires $33\text{ bytes}$ (compressed), and its signature is $\approx 64\text{ to }72\text{ bytes}$ (DER/compact format).

Consequently, existing mempool gossip protocols, wire serializations, block headers, and state Merkle trees were designed under the implicit architectural assumption that cryptographic proofs of identity occupy negligible payload space ($\le 100\text{ bytes}$).

---

### 1.2 The Quantum Threat: Shor's Algorithm and ECDLP Collapse

In 1994, Peter Shor formulated a quantum polynomial-time algorithm for prime factorization and discrete logarithms on a Fault-Tolerant Quantum Computer (FTQC):

$$
\mathcal{O}\left((\log N)^3\right) \text{ gate complexity}
$$

In 2003, Proos and Zalka demonstrated that Shor's algorithm solves ECDLP with significantly fewer quantum resources than factoring equivalent-security RSA moduli. Specifically, breaking a $256\text{-bit}$ elliptic curve requires only $\approx 1,000 \text{ to } 1,500$ error-corrected, logical qubits.

```
       CLASSICAL DOMAIN (Exponential Barrier)
       ----------------------------------------------------
       ECDLP (secp256k1 / Ed25519): ~2^128 operations
       Best classical algorithm: Pollard's rho O(√n)
       [IMPASSABLE ON CLASSICAL SUPERCOMPUTERS]

                              │
                              │ Arrival of Cryptographically Relevant
                              │ Quantum Computers (CRQCs)
                              ▼
       QUANTUM DOMAIN (Polynomial Collapse)
       ----------------------------------------------------
       Shor's Algorithm: O((log N)^3) operations
       Logical Qubits Required: ~1,000 - 1,500 logical qubits
       [TOTAL EXPLOITATION: Private keys derived from public keys]
```

#### Attack Windows on Distributed Ledgers
As demonstrated by Aggarwal et al. (2018), quantum adversaries target two primary threat vectors in public ledgers:

1. **Long-Range / Static Attack (Exposed Public Keys & Address Reuse):**
   * Whenever an account transacts, its raw public key is permanently published on-chain.
   * A quantum adversary can read public keys from ledger history, execute Shor's algorithm offline to compute the underlying private scalar $d$ where $Q = d \cdot G$, and forge transactions that completely drain user balances.
   * In Bitcoin alone, over 4 million BTC (including Satoshi Nakamoto’s early coinbase outputs and legacy Pay-to-Public-Key / reused Pay-to-PubKey-Hash addresses) directly expose their unhashed public keys.

2. **Short-Range / Front-Running Attack (Mempool Interception):**
   * Even when an address scheme uses address hashing ($\text{Address} = \text{Hash}(\text{PublicKey})$), the raw public key must still be broadcast to the P2P mempool when validating a transaction.
   * If an adversary operates a quantum computer capable of resolving the discrete logarithm faster than the network's consensus block finality time (e.g., within Bitcoin's 10-minute target or a PoS 12-second slot), the attacker intercepts the transaction in the mempool, derives the private key, and submits a higher-gas replacement transaction to siphon the funds before the legitimate block is finalized.

---

### 1.3 Why We Are Building This: The Systems-Level Gap

Faced with this threat, the global cryptographic community, led by the National Institute of Standards and Technology (NIST), finalized its first post-quantum cryptographic standards in 2024 (FIPS 204 ML-DSA and FIPS 206 FN-DSA/Falcon).

However, **there is a profound gap between theoretical cryptography and real-world distributed systems**:

1. **Most PQC Research Stops at Microbenchmarks:**  
   Standard papers evaluate post-quantum signature verification solely as an isolated CPU loop ($X$ microseconds per signature on a single thread). They completely ignore what happens when these signatures are placed into a high-throughput, multi-peer distributed state machine.

2. **The "Lattice Tax" Breaks Standard Blockchain Architectures:**  
   Lattice-based digital signatures require orders of magnitude more storage and bandwidth than elliptic curves:
   * **Ed25519:** $32\text{ B}$ public key, $64\text{ B}$ signature.
   * **Falcon-512:** $897\text{ B}$ public key, $\approx 666\text{ B}$ signature ($\approx 16\times$ larger).
   * **ML-DSA-44:** $1,312\text{ B}$ public key, $2,420\text{ B}$ signature ($\approx 40\times$ larger).

3. **Cascading Systems Bottlenecks:**
   * **P2P Wire Saturation:** Propagating a block of $2,000$ transactions in Ed25519 requires transmitting $\approx 200\text{ KB}$ of cryptographic data. In ML-DSA-44, that exact same block requires transmitting $\approx 7.46\text{ MB}$ of cryptographic data. This leads to TCP packet fragmentation, increased packet drop rates, and higher hop-by-hop latency across distributed nodes.
   * **Orphan & Fork Rate Amplification:** Under proof-of-work or round-robin proof-of-authority, block propagation delays directly increase the probability that two validators produce competing blocks at the same height, weakening consensus finality and degrading network throughput.
   * **Hardware Cache Trashing:** Verifying thousands of lattice signatures involves loading large polynomial vectors into CPU memory. The working set of a $10,000\text{-tx}$ batch in ML-DSA is $\approx 37\text{ MB}$, completely overflowing the CPU's L1 ($32\text{–}48\text{ KB}$) and L2 ($1.25\text{ MB}$) caches, causing heavy bus locking and memory bandwidth stalls.
   * **State & Disk Bloat:** Storing full lattice witness signatures indefinitely will bloat ledger state storage by gigabytes per week under normal commercial transaction volume.

4. **Why From-Scratch Rust?**  
   Heavy monolithic frameworks like Substrate or Cosmos/CometBFT introduce immense abstraction layers, garbage-collected serialization, complex event loops, and hidden memory allocations. By engineering a custom, modular Rust engine from the ground up:
   * We retain **deterministic byte-level control** over memory layout, thread scheduling, serialization pipelines, and wire packets.
   * We isolate and measure pure cryptographic overhead versus networking and storage overhead with zero framework noise.
   * We can implement novel optimizations (e.g., Segregated Witness with Epoch Pruning and core-pinned batch verification) natively inside the consensus loop.

---

## 2. Foundational Research Literature & Academic Citations

This project directly builds upon, implements, and benchmarks the mathematical and algorithmic discoveries documented in the following research papers:

### 2.1 Foundational Quantum Threat Papers

1. **Shor, P. W. (1994).** *Algorithms for quantum computation: discrete logarithms and factoring.*  
   *Venue:* 35th Annual Symposium on Foundations of Computer Science (FOCS 1994), IEEE.  
   *Link:* [IEEE Xplore / DOI: 10.1109/SFCS.1994.365700](https://doi.org/10.1109/SFCS.1994.365700)  
   *Relevance:* Established the polynomial-time quantum algorithm breaking RSA and discrete logarithms.

2. **Proos, J., & Zalka, C. (2003).** *Shor's discrete logarithm quantum algorithm for elliptic curves.*  
   *Venue:* Quantum Information & Computation (QIC), Vol. 3, No. 4, pp. 317–344.  
   *Link:* [arXiv:quant-ph/0301164](https://arxiv.org/abs/quant-ph/0301164)  
   *Relevance:* Proved that elliptic-curve cryptography collapses under Shor's algorithm with significantly fewer logical qubits than integer factorization.

3. **Aggarwal, D., Brennen, G. K., Lee, T., Santha, M., & Tomamichel, M. (2018).** *Quantum attacks on Bitcoin, and how to protect against them.*  
   *Venue:* Ledger, Vol. 3, pp. 127–144.  
   *Link:* [Ledger Journal / DOI: 10.5195/ledger.2018.127](https://doi.org/10.5195/ledger.2018.127) | [arXiv:1710.10377](https://arxiv.org/abs/1710.10377)  
   *Relevance:* Analyzed mempool front-running vs. public key exposure windows and evaluated post-quantum signature viability for distributed ledgers.

---

### 2.2 Primary Lattice Cryptographic Standards & Source Papers

4. **NIST FIPS 204 (2024):** *Module-Lattice-Based Digital Signature Standard (ML-DSA).*  
   *Author/Publisher:* National Institute of Standards and Technology (NIST), U.S. Department of Commerce.  
   *Link:* [NIST CSRC FIPS 204 Publication](https://csrc.nist.gov/pubs/fips/204/final) | [DOI: 10.6028/NIST.FIPS.204](https://doi.org/10.6028/NIST.FIPS.204)  
   *Foundation:* Based on the CRYSTALS-Dilithium proposal.  
   *Dilithium Original Paper:* Ducas, L., Kiltz, E., Lepoint, T., Lyubashevsky, V., Schwabe, P., Seiler, G., & Stehlé, D. (2018). *CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme.* IACR Trans. Cryptogr. Hardw. Embed. Syst. (CHES 2018).  
   *Link:* [IACR ePrint 2017/633](https://eprint.iacr.org/2017/633)

5. **NIST FIPS 206 (2024):** *Fast-Fourier Lattice-Based Digital Signature Standard (FN-DSA / Falcon).*  
   *Author/Publisher:* National Institute of Standards and Technology (NIST), U.S. Department of Commerce.  
   *Link:* [NIST CSRC FIPS 206 Publication](https://csrc.nist.gov/pubs/fips/206/final) | [DOI: 10.6028/NIST.FIPS.206](https://doi.org/10.6028/NIST.FIPS.206)  
   *Foundation:* Based on the Falcon algorithm.  
   *Falcon Original Paper:* Fouque, P. A., Hoffstein, J., Kirchner, P., Lyubashevsky, V., Pornin, T., Prest, T., Ricosset, T., Seiler, G., Whyte, W., & Zhang, Z. (2018). *Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU.*  
   *Link:* [IACR ePrint 2018/904](https://eprint.iacr.org/2018/904) | [Falcon Official Website](https://falcon-sign.info/)

---

### 2.3 Architectural & Blockchain Design References

6. **Wuille, P., Johnson, L., & Corallo, M. (2015).** *Segregated Witness (Consensus layer).*  
   *Specification:* Bitcoin Improvement Proposal 141 (BIP 141).  
   *Link:* [Bitcoin BIP 141 GitHub Specification](https://github.com/bitcoin/bips/blob/master/bip-0141.mediawiki)  
   *Relevance:* Structural model for separating transaction execution intents from validation witnesses to prevent malleability and decouple cryptographic state storage.

7. **Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., & Yang, B. Y. (2012).** *High-speed high-security signatures (Ed25519).*  
   *Venue:* Journal of Cryptographic Engineering, Vol. 2, pp. 77–89.  
   *Link:* [Ed25519 Publication / DOI: 10.1007/s13389-012-0027-1](https://doi.org/10.1007/s13389-012-0027-1)  
   *Relevance:* Serves as the control group baseline against which all lattice overheads are measured.

---

## 3. Algorithmic Deep Dive: Mathematical Foundations

```
========================================================================================
                                CRYPTOGRAPHIC TAXONOMY
========================================================================================
        Classical Primitive                      Lattice-Based Post-Quantum Primitives
         (Discrete Logarithm)                      (Shortest Vector / Learning With Errors)
                 │                                        │
           [Ed25519]                         ┌────────────┴─────────────┐
        Curve25519 group                     │                          │
      Pk: 32 B | Sig: 64 B             [Falcon-512]                [ML-DSA-44]
                                        (FIPS 206)                  (FIPS 204)
                                       NTRU Lattice                 Module-LWE
                                   Fast-Fourier Sampling      Fiat-Shamir with Aborts
                                   Pk: 897 B | Sig: ~666 B    Pk: 1312 B | Sig: 2420 B
========================================================================================
```

### 3.1 Falcon-512 (FN-DSA, FIPS 206)
* **Mathematical Setting:** Operates over the cyclotomic ring $\mathcal{R} = \mathbb{Z}[x] / (\phi_n(x))$ where $\phi_n(x) = x^n + 1$ and $n = 512$.
* **Underlying Hardness:** Short Integer Solution (SIS) problem over NTRU lattices.
* **Mechanism:** Employs the **"Hash-and-Sign"** paradigm using Fast Fourier Orthogonalization over the tree of polynomials (the Falcon tree).
* **Key Generation:** Generates short polynomials $f, g, F, G \in \mathcal{R}$ satisfying the NTRU equation:

  $$
  fG - gF = q \pmod{x^n + 1}, \quad \text{where } q = 12289
  $$

  The public key is computed as $h = g \cdot f^{-1} \pmod q$.
* **Verification:** Checks that the signature polynomial vector $(s_1, s_2)$ satisfies $s_1 + s_2 h = c \pmod q$ and that the Euclidean norm $\|(s_1, s_2)\|$ falls below a precomputed threshold $\beta$.
* **Systems Trade-offs:**
  * **Pros:** Smallest combined signature + public key footprint among all NIST standards ($\approx 1.56\text{ KB}$ total). Extremely fast verification.
  * **Cons:** Key generation and signing require double-precision floating-point emulation with rigorous constant-time Gaussian sampling (Fast Fourier Sampling) to prevent side-channel timing leaks. In a consensus engine, non-deterministic floating-point math across different hardware architectures can break state consensus; thus, integer-only fixed-point verification emulation must be strictly enforced.

### 3.2 ML-DSA-44 (CRYSTALS-Dilithium, FIPS 204)
* **Mathematical Setting:** Operates over polynomial rings $\mathcal{R}_q = \mathbb{Z}_q[x] / (x^{256} + 1)$ with modulus $q = 8380417 = 2^{23} - 2^{13} + 1$.
* **Underlying Hardness:** Module Learning With Errors (M-LWE) and Module Short Integer Solution (M-SIS) problems over matrices of polynomials of dimension $k \times \ell$ ($4 \times 4$ for ML-DSA-44).
* **Mechanism:** Employs the **"Fiat-Shamir with Aborts"** framework (Lyubashevsky paradigm). It avoids Gaussian sampling entirely, relying instead on uniform sampling across bounded intervals.
* **Verification:** Matrix-vector polynomial multiplication:

  $$
  w_1 = \text{HighBits}_q(\mathbf{A}\mathbf{z} - c\mathbf{t}_1 \cdot 2^d)
  $$

  Verifies that the $L_\infty$ norm of vector $\mathbf{z}$ is bounded by $\gamma_1 - \beta$ and that $c = H(\mu \,\|\, w_1)$.
* **Systems Trade-offs:**
  * **Pros:** Pure integer arithmetic ($32\text{-bit}$ modular operations). No floating-point dependencies. Extremely robust to hardware variance, easy to vectorize using AVX2/AVX-512 SIMD, and mathematically clean.
  * **Cons:** Substantially larger cryptographic payload ($1,312\text{ bytes}$ public key, $2,420\text{ bytes}$ signature $\rightarrow 3.73\text{ KB}$ per transaction), creating severe pressure on network buffers and memory caches.

---

## 4. Hardware Budget & Constraint Validation

All experiments and node deployments execute deterministically on local bare-metal hardware:

* **CPU (Intel Core i5-12th Gen Alder Lake):**
  * **Instruction Sets:** Hardware AVX2, BMI2, and SHA-NI natively accelerate Number Theoretic Transforms (NTT), polynomial multiplications, and BLAKE3/SHAKE hashing.
  * **Hybrid Architecture:** Features Performance Cores (P-cores) and Efficient Cores (E-cores). This lets us profile worker-thread affinity, assessing throughput differences when batch verification runs on P-cores versus low-power E-cores.
* **RAM (16 GB DDR4/DDR5):**
  * Multi-node local devnet deployments (4 to 8 nodes) run concurrently with an enforced RSS memory cap of $\le 250\text{ MB}$ per node ($\le 2\text{ GB}$ total testnet RAM footprint).
  * State storage tests utilize an embedded key-value engine (`sled`) with an explicit $512\text{ MB}$ write buffer limit.
* **Integrated Graphics:**
  * Post-quantum lattice verification and consensus gossiping are pure integer CPU workloads; no GPU/VRAM hardware is required, ensuring maximal accessibility and reproducibility.

---

## 5. Architectural Innovations & Technical Specifications

```
========================================================================================
                          TRANSACTION PIPELINE DECOUPLING
========================================================================================

    P2P Network (Fast Path)                      Validation Layer (Heavy Path)
    -----------------------                      ----------------------------
    [ TxIntent Gossip ]                          [ Batch Verifier Engine ]
    • Nonce: u64                                 • Worker Thread 1 (Rayon)
    • Sender: [u8; 20]                           • Worker Thread 2 (Rayon)
    • Recipient: [u8; 20]                        • Worker Thread 3 (Rayon)
    • Amount: u64                                • Worker Thread 4 (Rayon)
    • Fee: u64                                                │
         │                                                    ▼
         ▼                                      [ Merkle Root Commitment ]
    Intent Root Hash                              Witness Commitment Root
         │                                                    │
         └───────────────────────┬────────────────────────────┘
                                 │
                                 ▼
                         [ Block Header ]
                         • Prev Hash
                         • Height
                         • Intent Merkle Root
                         • Witness Merkle Root  <── (Prunable after Epoch k)
========================================================================================
```

### 5.1 Decoupled Segregated Witness Architecture

To insulate the ledger from lattice signature bloat, transaction state mutations are decoupled from authentication proofs:

```rust
// crates/types/src/transaction.rs

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TxIntent {
    pub nonce: u64,
    pub sender_address: [u8; 20],
    pub recipient_address: [u8; 20],
    pub amount: u64,
    pub fee: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum WitnessProof {
    Ed25519 {
        public_key: [u8; 32],
        signature: [u8; 64],
    },
    Falcon512 {
        public_key: Vec<u8>,   // 897 bytes
        signature: Vec<u8>,    // ~666 bytes
    },
    MlDsa44 {
        public_key: Vec<u8>,   // 1312 bytes
        signature: Vec<u8>,    // 2420 bytes
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transaction {
    pub intent: TxIntent,
    pub witness: WitnessProof,
}

impl Transaction {
    /// Produces a deterministic BLAKE3 commitment hash for the intent
    pub fn intent_hash(&self) -> [u8; 32] {
        use blake3::Hasher;
        let mut hasher = Hasher::new();
        hasher.update(&bincode::serialize(&self.intent).unwrap());
        *hasher.finalize().as_bytes()
    }
}
```

### 5.2 Research Novelty: Epoch-Based Witness Pruning with Vector Commitments

* **The Problem:** In an ML-DSA-44 ledger, 1 million transactions consume $\approx 3.73\text{ GB}$ of disk space for signatures alone. Validating nodes run out of disk space rapidly, driving centralization.
* **The Optimization:**
  * Block headers commit to two separate Merkle trees: the **Intent Merkle Root** and the **Witness Merkle Root**.
  * Validating full nodes verify the witnesses during block proposal and initial gossiping.
  * Once a block is buried under an epoch threshold $k$ (e.g., $k = 1,000$ block confirmations), validating nodes delete the raw `WitnessProof` payload from persistent storage, retaining only the $32\text{-byte}$ witness root commitment.
  * Archival nodes preserve the full witness history, while light nodes and validating nodes retain a constant-growth state footprint.
* **Empirical Validation:** We measure the storage growth rate ($\text{MB}/\text{block}$) and node sync speed across pruned vs. unpruned configurations.

---

## 6. Workspace Architecture

The workspace is organized into modular crates:

```
qr-dlt/
├── Cargo.toml                  # Cargo workspace manifest
├── benches/
│   ├── crypto_bench.rs         # Microbenchmarks: Ed25519 vs Falcon vs ML-DSA
│   └── block_validation.rs     # Batch verification scaling (1 to 10,000 txs)
├── crates/
│   ├── crypto/                 # Agnostic trait abstractions & SIMD implementations
│   ├── types/                  # Block, Header, Intent, and Witness data models
│   ├── storage/                # State database, trie commitments, sled KV interface
│   ├── mempool/                # Admission filtering & Rayon parallel verifier
│   ├── consensus/              # Deterministic PoA consensus engine
│   ├── network/                # Async Tokio P2P gossip engine
│   └── node/                   # CLI executable, metrics exporter, node runtime
└── scripts/
    ├── run_local_cluster.sh    # Spawns a 4-node local testnet
    ├── simulate_latency.sh     # Injects WAN delays via Linux 'tc netem'
    └── generate_flamegraph.sh  # Generates CPU cache and flamegraph profiles
```

---

## 7. Execution Roadmap (16 Weeks)

```
[Weeks 1-3]  Phase 1: Cryptographic Abstraction & Microbenchmarking
[Weeks 4-7]  Phase 2: Types, Segregated Transaction Engine & State DB
[Weeks 8-11] Phase 3: Consensus, P2P Gossip & Multi-Node Local Devnet
[Weeks 12-14] Phase 4: Bottleneck Isolation, Novel Optimization & Experiments
[Weeks 15-16] Phase 5: Empirical Analysis, Manuscript Writing & Artifact Packaging
```

### Phase 1: Cryptographic Abstraction & Microbenchmarks (Weeks 1–3)
* [ ] Implement generic `CryptoSigner` and `CryptoVerifier` traits in `crates/crypto`.
* [ ] Integrate baseline `ed25519-dalek`, `pqcrypto-falcon`, and `pqcrypto-dilithium`.
* [ ] Configure Criterion microbenchmarks evaluating KeyGen, Sign, and Verify times ($\mu s$ and cycles).
* [ ] Validate constant-time execution and ensure deterministic byte serialization across all targets.

### Phase 2: Core Ledger Engine & State Storage (Weeks 4–7)
* [ ] Implement `TxIntent`, `WitnessProof`, and dual-root `Block` models in `crates/types`.
* [ ] Build BLAKE3 Merkle tree computation for transaction intents and witness roots.
* [ ] Implement account state transitions, nonces, and balance checks in `crates/storage` with `sled`.
* [ ] Build the Rayon-based parallel batch verification queue in `crates/mempool`.
* [ ] Profile batch verification scaling across $1,000$, $5,000$, and $10,000$ transactions.

### Phase 3: Consensus & Multi-Node Local Testnet (Weeks 8–11)
* [ ] Build a deterministic round-robin Proof-of-Authority (PoA) consensus engine in `crates/consensus`.
* [ ] Build an asynchronous TCP/Tokio gossip layer for broadcasting transaction intents and blocks.
* [ ] Write `scripts/run_local_cluster.sh` to spin up 4 local nodes on loopback (`127.0.0.1:8001..8004`).
* [ ] Use `scripts/simulate_latency.sh` (`tc netem`) to simulate realistic WAN conditions ($50\text{ ms}$, $100\text{ ms}$, $200\text{ ms}$, $0.5\%$ loss).
* [ ] Measure propagation latency comparing Ed25519, Falcon-512, and ML-DSA-44 blocks.

### Phase 4: Optimization Implementation & Profiling (Weeks 12–14)
* [ ] Implement the Epoch-Based Witness Pruning protocol in `crates/storage`.
* [ ] Profile CPU memory stalls and cache invalidations using `cargo flamegraph` and Linux `perf`.
* [ ] Run stress tests across $100,000$ consecutive transactions under varying WAN latency profiles.
* [ ] Record comparative metrics: TPS, disk usage growth over time, and block orphan/reorganization rates.

### Phase 5: Academic Paper & Final Deliverables (Weeks 15–16)
* [ ] Process raw Criterion and testnet logs into publication-ready graphs via Python (`matplotlib`/`seaborn`).
* [ ] Author an academic manuscript formatted for IEEE/ACM conference tracks:
  1. Introduction & Quantum Threat Formulation.
  2. Background on Lattice Signatures (NTRU vs. Module-LWE).
  3. Systems Architecture & Segregated Witness Implementation.
  4. Epoch-Based Witness Pruning Protocol (Formal Algorithm & Proof).
  5. Empirical Evaluation & Comparative Benchmarks.
  6. Related Works & Conclusion.
* [ ] Package a clean, reproducible GitHub repository with CI pipelines and one-command replication scripts.

---

## 8. Role Division & Collaborative Workflow

| Domain | **Bashar Khan** | **Zaheer Khan** |
| :--- | :--- | :--- |
| **Cryptographic Primitives** | AVX2 SIMD checks, Criterion benchmarking harness, Falcon-512 integration. | ML-DSA-44 integration, key-encoding bounds checking, address hashing logic. |
| **System Engine** | `rayon` parallel batch verifier, state storage transitions (`sled`), memory profiling. | Transaction serialization, SegWit decoupling, mempool admission filters. |
| **Networking & Devnet** | Network latency injection (`tc netem`), cluster orchestration scripts, metrics collector. | P2P gossip layer, block header broadcasting, synchronization logic. |
| **Academic Manuscript** | Abstract, System Architecture, Experimental Methodology, Performance Graphs. | Literature Review, Mathematical Background, Threat Modeling, Discussion. |

---

## 9. Verification & Development Commands

```bash
# Verify Rust toolchain and AVX2 capabilities
rustup default stable
lscpu | grep -i avx2

# Run cryptographic microbenchmarks with native SIMD optimizations
RUSTFLAGS="-C target-cpu=native" cargo bench --bench crypto_bench

# Profile block validation under load with flamegraph
cargo install flamegraph
cargo flamegraph --bin qr-dlt-node -- --validate-sample-block

# Execute WAN latency emulation (Linux tc netem)
sudo ./scripts/simulate_latency.sh --delay 100ms --loss 0.5%

# Spawn local 4-node devnet
chmod +x scripts/run_local_cluster.sh
./scripts/run_local_cluster.sh
```

---

## 10. Risk Management & Fallback Matrix

| Identified Risk | Impact | Mitigation Strategy |
| :--- | :--- | :--- |
| **Falcon non-deterministic sampling across nodes** | High (Consensus fork) | Enforce constant-time, deterministic integer emulation wrappers (`pqcrypto-falcon` / Thomas Pornin reference routines). Prohibit platform floating-point calls in consensus code. |
| **Excessive block propagation delay due to PQC key size** | Medium (Elevated orphan rates) | Apply Segregated Witness immediately: broadcast only compact `TxIntent` during initial gossip, pulling witness payloads during block assembly. |
| **Research novelty deemed incremental by reviewers** | Low-Medium (Submission pivot) | Frame the contribution as a comprehensive systems benchmarking and architectural evaluation of lattice primitives in next-generation decentralized ledgers; submit to systems/applied cryptography tracks (e.g., IEEE Access, MDPI Applied Sciences, or specialized PQC workshops). |
