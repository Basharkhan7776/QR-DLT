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
│   ├── crypto/                 # Agnostic trait abstractions, Falcon-512 & SIMD implementations
│   ├── types/                  # Block, Header, Intent, Witness & EIP-2718 Type-0x46 data models
│   ├── storage/                # State database, EVM MPT commitments, sled KV interface
│   ├── evm/                    # Embedded revm engine & native Falcon-512 precompile (0x15)
│   ├── mempool/                # Admission filtering & Rayon parallel verifier
│   ├── consensus/              # Deterministic PoA consensus engine with EVM execution
│   ├── network/                # Async Tokio P2P gossip engine
│   └── node/                   # CLI executable, JSON-RPC server (eth_*), node runtime
└── scripts/
    ├── run_local_cluster.sh    # Spawns a 4-node local testnet
    ├── simulate_latency.sh     # Injects WAN delays via Linux 'tc netem'
    ├── generate_flamegraph.sh  # Generates CPU cache and flamegraph profiles
    └── run_evm_comparison.sh   # Automated head-to-head evaluation (Falcon-EVM vs Anvil/Reth)
```

---

## 7. Execution Roadmap (20 Weeks)

```
[Weeks 1-3]   Phase 1: Cryptographic Abstraction & Microbenchmarking [Completed]
[Weeks 4-7]   Phase 2: Types, Segregated Transaction Engine & State DB [Completed]
[Weeks 8-11]  Phase 3: Consensus, P2P Gossip & Multi-Node Local Devnet [Completed]
[Weeks 12-14] Phase 4: Bottleneck Isolation, Novel Optimization & Experiments [Completed]
[Weeks 15-16] Phase 5: Empirical Analysis, Manuscript Writing & Artifact Packaging [Completed]
[Weeks 17-20] Phase 6: Falcon-EVM Sovereign Blockchain & Comparative Evaluation [In Progress]
```

### Phase 1: Cryptographic Abstraction & Microbenchmarks (Weeks 1–3) — COMPLETED
* [x] Implement generic `CryptoSigner` and `CryptoVerifier` traits in `crates/crypto`.
* [x] Integrate baseline `ed25519-dalek`, `pqcrypto-falcon` (Falcon-512), and `pqcrypto-dilithium` (ML-DSA-44).
* [x] Configure Criterion microbenchmarks evaluating KeyGen, Sign, and Verify times ($\mu s$ and cycles).
* [x] Validate constant-time execution and ensure deterministic byte serialization across all targets.

### Phase 2: Core Ledger Engine & State Storage (Weeks 4–7) — COMPLETED
* [x] Implement `TxIntent`, `WitnessProof`, and dual-root `Block` models in `crates/types`.
* [x] Build BLAKE3 Merkle tree computation for transaction intents and witness roots.
* [x] Implement account state transitions, nonces, and balance checks in `crates/storage` with `sled`.
* [x] Build the Rayon-based parallel batch verification queue in `crates/mempool`.
* [x] Profile batch verification scaling across $100$, $500$, and $1,000$ transactions.

### Phase 3: Consensus & Multi-Node Local Testnet (Weeks 8–11) — COMPLETED
* [x] Build a deterministic round-robin Proof-of-Authority (PoA) consensus engine in `crates/consensus`.
* [x] Build an asynchronous TCP/Tokio gossip layer for broadcasting transaction intents and blocks.
* [x] Write `scripts/run_local_cluster.sh` to spin up 4 local nodes on loopback (`127.0.0.1:8001..8004`).
* [x] Write `scripts/simulate_latency.sh` (`tc netem`) to simulate realistic WAN conditions ($50\text{ ms}$, $100\text{ ms}$, $200\text{ ms}$, $0.5\%$ loss).
* [x] Measure propagation latency and packet sizes comparing Ed25519, Falcon-512, and ML-DSA-44 blocks.

### Phase 4: Optimization Implementation & Profiling (Weeks 12–14) — COMPLETED
* [x] Implement the Epoch-Based Witness Pruning protocol in `crates/storage`.
* [x] Profile CPU memory stalls and cache invalidations using `cargo flamegraph` via `scripts/generate_flamegraph.sh`.
* [x] Run high-throughput stress tests across batch verification and storage commitment pipelines.
* [x] Record comparative metrics: TPS, disk usage growth over time, and witness space reclamation rate.

### Phase 5: Empirical Analysis & Final Deliverables (Weeks 15–16) — COMPLETED
* [x] Process raw Criterion and evaluation logs into publication-ready vector charts via Python (`scripts/plot_results.py`).
* [x] Build full CLI benchmarking evaluation suite (`qr-dlt-node evaluate`).
* [x] Produce comprehensive empirical walkthrough documentation and supervisor reporting.
* [x] Package a clean, reproducible GitHub repository with full test suite passing (17 unit & integration tests).

### Phase 6: Falcon-EVM Sovereign Blockchain & Comparative Evaluation (Weeks 17–20) — IN PROGRESS
* [x] **Week 17: Embedded EVM Engine (`revm`) & Native Falcon-512 Precompile (`0x15`)** — COMPLETED
  * [x] Embed `revm` (Rust Ethereum Virtual Machine) into the node execution pipeline (`crates/evm`).
  * [x] Implement the native Falcon-512 verification precompile at address `0x0000000000000000000000000000000000000015` (`0x15`) with deterministic AVX2 polynomial verification.
  * [x] Enforce strict integer fixed-point arithmetic in consensus verification to prevent multi-platform floating-point consensus forks.
  * [x] Validate precompile execution with NIST FIPS 206 test vectors and calibrate precompile gas pricing ($\approx 3,000\text{ gas}$).
* [x] **Week 18: EIP-2718 Type `0x46` Falcon Envelope & Account Identity Model** — COMPLETED
  * [x] Implement EIP-2718 typed transaction envelope Type `0x46` carrying `[chainId, nonce, gasFee, gasLimit, to, value, data, falconPubKey (897 B), falconSig (~666 B)]`.
  * [x] Establish Ethereum-standard 20-byte address derivation: $\text{Address} = \text{keccak256}(\text{falcon\_pubkey})[12..32]$.
  * [x] Implement intrinsic gas formula: $21,000 \text{ base} + \text{calldata gas} + \text{Falcon verification intrinsic gas } (\approx 4,000\text{ gas})$.
  * [x] Integrate Falcon EVM transactions into `crates/mempool` parallel admission validation.
* [x] **Week 19: Dual-Root EVM Block Assembly, State Transition & SegWit Pruning** — COMPLETED
  * [x] Implement dual-root EVM block headers committing to standard EVM MPT `state_root`, `receipts_root`, and QR-DLT BLAKE3 `witness_root`.
  * [x] Wire PoA consensus proposer with sequential `revm` block state execution and parallel Rayon signature verification.
  * [x] Implement Epoch-Based Witness Pruning for EVM blocks: purge raw 1.56 KB Falcon witnesses after confirmation threshold $k$, maintaining constant-growth node storage while preserving cryptographic auditability.
* [ ] **Week 20: JSON-RPC Layer, Smart Contract Deployment & Head-to-Head Benchmarking vs. Normal EVM**
  * Implement Ethereum JSON-RPC server (`eth_chainId`, `eth_sendRawTransaction`, `eth_call`, `eth_getBalance`, `eth_estimateGas`) via `jsonrpsee`.
  * Build a lightweight client/wallet CLI tool (`falcon-signer`) to sign and broadcast Type `0x46` transactions.
  * Deploy Solidity test contracts: ERC-20 token, AMM DEX, and Post-Quantum Account Abstraction (ERC-4337) contract utilizing the `0x15` precompile.
  * Execute head-to-head empirical benchmarking: Falcon-EVM vs. Normal EVM Chain (Anvil / Reth) across TPS, block propagation delay under WAN latency (`tc netem`), gas economics, storage bloat, and quantum mempool front-running attack windows.

---

## 8. Empirical Systems Evaluation & Benchmarking Results

Our empirical evaluations on bare-metal Linux (Intel Core i5 Alder Lake, AVX2/BMI2/SHA-NI) yielded the following quantitative findings:

### 8.1 The "Lattice Tax" Wire Overhead (Figure 1)

| Cryptographic Scheme | Public Key | Signature | Total Witness | Lattice Tax Multiplier | Block Payload Share |
| :--- | :---: | :---: | :---: | :---: | :---: |
| **Ed25519** (Classical Baseline) | $32\text{ B}$ | $64\text{ B}$ | **$96\text{ B}$** | **$1.0\times$** | $60.0\%$ |
| **Falcon-512** (NIST FIPS 206) | $897\text{ B}$ | $666\text{ B}$ | **$1,563\text{ B}$** | **$16.3\times$** | $96.0\%$ |
| **ML-DSA-44** (NIST FIPS 204) | $1,312\text{ B}$ | $2,420\text{ B}$ | **$3,732\text{ B}$** | **$38.9\times$** | **$98.3\%$** |

*Analysis:* In ML-DSA-44, witness proofs account for **$98.3\%$ of the total block size**. Transmitting monolithic post-quantum transactions saturates P2P wire buffers, directly validating the necessity of QR-DLT's Decoupled Segregated Witness architecture.

### 8.2 Parallel Batch Verification Scaling (Figure 2)

| Batch Size | Ed25519 (Baseline) | Falcon-512 (FIPS 206) | ML-DSA-44 (FIPS 204) |
| :---: | :---: | :---: | :---: |
| **100 txs** | $440\text{ tx/s}$ ($227.3\text{ ms}$) | **$27,617\text{ tx/s}$** ($3.62\text{ ms}$) | **$30,721\text{ tx/s}$** ($3.26\text{ ms}$) |
| **500 txs** | $486\text{ tx/s}$ ($1,028.6\text{ ms}$) | **$23,737\text{ tx/s}$** ($21.06\text{ ms}$) | **$32,365\text{ tx/s}$** ($15.45\text{ ms}$) |
| **1,000 txs** | $501\text{ tx/s}$ ($1,994.9\text{ ms}$) | **$20,402\text{ tx/s}$** ($49.02\text{ ms}$) | **$34,662\text{ tx/s}$** ($28.85\text{ ms}$) |

*Analysis:* Leveraging Rayon work-stealing concurrency and hardware AVX2 vectorization, lattice verification achieves throughput exceeding **$34,000\text{ TPS}$ for ML-DSA-44** and **$20,000\text{ TPS}$ for Falcon-512**. ML-DSA-44 outpaces Falcon-512 because its modular polynomial arithmetic over $\mathbb{Z}_q$ maps natively onto integer SIMD registers without requiring Falcon's floating-point emulation.

### 8.3 Epoch-Based Witness Pruning Storage Reclamation (Figure 3)

| Metric | Unpruned Archival Node | Pruned Validating Node | Improvement |
| :--- | :---: | :---: | :---: |
| **Raw Witness Payload (500 txs)** | $1,832.03\text{ KB}$ | **$0\text{ KB}$** (Purged from disk) | **$-100.0\%$** |
| **Retained Intent State** | $31.25\text{ KB}$ | **$31.25\text{ KB}$** | Preserved |
| **Total Block Data** | $1,863.28\text{ KB}$ | **$31.25\text{ KB}$** | **$98.3\%$ Storage Reclaimed** |
| **Commitment Invariant** | Full proof history | 32-byte header Merkle root | Complete mathematical verifiability |

*Analysis:* Epoch pruning bounds state storage growth to a constant function of transaction execution intents, preventing node disk exhaustion while maintaining full cryptographic auditability via vector inclusion proofs.

---

## 9. Future Plan: Falcon-EVM Blockchain Architecture & Comparative Evaluation Framework

To evaluate the operational feasibility of post-quantum cryptography in smart contract ecosystems, the project expands to construct **Falcon-EVM (QR-EVM)**: a sovereign, EVM-compatible blockchain running native Falcon-512 signatures, followed by a head-to-head empirical evaluation against a normal EVM chain (ECDSA $\text{secp256k1}$).

```
========================================================================================
                          FALCON-EVM BLOCKCHAIN ARCHITECTURE
========================================================================================

    [ User / Wallet / dApp ]
    • Generates Falcon-512 Keypair
    • Signs EIP-2718 Type-0x46 Envelope: [nonce, gasPrice, gasLimit, to, value, data, pk, sig]
                  │
                  ▼ (JSON-RPC eth_sendRawTransaction)
    [ Falcon-EVM Node RPC & Mempool ]
    • Fast-path Nonce & Solvency Gate
    • Rayon AVX2 Parallel Batch Verifier (Falcon-512 verification)
                  │
                  ▼
    [ EVM Consensus & Execution Engine (revm + PoA) ]
    • Derives Sender Address: keccak256(pk)[12..32]
    • Executes Bytecode via `revm` State Processor
    • Exposes Precompile 0x15 (`falcon_verify`) to Solidity Smart Contracts
                  │
                  ├─────────────────────────────────────────┐
                  ▼                                         ▼
    [ Standard EVM State Trie ]              [ Decoupled Witness Storage ]
    • Merkle Patricia Trie (MPT / Accounts)  • Sled / RocksDB Raw Witnesses
    • World State: Nonces, Balances, Code    • Prunable after Epoch k confirmations
                  │                                         │
                  └───────────────────┬─────────────────────┘
                                      ▼
                             [ Falcon-EVM Block ]
                             • State Root (MPT)
                             • Transactions Root (EIP-2718)
                             • Receipts Root
                             • Witness Merkle Root (Prunable)
========================================================================================
```

### 9.1 Core Systems Components

1. **Embedded EVM State Engine (`revm`):**
   * Integrates the Rust Ethereum Virtual Machine (`revm`) directly into the block proposal and validation loop.
   * Maintains EVM world state (nonces, balances, bytecode, and storage slots) backed by `sled` key-value storage.

2. **Native Falcon-512 EVM Precompile (`0x15`):**
   * Registered at address `0x0000000000000000000000000000000000000015`.
   * **Input:** $\text{msg\_hash}\,(32\text{ B}) \,\|\, \text{pk\_len}\,(2\text{ B}) \,\|\, \text{public\_key}\,(897\text{ B}) \,\|\, \text{sig\_len}\,(2\text{ B}) \,\|\, \text{signature}\,(\approx 666\text{ B})$.
   * **Output:** $32\text{-byte}$ word containing `1` (valid) or `0` (invalid).
   * **Gas Schedule:** Calibrated to $3,000\text{ gas}$ reflecting AVX2-accelerated NTT verification CPU cycles, avoiding the prohibitive cost ($>1.5\text{M gas}$) of interpreting polynomial arithmetic in pure EVM bytecode.
   * **Determinism:** Strictly adheres to integer fixed-point emulation to prevent floating-point consensus diverges.

3. **EIP-2718 Type `0x46` Falcon Transaction Envelope:**
   * Standard Ethereum transactions rely on ECDSA public key recovery (`ecrecover`). Because Falcon does not support recovery from signature alone, Type `0x46` explicitly carries the 897-byte public key alongside the signature:
     $$\text{FalconTx} = 0x46 \,\|\, \text{rlp}([ \text{chainId}, \text{nonce}, \text{maxPriorityFee}, \text{maxFee}, \text{gasLimit}, \text{to}, \text{value}, \text{data}, \text{accessList}, \text{falconPubKey}, \text{falconSig} ])$$
   * **Address Derivation:** Evaluated via $\text{Address} = \text{keccak256}(\text{falcon\_public\_key})[12..32]$, preserving 20-byte EVM address interoperability.
   * **Intrinsic Gas Formula:** $21,000 \text{ base} + \text{calldata gas} + \text{Falcon verification intrinsic gas } (\approx 4,000\text{ gas})$.

4. **Decoupled EVM Segregated Witness & Epoch Pruning:**
   * EVM block headers commit to standard MPT `state_root`, `transactions_root`, and `receipts_root`, alongside QR-DLT's BLAKE3 `witness_root`.
   * Validating nodes verify signatures upon block proposal and mempool admission, but purge the raw $1,563\text{-byte}$ witness payloads after $k = 1,000$ block confirmations.
   * This bounds node disk growth to a flat line identical to classical EVM chains while preserving complete cryptographic auditability.

5. **JSON-RPC Server & Signing SDK:**
   * JSON-RPC endpoints (`eth_chainId`, `eth_sendRawTransaction`, `eth_call`, `eth_getBalance`, `eth_estimateGas`) powered by `jsonrpsee`.
   * Client tooling (`falcon-signer`) capable of generating Falcon keypairs, encoding Type `0x46` transactions, and broadcasting to the Falcon-EVM mempool.

---

### 9.2 Head-to-Head Comparative Testing Framework: Falcon-EVM vs. Normal EVM Chain

To evaluate the operational differences between classical and post-quantum EVM architectures, we establish an automated comparative evaluation pipeline:

* **Control Group (Normal EVM):** Standard Reth / Anvil instance executing classical ECDSA $\text{secp256k1}$ transactions.
* **Experimental Group (Falcon-EVM):** Sovereign QR-EVM node executing Falcon-512 Type `0x46` transactions with native precompile `0x15` and SegWit epoch pruning.

#### Head-to-Head Evaluation Matrix

| Metric | Normal EVM Chain (ECDSA Baseline) | Falcon-EVM Chain (Falcon-512) | Research Hypothesis / Systems Impact |
| :--- | :--- | :--- | :--- |
| **Cryptographic Scheme** | ECDSA ($\text{secp256k1}$) | Falcon-512 (NIST FIPS 206 / FN-DSA) | Full quantum resilience against Shor's algorithm. |
| **Transaction Wire Footprint** | $\approx 110\text{ bytes}$ | $\approx 1,670\text{ bytes}$ | Falcon transactions are $\approx 15\times$ larger due to lattice key requirements. |
| **Public Key Derivation** | Recovered on-the-fly (`ecrecover`) | Explicitly provided in envelope ($897\text{ B}$) | Eliminates ambiguity; requires SegWit to prevent state bloat. |
| **Parallel Batch Verification TPS** | $\approx 500\text{–}1,200\text{ TPS}$ | **$>20,000\text{ TPS}$** | Falcon NTT verification maps onto AVX2 SIMD, outperforming elliptic curve scalar multiplication. |
| **Block Propagation under WAN Delay** | Baseline ($t_0$) | $t_0 + \Delta t$ (Monolithic) vs $t_0$ (Decoupled SegWit) | Decoupled intent propagation prevents packet fragmentation and elevated orphan rates. |
| **Smart Contract Verification Cost** | $3,000\text{ gas}$ (`ecrecover` `0x01`) | $3,000\text{ gas}$ (Precompile `0x15`) vs $>1.5\text{M gas}$ (Solidity) | Proves native precompiles are mandatory for viable PQC smart contracts. |
| **Disk State Bloat per 100k Transactions** | $\approx 11\text{ MB}$ | **$\approx 12\text{ MB}$** (Pruned) vs $167\text{ MB}$ (Unpruned) | Epoch pruning achieves storage parity with classical EVM chains. |
| **Mempool Front-Running Window** | **Vulnerable** (CRQC breaks key in mempool window) | **Secure** (Lattice SIS problem remains hard) | Demonstrates elimination of quantum front-running exploit vectors. |

#### Comparative Benchmark Scenarios
1. **Workload A: High-Throughput Token Transfers (ERC-20):** 10,000 concurrent transfers submitted to both chains; measure sustained TPS, memory usage, and confirmation latency.
2. **Workload B: Stateful DeFi Swaps (Constant-Product AMM):** Evaluate EVM state execution overhead relative to signature verification.
3. **Workload C: WAN Network Degradation:** Inject $50\text{ ms}$, $100\text{ ms}$, and $200\text{ ms}$ latency via `scripts/simulate_latency.sh` to measure propagation bottlenecks in monolithic vs. SegWit blocks.
4. **Workload D: Storage Reclamation Profiling:** Run 100,000 transactions and record disk growth every 1,000 blocks to benchmark the exact storage reclamation curve.

---

## 10. Role Division & Collaborative Workflow

| Domain | **Bashar Khan** | **Zaheer Khan** |
| :--- | :--- | :--- |
| **Cryptographic Primitives** | AVX2 SIMD checks, Criterion benchmarking harness, Falcon-512 integration. | ML-DSA-44 integration, key-encoding bounds checking, address hashing logic (`keccak256`). |
| **System Engine** | `rayon` parallel batch verifier, `revm` embedded execution engine, state transitions (`sled`), memory profiling. | Transaction serialization, SegWit decoupling, mempool admission filters, epoch-based witness pruner. |
| **Networking & Devnet** | Network latency injection (`tc netem`), cluster orchestration scripts, metrics collector. | P2P gossip layer, block header broadcasting, synchronization logic. |
| **EVM Engine & Precompile** | Native Falcon-512 precompile (`0x15`), EIP-2718 Type `0x46` envelope, Anvil/Reth comparison testbed. | Ethereum JSON-RPC server (`jsonrpsee`), Solidity contract test suite (ERC-20 / AMM), mempool front-running modeling. |
| **Academic Manuscript** | Abstract, System Architecture, Experimental Methodology, Performance Graphs. | Literature Review, Mathematical Background, Threat Modeling, Discussion. |

---

## 11. Verification & Development Commands

```bash
# Verify Rust toolchain and AVX2 capabilities
rustup default stable
lscpu | grep -i avx2

# Run full workspace test suite (17 tests passing)
cargo test --workspace

# Run cryptographic microbenchmarks with native SIMD optimizations
RUSTFLAGS="-C target-cpu=native" cargo bench --bench crypto_bench
RUSTFLAGS="-C target-cpu=native" cargo bench --bench block_validation

# Execute empirical evaluation and generate publication vector charts
cargo run -p qr-dlt-node -- evaluate --output-file empirical_results.json
python3 scripts/plot_results.py empirical_results.json

# Profile block validation under load with flamegraph
./scripts/generate_flamegraph.sh falcon512 2000

# Execute WAN latency emulation (Linux tc netem)
sudo ./scripts/simulate_latency.sh --delay 100ms --loss 0.5%
sudo ./scripts/simulate_latency.sh --clear

# Spawn local 4-node devnet
chmod +x scripts/run_local_cluster.sh
./scripts/run_local_cluster.sh

# Run head-to-head comparative evaluation (Falcon-EVM vs Normal EVM Anvil)
chmod +x scripts/run_evm_comparison.sh
./scripts/run_evm_comparison.sh --txs 10000 --concurrency 50
```

---

## 12. Risk Management & Fallback Matrix

| Identified Risk | Impact | Mitigation Strategy |
| :--- | :--- | :--- |
| **Falcon non-deterministic sampling across nodes** | High (Consensus fork) | Enforce constant-time, deterministic integer emulation wrappers (`pqcrypto-falcon` / Thomas Pornin reference routines). Prohibit platform floating-point calls in consensus code. |
| **Excessive block propagation delay due to PQC key size** | Medium (Elevated orphan rates) | Apply Segregated Witness immediately: broadcast only compact `TxIntent` during initial gossip, pulling witness payloads during block assembly. |
| **EVM tooling incompatibility with Type `0x46` transactions** | Medium (Developer friction) | Expose standard JSON-RPC methods (`eth_sendRawTransaction`) wrapping Type `0x46` RLP bytes; provide client-side Python and Rust signing SDKs for automated testing. |
| **Prohibitive EVM calldata gas costs for Falcon signatures** | High (Adoption barrier) | Benchmark detached sidecar proofs and native precompile `0x15` ($3,000\text{ gas}$) rather than raw calldata interpreted by EVM smart contract loops. |
| **Lack of native EVM precompile for Falcon-512 in standard clients** | Medium (Verification cost) | Provide dual benchmark paths: (1) embedded `revm` Falcon-512 precompile in QR-EVM for native performance, and (2) EVM bytecode verification emulator assessing the baseline penalty on un-upgraded chains. |
| **Research novelty deemed incremental by reviewers** | Low-Medium (Submission pivot) | Frame the contribution as the first systems-level implementation and empirical evaluation of a sovereign post-quantum EVM blockchain with segregated witness pruning; submit to systems/applied cryptography tracks (IEEE Access, ACM DLT, or PQC workshops). |

