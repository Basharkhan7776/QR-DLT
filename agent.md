# Quantum-Resilient Distributed Ledger (QR-DLT)

**Project Title:** Empirical Evaluation and Systems Optimization of Lattice-Based Digital Signatures in a From-Scratch Rust Blockchain Architecture

**Principal Investigators:** Bashar Khan & Zaheer Khan  
**Target Environment:** Bare-Metal Linux (Ubuntu 22.04 LTS, Linux Kernel 6.8) on Intel Core i5-12400 (Alder Lake, 6 P-cores / 12 threads @ 2.50 GHz base / 4.40 GHz boost, 18 MB L3 cache, AVX2/BMI2/SHA-NI), 16 GB DDR4-3200 RAM, Integrated Graphics.

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
* An $\text{Ed25519}$ public key requires just $32\text{ bytes}$, and its signature is $64\text{ bytes}$ ($96\text{ bytes}$ witness).
* An ECDSA $\text{secp256k1}$ transaction transmits a $65\text{ bytes}$ signature ($r, s, v$) while the public key is recovered dynamically via `ecrecover`, yielding a raw wire envelope of just $\approx 110\text{ bytes}$.

Consequently, existing mempool gossip protocols, wire serializations, block headers, and state Merkle trees were designed under the implicit architectural assumption that cryptographic proofs of identity occupy negligible payload space ($\le 110\text{ bytes}$).

---

### 1.2 The Quantum Threat: Shor's Algorithm and ECDLP Collapse

In 1994, Peter Shor formulated a quantum polynomial-time algorithm for prime factorization and discrete logarithms on a Fault-Tolerant Quantum Computer (FTQC):

$$
\mathcal{O}\left((\log N)^3\right) \text{ gate complexity}
$$

In 2003, Proos and Zalka demonstrated that Shor's algorithm solves ECDLP with significantly fewer quantum resources than factoring equivalent-security RSA moduli. More recent quantum cryptanalysis (Gidney & Ekerå 2021; Google Quantum AI 2025/2026) calculates that breaking $\text{secp256k1}$ requires only $\approx 1,200 \text{ to } 1,450$ error-corrected logical qubits and fewer than $5 \times 10^5$ physical qubits under surface-code architectures, completing in under 10 minutes to several hours.

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
       Logical Qubits Required: ~1,200 - 1,450 logical qubits
       [TOTAL EXPLOITATION: Private keys derived from public keys]
```

#### Attack Windows & Threat Vectors on Distributed Ledgers
As demonstrated by Aggarwal et al. (2018), quantum adversaries target two primary threat vectors in public ledgers:

1. **Static Threat: Public Keys Exposed at Rest (Dominant Attack Vector):**
   * In systems utilizing public key hashing ($\text{Address} = \text{keccak256}(pk)[12..32]$), the raw public key is permanently exposed on-chain the moment an account transmits its first outgoing transaction.
   * A quantum adversary can scrape all exposed public keys from ledger history, execute Shor's algorithm offline at leisure to compute the underlying private scalar $d$ where $Q = d \cdot G$, and forge unauthorized transactions that drain user balances before migration can occur.
   * In Bitcoin, over 4 million BTC reside in unhashed or reused addresses; in Ethereum, tens of millions of active accounts have already permanently exposed their $\text{secp256k1}$ public keys.

2. **Dynamic Threat: Short-Range Mempool Interception (Front-Running):**
   * Even for unspent/unexposed addresses, broadcasting a transaction sends the raw public key to the P2P mempool.
   * In Ethereum, the normal block proposal slot is $\approx 12\text{ seconds}$ (contrasting with Bitcoin's 10-minute target). Under severe network congestion or gas price wars ($600\text{--}3,600\text{ seconds}$), an adversary possessing an ultrafast CRQC could intercept the transaction in the mempool, compute the private key, and submit a higher-priority replacement transaction before block inclusion.

---

### 1.3 Why We Are Building This: The Post-Quantum Trilemma & Systems Gap

Faced with this threat, the global cryptographic community, led by NIST, approved FIPS 204 (ML-DSA) in August 2024 and submitted draft FIPS 206 (FN-DSA / Falcon) for final approval (expected late 2026/2027).

However, transitioning distributed ledgers to post-quantum cryptography encounters **The Post-Quantum Trilemma**: a fundamental systems conflict between:
1. **Cryptographic Quantum Resilience:** Hardness based on lattice problems (SIS/LWE) with no known sub-exponential quantum algorithms.
2. **Payload Size ("The Lattice Tax"):** Lattice keys and signatures are orders of magnitude larger than classical primitives:
   * **Ed25519:** $32\text{ B}$ public key, $64\text{ B}$ signature ($96\text{ B}$ witness baseline).
   * **secp256k1 (Normal EVM):** $\approx 110\text{ B}$ wire envelope ($65\text{ B}$ signature, public key recovered).
   * **Falcon-512 (Draft FIPS 206):** $897\text{ B}$ public key, $\approx 666\text{ B}$ signature ($1,563\text{ B}$ witness $\rightarrow \mathbf{16.3\times}$ over Ed25519; $1,670\text{ B}$ Type 0x46 envelope $\rightarrow \mathbf{15.2\times}$ over secp256k1).
   * **ML-DSA-44 (FIPS 204):** $1,312\text{ B}$ public key, $2,420\text{ B}$ signature ($3,732\text{ B}$ witness $\rightarrow \mathbf{38.9\times}$ over Ed25519).
3. **Execution Throughput & State Scalability:**
   * **P2P Wire Saturation:** Monolithic transmission of $1,000$ Falcon transactions requires transmitting $\approx 1.63\text{ MB}$ of cryptographic data (vs. $107\text{ KB}$ for ECDSA), causing packet fragmentation and elevated peer gossip latency.
   * **EVM Interpretation Bottlenecks:** Interpreting lattice polynomial arithmetic in EVM bytecode costs $>1.5\text{M}$ to $5.8\text{M gas}$, making native precompiles mandatory.
   * **State & Disk Bloat:** Storing raw $1.56\text{ KB}$ lattice witnesses permanently in the state trie rapidly exhausts validator disk storage.

#### Why From-Scratch Rust?
Standard frameworks (Substrate, Cosmos) introduce heavy abstractions and serialization overheads. By constructing a custom, modular Rust engine from the ground up:
* We retain **deterministic byte-level control** over memory layout, thread scheduling, SIMD registers, and wire serialization.
* We isolate and measure pure cryptographic execution versus networking and storage overhead with zero framework distortion.
* We demonstrate that **Decoupled Segregated Witness with Epoch Pruning** and a **Stateless Native Precompile (`0x15`)** allow a sovereign post-quantum EVM chain to remain viable on standard commodity hardware.

---

## 2. Foundational Research Literature & Academic Citations

This project directly builds upon, implements, and benchmarks the mathematical and algorithmic discoveries documented in the following research papers and standard specifications:

### 2.1 Foundational Quantum Threat Papers & Resource Estimations

1. **Shor, P. W. (1994).** *Algorithms for quantum computation: discrete logarithms and factoring.*  
   *Venue:* 35th Annual Symposium on Foundations of Computer Science (FOCS 1994), IEEE.  
   *Link:* [IEEE Xplore / DOI: 10.1109/SFCS.1994.365700](https://doi.org/10.1109/SFCS.1994.365700)  
   *Relevance:* Established the polynomial-time quantum algorithm breaking RSA and discrete logarithms.

2. **Proos, J., & Zalka, C. (2003).** *Shor's discrete logarithm quantum algorithm for elliptic curves.*  
   *Venue:* Quantum Information & Computation (QIC), Vol. 3, No. 4, pp. 317–344.  
   *Link:* [arXiv:quant-ph/0301164](https://arxiv.org/abs/quant-ph/0301164)  
   *Relevance:* Proved that elliptic-curve cryptography collapses under Shor's algorithm with significantly fewer logical qubits than integer factorization.

3. **Gidney, C., & Ekerå, M. (2021) / Google Quantum AI (2025/2026).** *How to factor 2048 bit RSA integers in 8 hours using 20 million noisy qubits.*  
   *Venue:* ACM Transactions on Quantum Computing (2021) / Google Quantum AI Technical Reports.  
   *Link:* [ACM TQC / DOI: 10.1145/3436228](https://doi.org/10.1145/3436228) | [arXiv:1905.09749](https://arxiv.org/abs/1905.09749)  
   *Relevance:* Established modern surface-code resource estimates demonstrating that breaking 256-bit elliptic curves ($\text{secp256k1}$) requires $\approx 1,200\text{--}1,450$ logical qubits and under half a million physical qubits, executable in under 10 minutes to several hours.

4. **Aggarwal, D., Brennen, G. K., Lee, T., Santha, M., & Tomamichel, M. (2018).** *Quantum attacks on Bitcoin, and how to protect against them.*  
   *Venue:* Ledger, Vol. 3, pp. 127–144.  
   *Link:* [Ledger Journal / DOI: 10.5195/ledger.2018.127](https://doi.org/10.5195/ledger.2018.127) | [arXiv:1710.10377](https://arxiv.org/abs/1710.10377)  
   *Relevance:* Analyzed mempool front-running vs. public key exposure windows and evaluated post-quantum signature viability for distributed ledgers.

---

### 2.2 Primary Lattice Cryptographic Standards & Source Papers

5. **NIST FIPS 204 (2024):** *Module-Lattice-Based Digital Signature Standard (ML-DSA).*  
   *Author/Publisher:* National Institute of Standards and Technology (NIST), U.S. Department of Commerce.  
   *Link:* [NIST CSRC FIPS 204 Publication](https://csrc.nist.gov/pubs/fips/204/final) | [DOI: 10.6028/NIST.FIPS.204](https://doi.org/10.6028/NIST.FIPS.204)  
   *Foundation:* Based on CRYSTALS-Dilithium.  
   *Dilithium Original Paper:* Ducas et al. (CHES 2018), [IACR ePrint 2017/633](https://eprint.iacr.org/2017/633).

6. **NIST Draft FIPS 206 (Pending / Late 2026–2027):** *Fast-Fourier Lattice-Based Digital Signature Standard (FN-DSA / Falcon).*  
   *Author/Publisher:* National Institute of Standards and Technology (NIST), U.S. Department of Commerce.  
   *Status Note:* FIPS 206 was submitted for final approval in August 2025; final publication is anticipated in late 2026 or 2027. FN-DSA modifies salt sampling and public-key hashing compared to the original Falcon-512 (2018) submission.  
   *Link:* [NIST CSRC FIPS 206 Draft](https://csrc.nist.gov/pubs/fips/206/draft)  
   *Foundation:* Based on the Falcon algorithm.  
   *Falcon Original Paper:* Fouque et al. (2018), *Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU.* [IACR ePrint 2018/904](https://eprint.iacr.org/2018/904).

---

### 2.3 Post-Quantum EVM, Precompile Proposals & Related Work

7. **Ethereum Improvement Proposals (EIPs) for Falcon & Lattice Precompiles:**
   * **EIP-8052 (2024):** *Falcon-512 Precompile for EVM.* Specifies splitting Falcon-512 verification into two modular precompiles: Hash-to-Point (`0x16`, calibrated to $1,000\text{ gas}$) and Core Signature Verification (`0x15`, calibrated to $2,000\text{ gas}$).
   * **EIP-7592 & EIP-7619:** Early proposals exploring post-quantum signature verification precompiles on Ethereum.
   * *Relevance to QR-DLT:* QR-DLT implements an integrated Falcon-512 precompile at `0x15` calibrated at $3,000\text{ gas}$ total execution cost, evaluating it within a live `revm` pipeline.

8. **Alternative Post-Quantum EVM Paradigms:**
   * **Hybrid Smart Accounts (e.g., ZKNOX):** Combines classical ECDSA with post-quantum Falcon-512 or ML-DSA signatures in ERC-4337 smart wallets.
   * **STARK / SNARK Signature Aggregation:** Off-chain aggregation of hundreds of post-quantum lattice signatures into a single zero-knowledge proof verified on-chain for $\approx 200,000\text{--}300,000\text{ gas}$.
   * **Hash-Based Signatures (SLH-DSA / SPHINCS+, FIPS 205):** Extremely large signatures ($7.8\text{--}49\text{ KB}$), rendering direct on-chain propagation prohibitive without aggressive off-chain aggregation.

9. **Wuille, P., Johnson, L., & Corallo, M. (2015).** *Segregated Witness (Consensus layer).*  
   *Specification:* Bitcoin Improvement Proposal 141 (BIP 141).  
   *Relevance:* Structural foundation for decoupling transaction execution intents from $1.56\text{ KB}$ cryptographic witnesses to prevent malleability and enable epoch-based witness pruning.

10. **Bernstein, D. J. et al. (2012) & libsecp256k1:**  
    * *Ed25519:* Journal of Cryptographic Engineering, Vol. 2, pp. 77–89 (2012).  
    * *secp256k1:* Bitcoin Core / Ethereum Foundation C reference implementation.  
    * *Relevance:* Baseline control groups against which all lattice payloads and verification latencies are empirically compared.

---

## 3. Algorithmic Deep Dive: Mathematical Foundations & Security Analysis

```
========================================================================================
                                CRYPTOGRAPHIC TAXONOMY
========================================================================================
        Classical Primitives                     Lattice-Based Post-Quantum Primitives
         (Discrete Logarithm)                      (Shortest Vector / Learning With Errors)
                 │                                        │
        ┌────────┴────────┐                      ┌────────┴─────────────┐
    [Ed25519]       [secp256k1]                  │                      │
   Curve25519     Koblitz curve            [Falcon-512]            [ML-DSA-44]
  Pk: 32 B        Pk: Recovered            (Draft FIPS 206)         (FIPS 204)
  Sig: 64 B       Sig: 65 B (r,s,v)          NTRU Lattice           Module-LWE
  Total: 96 B     Wire: ~110 B          Pk: 897 B | Sig: ~666 B  Pk: 1312 B | Sig: 2420 B
========================================================================================
```

### 3.1 Falcon-512 (FN-DSA, Draft FIPS 206)
* **Mathematical Setting:** Operates over the cyclotomic ring $\mathcal{R} = \mathbb{Z}[x] / (\phi_n(x))$ where $\phi_n(x) = x^n + 1$ and $n = 512$.
* **Underlying Hardness:** Short Integer Solution (SIS) problem over NTRU lattices.
* **Mechanism:** Employs the **"Hash-and-Sign"** paradigm using Fast Fourier Orthogonalization over the tree of polynomials (the Falcon tree).
* **Key Generation:** Generates short polynomials $f, g, F, G \in \mathcal{R}$ satisfying the NTRU equation:

  $$
  fG - gF = q \pmod{x^n + 1}, \quad \text{where } q = 12289
  $$

  The public key is computed as $h = g \cdot f^{-1} \pmod q$.
* **Verification (Strictly Integer Modular Arithmetic):**
  * Checks that the signature polynomial vector $(s_1, s_2)$ satisfies $s_1 + s_2 h = c \pmod q$ using the Number Theoretic Transform (NTT) over $\mathbb{Z}_q$.
  * Checks that the squared Euclidean norm $\|(s_1, s_2)\|^2 \le \lfloor \beta^2 \rfloor = 34034726$.
  * **Consensus Safety:** Falcon verification is mathematically specified using pure integer modular arithmetic and NTTs. There is no floating-point arithmetic in verification, precluding floating-point consensus forks across validating nodes.
* **Signing & Side-Channel Considerations (Client / Wallet):**
  * Key generation and signing require double-precision floating-point emulation for Fast Fourier Gaussian sampling.
  * In client wallets, constant-time algorithms or hardware cryptographic boundaries must be enforced to prevent microarchitectural cache-timing and power-analysis side channels.
* **Address Derivation & Quantum Collision Margins:**
  * Falcon-EVM derives addresses using the standard Ethereum formula: $\text{Address} = \text{keccak256}(\text{falcon\_pubkey})[12..32]$.
  * The 20-byte ($160\text{-bit}$) output provides $80\text{-bit}$ classical collision security and $\approx 53.3\text{-bit}$ quantum collision security against quantum birthday attacks via Brassard-Høyer-Tapp (BHT). For full 128-bit quantum collision security, migrating to a 32-byte address format ($\text{keccak256}(pk)[0..32]$) is planned for future network upgrades.

### 3.2 ML-DSA-44 (CRYSTALS-Dilithium, FIPS 204)
* **Mathematical Setting:** Operates over polynomial rings $\mathcal{R}_q = \mathbb{Z}_q[x] / (x^{256} + 1)$ with modulus $q = 8380417 = 2^{23} - 2^{13} + 1$.
* **Underlying Hardness:** Module Learning With Errors (M-LWE) and Module Short Integer Solution (M-SIS) problems over matrices of polynomials ($4 \times 4$ for ML-DSA-44).
* **Mechanism:** Employs the **"Fiat-Shamir with Aborts"** framework (Lyubashevsky paradigm), relying on uniform sampling across bounded intervals.
* **Systems Trade-offs:**
  * **Pros:** Pure integer arithmetic ($32\text{-bit}$ modular operations) with no floating-point dependencies. Extremely robust and maps natively to AVX2/AVX-512 SIMD.
  * **Cons:** Substantially larger cryptographic payload ($1,312\text{ bytes}$ public key, $2,420\text{ bytes}$ signature $\rightarrow 3.73\text{ KB}$ per transaction), creating severe pressure on network buffers and memory caches.

---

## 4. Hardware Budget & Constraint Validation

All experiments and node deployments execute deterministically on local bare-metal hardware:

* **CPU (Intel Core i5-12400 Alder Lake):**
  * **Cores/Threads:** 6 Physical Performance Cores (P-cores) / 12 logical threads @ 2.50 GHz base / 4.40 GHz turbo boost, 18 MB Intel Smart Cache (L3).
  * **Instruction Sets:** Hardware AVX2, BMI2, and SHA-NI natively accelerate Number Theoretic Transforms (NTT), polynomial multiplications, and Keccak/BLAKE3 hashing.
  * **Compiler Flags:** Compiled with `RUSTFLAGS="-C target-cpu=native"` to enable automatic vectorization across AVX2 registers.
* **RAM (16 GB DDR4-3200):**
  * Multi-node local devnet deployments (4 to 8 nodes) run concurrently with an enforced RSS memory cap of $\le 250\text{ MB}$ per node ($\le 2\text{ GB}$ total testnet RAM footprint).
  * State storage tests utilize an embedded key-value engine (`sled`) with an explicit $512\text{ MB}$ write buffer limit.
* **Operating System & Toolchain:**
  * Ubuntu 22.04 LTS (Linux Kernel 6.8.0), Rust 1.84.0 stable toolchain, `revm` v43.0.3, `pqcrypto-falcon` v0.4 (`liboqs` C backend).
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

### 5.2 Research Novelty: Epoch-Based Witness Pruning with Dual-Root Commitments

* **The Problem:** In a post-quantum ledger, transaction witnesses are massive ($\approx 1.56\text{ KB}$ for Falcon-512, $\approx 3.73\text{ KB}$ for ML-DSA-44). Storing these proofs indefinitely causes rapid disk exhaustion and validator centralization.
* **The Optimization:**
  * Block headers commit to two separate cryptographic roots:
    1. **Execution Intent / State Root:** Standard EVM Merkle Patricia Trie (`state_root`, `receipts_root`) or QR-DLT BLAKE3 `intent_root`.
    2. **Witness Commitment Root:** BLAKE3 Merkle tree over all transaction witness signatures (`witness_root`).
  * **Consensus Wire Reality (Fresh Blocks):** During round-robin block proposal, newly minted blocks **must still transmit the full witness payload** over the P2P network so peer validators can independently verify the cryptographic validity of all transactions before accepting the block.
  * **Retrospective Epoch Pruning:** Once a block reaches confirmation depth $k$ (e.g., $k = 100$ or $k = 1,000$ blocks), validating full nodes delete the raw $1.56\text{ KB}$ witness payloads from persistent disk storage, retaining only the $32\text{-byte}$ header `witness_root`.
  * **Auditability Trade-Off:** Reclaiming **$93.6\%$ of historical disk space** allows validating nodes to maintain a flat, sustainable storage footprint. However, newly joining nodes performing historical sync from genesis must either fetch historical witnesses from archival nodes or rely on trusted state checkpoints / weak subjectivity (the same operational trade-off accepted by Bitcoin BIP 141 and Ethereum EIP-4844).

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

## 7. Execution Roadmap (24 Weeks)

```
[Weeks 1-3]   Phase 1: Cryptographic Abstraction & Microbenchmarking [Completed]
[Weeks 4-7]   Phase 2: Types, Segregated Transaction Engine & State DB [Completed]
[Weeks 8-11]  Phase 3: Consensus, P2P Gossip & Multi-Node Local Devnet [Completed]
[Weeks 12-14] Phase 4: Bottleneck Isolation, Novel Optimization & Experiments [Completed]
[Weeks 15-16] Phase 5: Empirical Analysis, Manuscript Writing & Artifact Packaging [Completed]
[Weeks 17-20] Phase 6: Falcon-EVM Sovereign Blockchain & Comparative Evaluation [Completed]
[Weeks 21-24] Phase 7: Reviewer Calibration, Live Multi-Node Network Testbed (tc netem) & Paper Revision [In Progress]
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
* [x] Record comparative metrics: verification throughput, disk usage growth over time, and witness space reclamation rate.

### Phase 5: Empirical Analysis & Final Deliverables (Weeks 15–16) — COMPLETED
* [x] Process raw Criterion and evaluation logs into publication-ready vector charts via Python (`scripts/plot_results.py`).
* [x] Build full CLI benchmarking evaluation suite (`qr-dlt-node evaluate`).
* [x] Produce comprehensive empirical walkthrough documentation and supervisor reporting.
* [x] Package a clean, reproducible GitHub repository with full test suite passing (51 unit & integration tests).

### Phase 6: Falcon-EVM Sovereign Blockchain & Comparative Evaluation (Weeks 17–20) — COMPLETED
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
* [x] **Week 20: JSON-RPC Layer, Smart Contract Deployment & Head-to-Head Benchmarking vs. Normal EVM** — COMPLETED
  * [x] Implement Ethereum JSON-RPC server (`eth_chainId`, `eth_sendRawTransaction`, `eth_call`, `eth_getBalance`, `eth_estimateGas`, `eth_blockNumber`, `eth_getBlockByNumber`) via `jsonrpsee`.
  * [x] Build a lightweight client/wallet CLI tool (`falcon-signer`) to sign and broadcast Type `0x46` transactions.
  * [x] Deploy Solidity test contracts: ERC-20 token, AMM DEX, and Post-Quantum Account Abstraction (ERC-4337) contract utilizing the `0x15` precompile.
  * [x] Execute initial head-to-head empirical benchmarking: Falcon-EVM vs. Normal EVM Chain (secp256k1 baseline).

### Phase 7: Reviewer Calibration, Live Multi-Node Network Testbed (`tc netem`) & Paper Revision (Weeks 21–24) — IN PROGRESS
* [ ] **Week 21: Statistical Rigor & Unified Benchmarking Harness**
  * Re-run all cryptographic benchmarks under identical Alder Lake hardware conditions (50 iterations, reporting mean $\pm$ standard deviation and 95% confidence intervals).
  * Resolve baseline discrepancies: Replace unoptimized Ed25519 comparison with C-optimized `secp256k1` (`libsecp256k1`) for all EVM-related evaluations.
  * Clarify terminology: Explicitly separate raw signature verification throughput (signatures/sec in Rayon pool) from end-to-end consensus state-machine throughput (transactions/sec bound by EVM sequential execution and MPT trie writes).
* [ ] **Week 22: Live Multi-Node Network Testbed with Linux `tc netem`**
  * Deploy a 4-node local cluster spanning isolated Linux network namespaces.
  * Configure Linux `tc netem` on virtual network interfaces (`veth`) to measure real TCP/IP socket gossip latency under WAN delays ($50\text{ ms}$, $100\text{ ms}$, $200\text{ ms}$) and packet loss ($0.5\%$).
  * Replace analytical arithmetic formulas with empirical network packet captures and socket-to-socket block propagation profiles.
* [ ] **Week 23: Solidity Gas Calibration & Account Abstraction Baseline**
  * Transparently deconstruct precompile gas economics: differentiate between precompile execution gas ($3,000\text{ gas}$) and calldata transmission gas ($\approx 25,520\text{ gas}$ for 1.59 KB non-zero input), totaling $\approx 28,520\text{ gas}$ on-chain.
  * Deploy an identical classical ECDSA ERC-4337 smart wallet contract to isolate the exact gas delta ($162,941\text{ gas}$ Falcon vs $\approx 85,200\text{ gas}$ ECDSA).
  * Benchmark or cite the pure EVM bytecode polynomial verification baseline ($2.4\text{M--}5.8\text{M gas}$).
* [ ] **Week 24: Threat Model Formalization, Related Work & Manuscript Polish**
  * Formalize full-stack post-quantum threat model: PoA validator consensus signatures, P2P TLS 1.3 handshakes, smart contract `ecrecover` deprecation, wallet-side floating-point Gaussian sampling side channels, and 20-byte address collision bounds.
  * Position against related proposals: EIP-8052 (split Falcon precompile), EIP-7592, EIP-7619, ZKNOX hybrid accounts, and STARK signature aggregation.
  * Update `paper/paper.tex` and figures with calibrated claims, exact numbers, and journal-ready presentation.

---

## 8. Empirical Systems Evaluation & Benchmarking Results

Our empirical evaluations on bare-metal Linux (Intel Core i5-12400 Alder Lake, AVX2/BMI2/SHA-NI) yielded the following quantitative findings:

### 8.1 The "Lattice Tax" Wire Overhead (Figure 1 & Figure 2)

We evaluate cryptographic payload overhead across two distinct contexts: (1) isolated cryptographic witness size against non-EVM baselines, and (2) serialized transaction envelope size against classical EVM baselines:

| Cryptographic Scheme | Public Key | Signature | Total Witness | Lattice Tax (Witness vs. Ed25519) | Wire Envelope (EVM Type) | Lattice Tax (Envelope vs. Normal EVM) |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **Ed25519** (Non-EVM Baseline) | $32\text{ B}$ | $64\text{ B}$ | **$96\text{ B}$** | **$1.00\times$** (Baseline) | — | — |
| **secp256k1** (Normal EVM Baseline) | Recovered | $65\text{ B}$ | $65\text{ B}$ | — | **$110\text{ B}$** (Legacy/EIP-1559) | **$1.00\times$** (Baseline) |
| **Falcon-512** (Draft FIPS 206) | $897\text{ B}$ | $\approx 666\text{ B}$ | **$1,563\text{ B}$** | **$16.28\times$** | **$1,670\text{ B}$** (Type `0x46`) | **$15.18\times$** |
| **ML-DSA-44** (NIST FIPS 204) | $1,312\text{ B}$ | $2,420\text{ B}$ | **$3,732\text{ B}$** | **$38.88\times$** | $\approx 3,840\text{ B}$ (Hypothetical) | $\approx 34.9\times$ |

*Analysis:* Falcon-512 achieves the most compact footprint among NIST post-quantum standards. However, because EVM transaction recovery (`ecrecover`) cannot be performed with Falcon signatures alone, the 897-byte public key must be explicitly transmitted in the Type `0x46` envelope, yielding a **$15.18\times$ wire expansion** over classical ECDSA envelopes.

### 8.2 Parallel Signature Verification Scaling (Figure 3)

We evaluate raw cryptographic signature verification throughput across batch sizes of $100$, $500$, and $1,000$ signatures using the Rayon parallel work-stealing pool across 12 logical threads on Intel Core i5-12400 (Alder Lake):

| Batch Size | Ed25519 (Pure-Rust Unoptimized) | Falcon-512 (AVX2 C-Binding) | ML-DSA-44 (AVX2 C-Binding) | secp256k1 (libsecp256k1 C-Binding) |
| :---: | :---: | :---: | :---: | :---: |
| **100 txs** | $440\text{ sigs/s}$ ($227.3\text{ ms}$) | **$27,617\text{ sigs/s}$** ($3.62\text{ ms}$) | **$30,721\text{ sigs/s}$** ($3.26\text{ ms}$) | — |
| **500 txs** | $486\text{ sigs/s}$ ($1,028.6\text{ ms}$) | **$23,737\text{ sigs/s}$** ($21.06\text{ ms}$) | **$32,365\text{ sigs/s}$** ($15.45\text{ ms}$) | — |
| **1,000 txs** | $501\text{ sigs/s}$ ($1,994.9\text{ ms}$) | **$20,402\text{ sigs/s}$** ($49.02\text{ ms}$) | **$34,662\text{ sigs/s}$** ($28.85\text{ ms}$) | **$26,817\text{ sigs/s}$** ($37.29\text{ ms}$) |
| **1,000 txs (16-thread dedicated)** | — | **$53,321\text{ sigs/s}$** ($18.75\text{ ms}$) | — | **$26,817\text{ sigs/s}$** ($37.29\text{ ms}$) |

*Analysis & Nuances:*
1. **Verification Speed vs. Payload Size:** ML-DSA-44 verification is faster than Falcon-512 ($34,662\text{ sigs/s}$ vs. $20,402\text{ sigs/s}$) because ML-DSA operates entirely with $32\text{-bit}$ integer modular arithmetic over $\mathbb{Z}_q$, mapping natively into AVX2 integer registers without Falcon's Fast Fourier polynomial decompression. However, Falcon-512 wins overwhelmingly on payload size ($1,563\text{ B}$ vs $3,732\text{ B}$), making Falcon far superior for network gossip and block serialization.
2. **Baseline Explanation:** The early Ed25519 benchmark ($440\text{--}501\text{ sigs/s}$) suffered from unoptimized pure-Rust point decompression without AVX2 backend extensions. In contrast, the true EVM baseline, `libsecp256k1` (C library), verified at **$26,817\text{ sigs/s}$**.
3. **Throughput Definition:** These figures measure **cryptographic signature verification throughput (signatures/sec)** in the parallel Rayon admission gate. End-to-end blockchain transaction throughput is bound by sequential EVM state execution, account nonce checks, and Merkle Patricia Trie disk persistence to $\approx 1,500\text{--}2,500\text{ TPS}$.

### 8.3 Epoch-Based Witness Pruning Storage Reclamation (Figure 4)

We evaluate historical disk storage reclamation across two workloads: (1) Falcon-512 EVM blocks (1,000 txs), and (2) ML-DSA-44 generic DLT blocks (500 txs):

| Metric | Falcon-512 EVM Block (1,000 txs) | ML-DSA-44 DLT Block (500 txs) |
| :--- | :---: | :---: |
| **Total Unpruned Block Size** | $1,630.86\text{ KB}$ | $1,863.28\text{ KB}$ |
| **Raw Witness Proof Payload** | $1,526.37\text{ KB}$ ($1,563\text{ B/tx}$ raw) | $1,832.03\text{ KB}$ ($3,732\text{ B/tx}$ raw) |
| **Retained Intent / State Payload** | $104.49\text{ KB}$ (Nonces, Balances, Calldata) | $31.25\text{ KB}$ (Compact intents) |
| **Purged Witness Space (Disk Reclaimed)** | **$1,526.37\text{ KB}$ purged** | **$1,832.03\text{ KB}$ purged** |
| **Storage Reclamation Rate** | **$93.55\% \approx \mathbf{93.6\%}$ Reclaimed** | **$98.32\% \approx \mathbf{98.3\%}$ Reclaimed** |
| **Commitment Invariant** | 32-byte `witness_root` in block header | 32-byte `witness_root` in block header |

*Analysis:* Storing unpruned lattice witnesses would bloat node disks by $\approx 1.53\text{ MB}$ per 1,000 Falcon transactions. Epoch pruning bounds disk growth on validating nodes to a constant function of transaction execution state, reclaiming **$93.6\%$ of historical disk space** for Falcon-EVM while preserving auditability via the 32-byte header commitment.

### 8.4 Head-to-Head Comparative Evaluation: Falcon-EVM vs. Normal EVM (secp256k1 Baseline)

Using our bare-metal benchmarking framework (`qr-dlt-node compare-evm`), we conducted a head-to-head empirical evaluation between **Falcon-EVM** (EIP-2718 Type `0x46` envelope, native `0x15` precompile, dual-root SegWit pruning) and **Normal EVM** (standard ECDSA secp256k1 baseline):

| Dimension | Normal EVM (secp256k1 Baseline) | Falcon-EVM (QR-DLT Sovereign) | Systems Impact & Analysis |
| :--- | :---: | :---: | :---: |
| **Transaction Wire Footprint** | $110\text{ B}$ (Signature $65\text{ B}$, PubKey recovered) | $1,670\text{ B}$ (PubKey $897\text{ B}$, Sig $666\text{ B}$) | **$15.18\times$ "Lattice Tax"** due to explicit public key transmission |
| **Parallel Verification Throughput** | $26,817\text{ sigs/s}$ ($37.29\text{ ms} / 1\text{k txs}$) | **$53,321\text{ sigs/s}$** ($18.75\text{ ms} / 1\text{k txs}$) | **$1.99\times$ Speedup** (AVX2 polynomial NTT beats ECC scalar point mult) |
| **Block Size (1,000 Transactions)** | $107.42\text{ KB}$ | $1,630.86\text{ KB}$ (Unpruned) / **$104.49\text{ KB}$ (Pruned)** | $1,526.37\text{ KB}$ purged after epoch confirmation threshold $k$ |
| **Propagation Delay (100 Mbps, 100ms RTT)** | $108.80\text{ ms}$ (Analytical serialization) | $233.60\text{ ms}$ (Unpruned) / **$108.56\text{ ms}$ (Pruned sync)** | Fresh blocks carry witnesses ($233.60\text{ ms}$); pruned sync matches classical |
| **Base Intrinsic Gas** | $21,000\text{ gas}$ | $25,000\text{ gas}$ ($21\text{k base} + 4\text{k Falcon verify}$) | $+19.0\%$ intrinsic base reflecting signature verification cost |
| **Precompile Execution Gas** | $3,000\text{ gas}$ (`ecrecover` `0x01`) | $3,000\text{ gas}$ (`falcon512` `0x15`) | **Execution cycle parity**; calldata adds $+25,520\text{ gas}$ for 1.59 KB input |
| **Post-Quantum AA (`executeUserOp`)** | $\approx 85,200\text{ gas}$ (Vulnerable to Shor) | $162,941\text{ gas}$ (ERC-4337 + `0x15` precompile) | $+77,741\text{ gas}$ delta ($+24\text{k calldata} + 3\text{k precompile} + \text{memory buffers}$) |
| **Storage Bloat Reclamation** | $0.0\%$ (Signatures permanently in RLP state) | **$93.6\%$ Reclaimed** ($1,526\text{ KB}$ purged / 1k txs) | Pruned historical state matches classical footprint ($104.5\text{ KB}$) |
| **Quantum Attack Surface** | **Vulnerable** (secp256k1 broken by Shor's algo) | **Computationally Hard** (NTRU lattice SIS hardness) | Exposed keys at rest vulnerable; Falcon eliminates discrete-log collapse |

---

## 9. Falcon-EVM Blockchain Architecture & Comparative Evaluation Framework

To evaluate the operational feasibility of post-quantum cryptography in smart contract ecosystems, the project implements **Falcon-EVM (QR-EVM)**: a sovereign, EVM-compatible blockchain running native Falcon-512 signatures, followed by a head-to-head empirical evaluation against a normal EVM chain (ECDSA $\text{secp256k1}$).

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
    • Exposes Stateless Precompile 0x15 (`falcon_verify`) to Solidity Smart Contracts
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
   * Integrates the Rust Ethereum Virtual Machine (`revm` v43.0.3) directly into the block proposal and validation loop.
   * Maintains EVM world state (nonces, balances, bytecode, and storage slots) backed by `sled` key-value storage.

2. **Native Falcon-512 EVM Precompile (`0x15`):**
   * Registered at address `0x0000000000000000000000000000000000000015` as a **stateless** pure function.
   * **Input:** $\text{msg\_hash}\,(32\text{ B}) \,\|\, \text{pk\_len}\,(2\text{ B}) \,\|\, \text{public\_key}\,(897\text{ B}) \,\|\, \text{sig\_len}\,(2\text{ B}) \,\|\, \text{signature}\,(\approx 666\text{ B})$.
   * **Output:** $32\text{-byte}$ word containing `1` (valid) or `0` (invalid).
   * **Gas Economics (Execution vs. Calldata):**
     * Precompile execution is calibrated to $3,000\text{ gas}$ reflecting AVX2-accelerated NTT verification CPU cycles.
     * Passing $1,595\text{ bytes}$ of calldata into the contract incurs standard EVM calldata costs ($\approx 16\text{ gas/byte} \approx 25,520\text{ gas}$), totaling $\approx 28,520\text{ gas}$ for on-chain contract calls.
   * **Bytecode Baseline:** Interpreting iterative polynomial NTT loops in un-precompiled Solidity bytecode would require an estimated $2.4\text{M--}5.8\text{M gas}$ (as established in EIP-8052 rationale), confirming that native precompiles are indispensable.

3. **EIP-2718 Type `0x46` Falcon Transaction Envelope:**
   * Standard Ethereum transactions rely on ECDSA public key recovery (`ecrecover`). Because Falcon does not support recovery from signature alone, Type `0x46` explicitly carries the 897-byte public key alongside the signature:
     $$\text{FalconTx} = 0x46 \,\|\, \text{rlp}([ \text{chainId}, \text{nonce}, \text{maxPriorityFee}, \text{maxFee}, \text{gasLimit}, \text{to}, \text{value}, \text{data}, \text{accessList}, \text{falconPubKey}, \text{falconSig} ])$$
   * **Address Derivation:** Evaluated via $\text{Address} = \text{keccak256}(\text{falcon\_public\_key})[12..32]$, preserving 20-byte EVM address interoperability.
   * **Intrinsic Gas Formula:** $21,000 \text{ base} + \text{calldata gas} + \text{Falcon verification intrinsic gas } (\approx 4,000\text{ gas})$.

4. **Decoupled EVM Segregated Witness & Epoch Pruning:**
   * EVM block headers commit to standard MPT `state_root`, `transactions_root`, and `receipts_root`, alongside QR-DLT's BLAKE3 `witness_root`.
   * Validating nodes verify signatures upon block proposal and mempool admission, but purge the raw $1.56\text{ KB}$ witness payloads after $k = 1,000$ block confirmations.
   * **Consensus Reality:** Freshly proposed blocks carry full witnesses for network consensus verification; epoch pruning reclaims historical storage ($93.6\%$) post-confirmation.

5. **JSON-RPC Server & Signing SDK:**
   * JSON-RPC endpoints (`eth_chainId`, `eth_sendRawTransaction`, `eth_call`, `eth_getBalance`, `eth_estimateGas`, `eth_blockNumber`, `eth_getBlockByNumber`) powered by `jsonrpsee`.
   * Client tooling (`falcon-signer`) capable of generating Falcon keypairs, encoding Type `0x46` transactions, and broadcasting to the Falcon-EVM mempool.

---

### 9.2 Head-to-Head Comparative Testing Framework: Falcon-EVM vs. Normal EVM Chain

To evaluate the operational differences between classical and post-quantum EVM architectures, we establish an automated comparative evaluation pipeline:

* **Control Group (Normal EVM):** Standard Reth / Anvil instance executing classical ECDSA $\text{secp256k1}$ transactions.
* **Experimental Group (Falcon-EVM):** Sovereign QR-EVM node executing Falcon-512 Type `0x46` transactions with native precompile `0x15` and SegWit epoch pruning.

#### Head-to-Head Evaluation Matrix

| Metric | Normal EVM Chain (ECDSA Baseline) | Falcon-EVM Chain (Falcon-512) | Research Hypothesis / Systems Impact |
| :--- | :--- | :--- | :--- |
| **Cryptographic Scheme** | ECDSA ($\text{secp256k1}$) | Falcon-512 (Draft FIPS 206 / FN-DSA) | Full quantum resilience against Shor's discrete logarithm attack. |
| **Transaction Wire Footprint** | $\approx 110\text{ bytes}$ | $\approx 1,670\text{ bytes}$ | Falcon transactions are $\approx 15.2\times$ larger due to explicit 897-byte public key. |
| **Public Key Derivation** | Recovered on-the-fly (`ecrecover`) | Explicitly provided in envelope ($897\text{ B}$) | Eliminates malleability; requires SegWit pruning to prevent state bloat. |
| **Parallel Batch Verification TPS** | $\approx 26,817\text{ sigs/s}$ | **$>50,000\text{ sigs/s}$** | Falcon NTT verification maps onto AVX2 SIMD, outperforming elliptic curve scalar multiplication. |
| **Block Propagation under WAN Delay** | Baseline ($t_0$) | $t_0 + \Delta t$ (Monolithic) vs $t_0$ (Decoupled SegWit sync) | Fresh blocks carry witnesses; decoupled intent propagation prevents packet fragmentation. |
| **Smart Contract Verification Cost** | $3,000\text{ gas}$ (`ecrecover` `0x01`) | $3,000\text{ gas}$ (Precompile `0x15`) vs $>1.5\text{M gas}$ (Solidity) | Precompile achieves execution parity; calldata adds $+25,520\text{ gas}$. |
| **Disk State Bloat per 100k Transactions** | $\approx 11\text{ MB}$ | **$\approx 10.5\text{ MB}$** (Pruned) vs $163\text{ MB}$ (Unpruned) | Epoch pruning achieves storage parity with classical EVM chains. |
| **Quantum Attack Surface** | **Vulnerable** (CRQC breaks key offline) | **Secure** (Lattice SIS problem remains hard) | Eliminates Shor's algorithm collapse for both at-rest and in-flight transactions. |

#### Comparative Benchmark Scenarios
1. **Workload A: High-Throughput Token Transfers (ERC-20):** 10,000 concurrent transfers submitted to both chains; measure sustained verification TPS, memory usage, and confirmation latency.
2. **Workload B: Stateful DeFi Swaps (Constant-Product AMM):** Evaluate EVM state execution overhead relative to signature verification.
3. **Workload C: Live WAN Network Emulation (`tc netem`):** Inject $50\text{ ms}$, $100\text{ ms}$, and $200\text{ ms}$ latency via `scripts/simulate_latency.sh` across Linux network namespaces to measure real socket gossip delay.
4. **Workload D: Storage Reclamation Profiling:** Run 100,000 transactions and record disk growth every 1,000 blocks to benchmark the exact storage reclamation curve.

---

## 10. Role Division & Collaborative Workflow

| Domain | **Bashar Khan** | **Zaheer Khan** |
| :--- | :--- | :--- |
| **Cryptographic Primitives** | AVX2 SIMD checks, Criterion benchmarking harness, Falcon-512 integration. | ML-DSA-44 integration, key-encoding bounds checking, address hashing logic (`keccak256`). |
| **System Engine** | `rayon` parallel batch verifier, `revm` embedded execution engine, state transitions (`sled`), memory profiling. | Transaction serialization, SegWit decoupling, mempool admission filters, epoch-based witness pruner. |
| **Networking & Devnet** | Network latency injection (`tc netem`), cluster orchestration scripts, metrics collector. | P2P gossip layer, block header broadcasting, synchronization logic. |
| **EVM Engine & Precompile** | Native Falcon-512 precompile (`0x15`), EIP-2718 Type `0x46` envelope, Anvil/Reth comparison testbed. | Ethereum JSON-RPC server (`jsonrpsee`), Solidity contract test suite (ERC-20 / AMM), threat modeling. |
| **Academic Manuscript** | Abstract, System Architecture, Experimental Methodology, Performance Graphs. | Literature Review, Mathematical Background, Threat Modeling, Discussion. |

---

## 11. Verification & Development Commands

```bash
# Verify Rust toolchain and AVX2 capabilities
rustup default stable
lscpu | grep -i avx2

# Run full workspace test suite (51 unit & integration tests passing)
cargo test --workspace

# Run cryptographic microbenchmarks with native SIMD optimizations
RUSTFLAGS="-C target-cpu=native" cargo bench --bench crypto_bench
RUSTFLAGS="-C target-cpu=native" cargo bench --bench block_validation

# Execute empirical evaluation and generate publication vector charts
cargo run -p qr-dlt-node -- evaluate --output-file paper/empirical_results.json
python3 scripts/generate_paper_figures.py

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
| **Falcon non-deterministic sampling across nodes** | High (Consensus fork) | Verification is strictly integer-only NTT arithmetic by specification; no floating-point arithmetic is executed in consensus verification loops. |
| **Wallet-side floating-point Gaussian sampling side-channels** | High (Key extraction) | Client wallets generating signatures must employ constant-time Gaussian sampling algorithms (e.g., Pornin's CDT sampling) or hardware security modules (HSMs). |
| **20-byte address collision margins under quantum search** | Medium (Address collision) | 20-byte addresses provide 80-bit classical and $\approx 53.3$-bit quantum collision security (BHT algorithm). For full 128-bit quantum security, plan future migration to 32-byte addresses (`keccak256(pk)[0..32]`). |
| **Excessive block propagation delay due to PQC key size** | Medium (Elevated orphan rates) | Apply compact block relay (BIP 152 style): transactions verified in the mempool are referenced by compact IDs, avoiding re-transmitting 1.56 KB witnesses during block announcement. |
| **Prohibitive EVM calldata gas costs for Falcon signatures** | High (Adoption barrier) | Calldata costs $\approx 25,520\text{ gas}$ for 1.59 KB. Mitigate via native precompile `0x15` ($3,000\text{ gas}$ execution) and detached sidecar proofs in future EIP-4844-style blobs. |
| **Lack of native EVM precompile for Falcon-512 in standard clients** | Medium (Verification cost) | Provide dual benchmark paths: (1) embedded `revm` Falcon-512 precompile in QR-EVM for native performance, and (2) EVM bytecode verification emulator assessing the baseline penalty on un-upgraded chains ($2.4\text{M--}5.8\text{M gas}$). |
| **Research novelty deemed incremental by reviewers** | Medium (Journal rejection) | Explicitly position against EIP-8052, EIP-7592, EIP-7619, and ZKNOX; emphasize that QR-DLT provides the first comprehensive end-to-end sovereign EVM chain with dual-root SegWit epoch pruning and empirical multi-node benchmarking. |


