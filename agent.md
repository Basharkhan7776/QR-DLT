# Quantum-Resilient Distributed Ledger (QR-DLT)

**Project Title:** Empirical Evaluation and Systems Optimization of Lattice-Based Digital Signatures in a From-Scratch Rust Blockchain Architecture

**Principal Investigators:** Bashar Khan & Zaheer Khan  
**Affiliation:** Department of Computer Science and Engineering, QR-DLT Research Lab  
**Code & Artifact Repository:** [github.com/bashar-khan/QR-DLT](https://github.com/bashar-khan/QR-DLT)  
**Target Environment:** Bare-Metal Linux (Ubuntu 22.04 LTS, Linux Kernel 6.8) on Intel Core i5-12400 (Alder Lake, 6 P-cores / 12 threads @ 2.50 GHz base / 4.40 GHz boost, 18 MB L3 cache, AVX2/BMI2/SHA-NI), 16 GB DDR4-3200 RAM, Integrated Graphics.

---

## 1. Project Motivation: The Classical Status Quo vs. The Post-Quantum Imperative

### 1.1 The Classical Status Quo

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

In 2003, Proos and Zalka demonstrated that Shor's algorithm solves ECDLP with significantly fewer quantum resources than factoring equivalent-security RSA moduli. Recent resource estimations by Babbush et al. (Google Quantum AI, 2026) calculate that breaking $\text{secp256k1}$ requires only $\approx 1,200 \text{ to } 1,450$ error-corrected logical qubits and fewer than $5 \times 10^5$ physical qubits under surface-code architectures, completing in under 10 minutes to several hours.

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
       Logical Qubits Estimated: ~1,200 - 1,450 logical qubits
       [TOTAL EXPLOITATION: Private keys derived from public keys]
```

#### Attack Windows & Threat Vectors on Distributed Ledgers
As formulated by Aggarwal et al. (2018), quantum adversaries target two primary threat vectors in public ledgers:

1. **Static Threat: Public Keys Exposed at Rest (Dominant Attack Vector):**
   * In systems utilizing public key hashing ($\text{Address} = \text{keccak256}(pk)[12..31]$), the raw public key is permanently exposed on-chain the moment an account transmits its first outgoing transaction.
   * A quantum adversary can scrape all exposed public keys from ledger history, execute Shor's algorithm offline at leisure to compute the underlying private scalar $d$ where $Q = d \cdot G$, and forge unauthorized transactions that drain user balances before migration can occur.
   * In Bitcoin, over 4 million BTC reside in unhashed or reused addresses; in Ethereum, tens of millions of active accounts have already permanently exposed their $\text{secp256k1}$ public keys.

2. **Dynamic Threat: Short-Range Mempool Interception (Front-Running):**
   * Even for unspent/unexposed addresses, broadcasting a transaction sends the raw public key to the P2P mempool.
   * In Ethereum, the normal block proposal slot is $\approx 12\text{ seconds}$. Under periods of high network congestion, transaction queuing delays expand. An adversary possessing an ultrafast CRQC capable of computing private keys in sub-slot time could intercept the transaction in the mempool, compute the private key, and submit a higher-priority replacement transaction before block inclusion.

---

### 1.3 Why We Are Building This: The Post-Quantum Trilemma & Systems Gap

Faced with this threat, the global cryptographic community, led by NIST, approved FIPS 204 (ML-DSA) in August 2024 and submitted draft FIPS 206 (FN-DSA / Falcon) for final approval (expected late 2026/2027).

However, transitioning distributed ledgers to post-quantum cryptography encounters **The Post-Quantum Trilemma**: a fundamental systems conflict between:
1. **Cryptographic Quantum Resilience:** Hardness based on lattice problems (NTRU / SIS / LWE) achieving NIST Security Level 1 with no known polynomial quantum algorithms.
2. **Payload Size ("The Lattice Tax"):** Lattice keys and signatures are orders of magnitude larger than classical primitives:
   * **Ed25519 (Non-EVM Baseline):** $32\text{ B}$ public key, $64\text{ B}$ signature ($96\text{ B}$ witness baseline).
   * **secp256k1 (Normal EVM Baseline):** $\approx 110\text{ B}$ wire envelope ($65\text{ B}$ signature, public key recovered).
   * **Falcon-512 (Draft FIPS 206):** $897\text{ B}$ public key, $\approx 666\text{ B}$ signature ($1,563\text{ B}$ witness $\rightarrow \mathbf{16.3\times}$ over Ed25519; $1,670\text{ B}$ Type 0x46 envelope $\rightarrow \mathbf{15.2\times}$ over secp256k1).
   * **ML-DSA-44 (FIPS 204):** $1,312\text{ B}$ public key, $2,420\text{ B}$ signature ($3,732\text{ B}$ witness $\rightarrow \mathbf{38.9\times}$ over Ed25519).
3. **Execution Throughput & State Scalability:**
   * **P2P Wire Saturation:** Monolithic transmission of $1,000$ Falcon transactions requires transmitting $\approx 1.63\text{ MB}$ of cryptographic data (vs. $107\text{ KB}$ for ECDSA), causing packet fragmentation and a $2.15\times$ increase in fresh block wire transmission time ($233.6\text{ ms}$ vs. $108.8\text{ ms}$ over 100 Mbps WAN).
   * **EVM Interpretation Bottlenecks:** Interpreting lattice polynomial arithmetic in EVM bytecode costs upwards of $2.4\text{M}$ to $5.8\text{M gas}$ (with an empirical benchmark mean of $\approx 3.8\text{M gas}$), making native precompiles mandatory.
   * **State & Disk Bloat:** Storing raw $1.56\text{ KB}$ lattice witnesses permanently in the state trie rapidly exhausts validator disk storage.

#### Why From-Scratch Rust?
Standard frameworks (Substrate, Cosmos) introduce heavy abstractions and serialization overheads. By constructing a custom, modular Rust engine from the ground up:
* We retain **deterministic byte-level control** over memory layout, thread scheduling, SIMD registers, and wire serialization.
* We isolate and measure pure cryptographic execution versus networking and storage overhead with zero framework distortion.
* We demonstrate that **Dual-Root Consensus with Decoupled Segregated Witness and Epoch Pruning** combined with a **Stateless Native Precompile (`0x15`)** allow a sovereign post-quantum EVM chain to remain viable on standard commodity hardware.

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

3. **Babbush, R., McClean, J. R., Newman, M., Gidney, C. et al. (Google Quantum AI, 2026).** *Securing Elliptic Curve Cryptocurrencies against Quantum Vulnerabilities: Resource Estimates and Mitigations.*  
   *Venue:* arXiv:2603.28846 / IACR Cryptology ePrint Archive, Report 2026/625.  
   *Link:* [arXiv:2603.28846](https://arxiv.org/abs/2603.28846) | [IACR ePrint 2026/625](https://eprint.iacr.org/2026/625)  
   *Relevance:* Modern surface-code resource estimates demonstrating that breaking 256-bit elliptic curves ($\text{secp256k1}$) requires $\approx 1,200\text{--}1,450$ logical qubits and under half a million physical qubits, executable in under 10 minutes to several hours.

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
   *Dilithium Original Paper:* Ducas, L., Kiltz, E., Lepoint, T., Lyubashevsky, V., Schwabe, P., Seiler, G., Stehlé, D. (CHES 2018), *CRYSTALS-Dilithium: A Lattice-Based Digital Signature Scheme*, IACR TCHES 2018(1), pp. 238–268.

6. **NIST Draft FIPS 206 (Submitted Aug 2025; Expected 2026/2027):** *Fast-Fourier Lattice-Based Digital Signature Standard (FN-DSA / Falcon).*  
   *Author/Publisher:* National Institute of Standards and Technology (NIST), U.S. Department of Commerce.  
   *Status Note:* Submitted for final approval in August 2025; final publication anticipated late 2026 or 2027. FN-DSA modifies salt sampling (moving it inside the loop) and introduces public-key hashing into the digest ($c = H(r \parallel m \parallel H(pk))$) relative to original Falcon (2018), breaking direct binary interoperability. QR-DLT tests against draft FIPS 206 KAT test vectors.  
   *Link:* [NIST CSRC FIPS 206 Draft](https://csrc.nist.gov/pubs/fips/206/draft)  
   *Foundation:* Based on the Falcon algorithm.  
   *Falcon Original Paper:* Fouque, P.-A., Hoffstein, J., Kirchner, P., Lyubashevsky, V., Pornin, T., Prest, T., Ricosset, T., Seiler, G., Whyte, W., Zhang, Z. (2018), *Falcon: Fast-Fourier Lattice-based Compact Signatures over NTRU.* [IACR ePrint 2018/904](https://eprint.iacr.org/2018/904).

---

### 2.3 Post-Quantum EVM, Precompile Proposals & Related Work

7. **Ethereum Improvement Proposals (EIPs) for Falcon & Lattice Precompiles:**
   * **EIP-8052 (Created Oct 2025):** Dubois, R., Masson, S., Sanso, A., van der Wijden, M. et al., *Falcon-512 Precompile for EVM*. Specifies splitting Falcon-512 verification into two modular precompiles: Hash-to-Point (priced at $1,000\text{ gas}$) and Core Signature Verification (priced at $2,000\text{ gas}$), derived by interpolating CPU cycle counts from SUPERCOP benchmarks against SHA-256 and `ecrecover`. Precompile addresses are TBD.
   * **EIP-7592:** *PQC Precompiles: Falcon-512 and ML-DSA*. Explores monolithic lattice verification precompiles for Ethereum execution environments.
   * **EIP-7619:** *Post-Quantum Precompiled Contracts*. Explores execution and gas accounting models for post-quantum signature verification.
   * *Relevance to QR-DLT:* QR-DLT implements an integrated Falcon-512 precompile at address `0x15` calibrated at $3,000\text{ gas}$ total CPU execution cost (exact parity with EIP-8052's $1,000 + 2,000\text{ gas}$ and classical `ecrecover`), evaluating it within a live `revm` pipeline.

8. **Alternative Post-Quantum EVM Paradigms & Protocols:**
   * **Hybrid Smart Accounts (e.g., ZKNOX):** Combines classical ECDSA with post-quantum Falcon-512 or ML-DSA signatures in ERC-4337 smart wallets.
   * **STARK / SNARK Signature Aggregation:** Off-chain aggregation of hundreds of post-quantum lattice signatures into a single succinct zero-knowledge proof verified on-chain for $\approx 200,000\text{--}300,000\text{ gas}$.
   * **Hash-Based Signatures (SLH-DSA / SPHINCS+, FIPS 205):** Extremely large signatures ($7.8\text{--}49\text{ KB}$), rendering direct on-chain propagation prohibitive without aggressive off-chain aggregation.

9. **Wuille, P., Johnson, L., & Corallo, M. (2015).** *Segregated Witness (Consensus layer).*  
   *Specification:* Bitcoin Improvement Proposal 141 (BIP 141).  
   *Relevance:* Structural foundation for decoupling transaction execution intents from $1.56\text{ KB}$ cryptographic witnesses to prevent malleability and enable epoch-based witness pruning.

10. **Bernstein, D. J., Duif, N., Lange, T., Schwabe, P., & Yang, B.-Y. (2012):**  
    * *Title:* *High-speed high-security signatures.*  
    * *Venue:* Journal of Cryptographic Engineering, Vol. 2, No. 2, pp. 77–89.  
    * *Relevance:* Foundations of constant-time Ed25519; used as our non-EVM baseline control group.

11. **Wood, G. (2014):**  
    * *Title:* *Ethereum: A Secure Decentralised Generalised Transaction Ledger.*  
    * *Specification:* Ethereum Project Yellow Paper, Berlin/London version.  
    * *Relevance:* Foundational specification for EVM state transition rules, intrinsic gas calculations ($21,000\text{ base}$), and Merkle Patricia Trie commitments.

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
* **Mathematical Setting:** Operates over the cyclotomic ring $\mathcal{R}_q = \mathbb{Z}_q[x] / (x^n + 1)$ where $n = 512$ and prime modulus $q = 12,289$.
* **Underlying Hardness:** Computational Shortest Vector Problem (SVP) and Short Integer Solution (SIS) over NTRU lattices, providing NIST Security Level 1 (matching the security level of AES-128 against brute-force search).
* **Mechanism:** Employs the **"Hash-and-Sign"** paradigm using Fast Fourier Orthogonalization over the tree of polynomials (the Falcon tree).
* **Key Generation:** Generates short polynomials $f, g, F, G \in \mathcal{R}_q$ satisfying the NTRU equation:

  $$
  fG - gF = q \pmod{x^n + 1}, \quad \text{where } q = 12,289
  $$

  The public key is computed as $h = g \cdot f^{-1} \pmod q$, occupying exactly $897\text{ bytes}$ in packed format.
* **Verification (Strictly Integer Modular Arithmetic):**
  * Checks that the signature polynomial vector $(s_1, s_2)$ satisfies $s_1 + s_2 h = c \pmod q$ using the Number Theoretic Transform (NTT) over $\mathbb{Z}_q$.
  * Checks that the squared Euclidean norm $\|(s_1, s_2)\|^2 \le \lfloor \beta^2 \rfloor = 34,034,726$.
  * **Consensus Safety:** Falcon verification is mathematically specified using pure integer modular arithmetic and NTTs. There is no floating-point arithmetic in verification, precluding floating-point consensus forks across validating nodes.
* **Draft FIPS 206 Specifics & KAT Validation:**
  * Draft FIPS 206 moves salt sampling inside the rejection loop and incorporates public key hashing into the message digest: $c = H(r \parallel m \parallel H(pk))$.
  * QR-DLT tests against draft FIPS 206 Known Answer Test (KAT) vectors to ensure strict conformance.
* **Signing & Side-Channel Considerations (Client / Wallet):**
  * Key generation and signing require double-precision floating-point emulation for Fast Fourier Gaussian sampling.
  * In client wallets, constant-time algorithms (e.g., Pornin's CDT Gaussian sampling) or hardware cryptographic boundaries must be enforced to prevent microarchitectural cache-timing and power-analysis side channels.
* **Address Derivation & Quantum Collision Margins:**
  * Falcon-EVM derives addresses using the standard Ethereum formula: $\text{Address} = \text{keccak256}(\text{falcon\_pubkey})[12..31]$.
  * The 20-byte ($160\text{-bit}$) output provides $80\text{-bit}$ classical collision security. Under quantum birthday attacks via the Brassard-Høyer-Tapp (BHT) algorithm, collision security is bounded at $\approx 2^{53.3}$ operations, assuming access to large-scale quantum random-access memory (QRAM). Under standard Grover second-preimage search, security remains at $2^{80}$ operations. For long-term 128-bit quantum collision security, migrating to a 32-byte address format ($\text{keccak256}(pk)[0..31]$) is planned for future network upgrades.

### 3.2 ML-DSA-44 (CRYSTALS-Dilithium, FIPS 204)
* **Mathematical Setting:** Operates over polynomial rings $\mathcal{R}_q = \mathbb{Z}_q[x] / (x^{256} + 1)$ with modulus $q = 8,380,417 = 2^{23} - 2^{13} + 1$.
* **Underlying Hardness:** Module Learning With Errors (M-LWE) and Module Short Integer Solution (M-SIS) problems over matrices of polynomials ($4 \times 4$ for ML-DSA-44), providing NIST Security Level 2.
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

### 5.2 Research Novelty: Formal Trust & Storage Model for Dual-Root Witness Pruning

* **The Problem:** In a post-quantum ledger, transaction witnesses are massive ($\approx 1.56\text{ KB}$ for Falcon-512, $\approx 3.73\text{ KB}$ for ML-DSA-44). Storing these proofs indefinitely causes rapid disk exhaustion and validator centralization.
* **The Dual-Root Consensus Model:**
  * Block headers commit to two separate, cryptographically binding roots:
    1. **Execution Intent / State Root:** Standard EVM Merkle Patricia Trie (`state_root`, `receipts_root`) or QR-DLT BLAKE3 `intent_root`.
    2. **Witness Commitment Root:** BLAKE3 Merkle tree over all transaction witness signatures (`witness_root`).
  * **Formal Header Commitment Invariant:**
    $$\text{Header}_h = \langle \text{parent\_hash}, h, \text{state\_root}, \text{receipts\_root}, \text{txs\_root}, \text{witness\_root} \rangle$$
* **Consensus Wire Reality (Fresh Blocks):**
  * Newly minted blocks **must still transmit the full witness payload** on the P2P wire so peer validators can independently verify the cryptographic validity of all transactions before accepting the block.
  * Over a 100 Mbps WAN link with 100 ms RTT, transmitting unpruned 1,000-tx blocks incurs an analytical serialization delay of **$233.60\text{ ms}$** vs **$108.80\text{ ms}$** for classical EVM ($2.15\times$ wire penalty). This represents the genuine consensus wire cost of post-quantum security.
* **Retrospective Epoch Pruning Protocol:**
  * **Finality Assumption under PoA:** Under our deterministic round-robin Proof-of-Authority consensus with validator set $\mathcal{V}$, any block at depth $k > 100$ confirmations is assumed finalized under the honest-majority assumption ($> 2/3 |\mathcal{V}|$ honest signers). After depth $k$, transaction history is immutable and cannot be reorganized.
  * **Pruning Trigger:** Once height $(H_{\text{current}} - H_{\text{block}}) > k$, validating full nodes invoke `prune_witnesses(block_hash)`, purging raw $1.56\text{ KB}$ witness payloads from persistent disk while retaining the 32-byte `witness_root` in the header.
  * **Storage Reclamation:** Reclaiming **$93.6\%$ of historical disk space** ($1,526.37\text{ KB}$ purged per 1,000 txs) bounds validating node disk growth to a flat, constant rate proportional only to account state and calldata.
* **Formal Trust & Archival Auditability Model:**
  * **Archival Node Tier:** Archival nodes do not execute pruning; they retain full historical witness blobs, serving them via P2P JSON-RPC (`eth_getRawTransactionWithWitness`) for off-chain compliance, dispute resolution, or legal verification.
  * **New Validator Sync:** Newly joining nodes perform state-sync via finalized weak subjectivity checkpoints (identical to the operational security model accepted by Ethereum EIP-4844 blob expiration and Bitcoin BIP-141). Alternatively, full-history archival sync can be requested from archival peers.

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

### Phase 7: Reviewer Calibration, Empirical Verification & Manuscript Alignment (Weeks 21–24) — IN PROGRESS / ADVANCED
* [x] **Week 21: Statistical Rigor & Unified Benchmarking Harness ($N=50$)** — COMPLETED
  * [x] Re-run all cryptographic benchmarks under identical Alder Lake hardware conditions ($N = 50$ iterations with 5 warmup iterations, reporting Mean $\pm$ StdDev and explicit 95% Confidence Intervals).
  * [x] Reconcile verification throughput across evaluation tiers:
    - *Tier 1 (Isolated Cryptographic Batch Verifier in `evaluate`)*: Falcon-512 achieves $64,766 \pm 3,158\text{ sigs/sec}$ ($15.48 \pm 0.87\text{ ms}$, 95% CI $[15.24, 15.72]\text{ ms}$).
    - *Tier 2 (Full Type 0x46 EVM Pipeline in `compare-evm`)*: Falcon-512 achieves $61,332 \pm 5,897\text{ sigs/sec}$ ($16.48 \pm 1.91\text{ ms}$, 95% CI $[15.95, 17.01]\text{ ms}$) vs. ECDSA secp256k1 at $50,405 \pm 2,379\text{ sigs/sec}$ ($19.88 \pm 0.98\text{ ms}$).
    - *Delta Explanation*: The $\approx 3,400\text{ sigs/sec}$ delta is accounted for by Type 0x46 RLP byte slicing, dynamic buffer allocation, and Keccak-256 address hashing inside the timed execution region.
  * [x] Compute and report rigorous 95% Confidence Interval on the $1.22\times$ speedup ratio: $1.22 \pm 0.04\times$ ($95\% \text{ CI } [1.17\times, 1.26\times]$ via Delta Method).
  * [x] Explicitly document underlying cryptographic libraries: `pqcrypto-falcon` v0.4 (`liboqs` C backend with AVX2 integer NTT vectorization) and `secp256k1` v0.29 (Bitcoin Core / Ethereum Foundation C reference implementation `libsecp256k1`).
* [x] **Week 22: Network Modeling, Live Socket Testbed & Wire Trade-Off Analysis** — COMPLETED
  * [x] Accurately delineate network evaluation tiers:
    - *Analytical WAN Model*: Formalized as $T_{\text{prop}} = \text{RTT} + \frac{\text{Block Size}}{\text{Bandwidth}}$. Over 100 Mbps WAN with 100 ms RTT, unpruned 1,000-tx blocks require **$233.60\text{ ms}$** vs **$108.80\text{ ms}$** for classical blocks.
    - *Live Socket Testbed*: Measured TCP/IP transit across live loopback sockets ($N = 50$). Sub-millisecond transit times ($0.37 \pm 0.01\text{ ms}$ pruned vs $0.61 \pm 0.04\text{ ms}$ classical) reflect serialization buffer sizes and Linux kernel socket buffer scheduling.
  * [x] Prominently highlight the consensus wire reality: Freshly proposed blocks travel with full witnesses, incurring a **$2.15\times$ propagation overhead** ($233.6\text{ ms}$ vs $108.8\text{ ms}$), establishing the genuine wire cost of post-quantum security.
  * [x] Formalize the PoA finality assumption: Blocks at confirmation depth $k > 100$ are irreversibly finalized under the honest-majority validator assumption ($> 2/3 |\mathcal{V}|$). Retrospective pruning reclaims $93.6\%$ disk bloat on validating nodes, shifting long-term historical proof archival onto archival nodes or weak subjectivity sync.
* [x] **Week 23: EVM Gas Calibration, Account Abstraction & Storage Slot Deconstruction** — COMPLETED
  * [x] Implement and compile classical ECDSA AA wallet (`EcdsaAccountAbstraction.sol`) and post-quantum Falcon AA wallet (`FalconAccountAbstraction.sol`).
  * [x] Empirically benchmark `executeUserOp` gas on `revm`: Classical ECDSA consumes **$91,768\text{ gas}$**; Falcon-512 consumes **$162,956\text{ gas}$** (delta: **$+71,188\text{ gas}$**).
  * [x] Deconstruct the $+71,188\text{ gas}$ delta with opcode-level precision:
    - *Calldata Transmission*: $+23,968\text{ gas}$ ($1,498\text{ B}$ non-zero difference in userOp payload @ 16 gas/byte).
    - *Storage Slot Reads (`SLOAD`)*: $+44,220\text{ gas}$. In `FalconAccountAbstraction`, the 897-byte public key is stored in contract state, spanning $\lceil 897 / 32 \rceil = 29$ storage slots. Reading the key via `abi.encodePacked` triggers 29 `SLOAD` operations and array iteration, compared to 1 single slot for ECDSA `address public owner`.
    - *System Recommendation*: Store $\text{keccak256}(pk)$ (1 slot, $2,100\text{ gas}$) in contract storage, and pass the 897-byte public key dynamically in calldata to eliminate the 28 unnecessary `SLOAD` operations.
    - *Dispatch Overhead*: $+3,000\text{ gas}$ precompile execution.
  * [x] Derive the $+4,000\text{ gas}$ intrinsic surcharge: Compensates for decoding 897-byte public key and 666-byte signature, computing 897-byte Keccak-256 address derivation ($204\text{ gas}$), and executing AVX2 integer NTT polynomial verification ($\approx 3,000\text{ gas}$ compute cycle parity).
  * [x] Align precompile calibration ($3,000\text{ gas}$) with EIP-8052 (Dubois et al., Oct 2025: $1,000\text{ gas}$ hash-to-point + $2,000\text{ gas}$ core verify) and classical `ecrecover` ($3,000\text{ gas}$).
  * [x] Document the source of interpreted bytecode verification: Standalone EVM bytecode polynomial NTT multiplication and rejection sampling consumes $2.4\text{M}$ to $5.8\text{M gas}$ ($\approx 3.8\text{M gas}$ benchmark mean).
* [x] **Week 24: Threat Model Formalization, Complete Literature Citations & Manuscript Alignment** — COMPLETED
  * [x] Delineate implemented layers (Layer 1 Type 0x46 envelope, Layer 4 Precompile `0x15` in `revm`, Dual-Root Consensus) from planned roadmap layers (Layer 2 Falcon PoA attestations, Layer 3 Kyber TLS 1.3 handshakes).
  * [x] Formalize hardness classifications: Correctly categorize Falcon-512 as NTRU lattice shortest vector problem (SVP/SIS) achieving NIST Security Level 1 (not "128-bit quantum security"), and ML-DSA as Module-SIS/LWE.
  * [x] Clarify quantum collision security: 20-byte address derivation provides $80\text{-bit}$ classical collision security, and $\approx 2^{53.3}$ quantum collision resistance under BHT *only assuming large-scale fault-tolerant QRAM*; under standard Grover second-preimage search, security remains at $2^{80}$.
  * [x] Specify draft FIPS 206 FN-DSA changes: Salt sampling inside rejection loop and public key hashing into digest ($c = H(r \parallel m \parallel H(pk))$), breaking binary compatibility with original Falcon. Explicitly report validation against draft FIPS 206 KAT test vectors.
  * [x] Correct all academic citations: Babbush et al. (2026, arXiv:2603.28846 / ePrint 2026/625), Dubois et al. (EIP-8052, Oct 2025), EIP-7592, EIP-7619, ZKNOX, STARK aggregation, Bernstein et al. (2012), Ducas et al. (2018), and Wood (2014).
  * [x] Fix stylistic items: Remove "Preprint submitted to Elsevier", confirm institutional affiliation, provide repository link, fix typos ("succinct"), replace "establish" with "estimate", and eliminate unsupported queuing assumptions. Ensure `paper/paper.pdf` strictly maintains its 6-page double-column format.

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

We evaluate cryptographic signature verification throughput across batch sizes of $100$, $500$, and $1,000$ signatures using the Rayon parallel work-stealing pool across 12 logical threads on Intel Core i5-12400 (Alder Lake, AVX2 SIMD acceleration) across $N = 50$ measured trials (with 5 warmup iterations):

| Batch Size | Ed25519 (Control) | Falcon-512 (Draft FIPS 206) | ML-DSA-44 (NIST FIPS 204) |
| :---: | :---: | :---: | :---: |
| **100 txs** | $40,167 \pm 4,822\text{ sigs/s}$ ($2.53 \pm 0.34\text{ ms}$) | **$62,455 \pm 4,087\text{ sigs/s}$** ($1.61 \pm 0.12\text{ ms}$) | **$66,712 \pm 9,732\text{ sigs/s}$** ($1.55 \pm 0.34\text{ ms}$) |
| **500 txs** | $44,124 \pm 3,803\text{ sigs/s}$ ($11.42 \pm 1.03\text{ ms}$) | **$63,978 \pm 1,690\text{ sigs/s}$** ($7.82 \pm 0.22\text{ ms}$) | **$76,699 \pm 5,296\text{ sigs/s}$** ($6.55 \pm 0.49\text{ ms}$) |
| **1,000 txs** | $48,654 \pm 1,913\text{ sigs/s}$ ($20.58 \pm 0.82\text{ ms}$) | **$64,766 \pm 3,158\text{ sigs/s}$** ($15.48 \pm 0.87\text{ ms}$) | **$79,929 \pm 2,852\text{ sigs/s}$** ($12.53 \pm 0.47\text{ ms}$) |

*Evaluation Frameworks & Timed Region Definitions:*
1. **Isolated Batch Verifier vs. Full EVM Pipeline:** In Table 2 (above, generated by `qr-dlt-node evaluate`), Falcon-512 processes raw in-memory parsed signatures at **$64,766 \pm 3,158\text{ sigs/sec}$** ($15.48\text{ ms}$ per 1,000 txs). In contrast, Table 3 and the abstract report **$61,332 \pm 5,897\text{ sigs/sec}$** ($16.48\text{ ms}$ per 1,000 txs), generated by the comprehensive `compare-evm` harness. This $\approx 3,400\text{ sigs/sec}$ ($1.00\text{ ms}$) difference accounts for the full Type 0x46 EVM pipeline: RLP envelope byte slicing, dynamic vector allocations, and Keccak-256 address hashing ($\text{keccak256}(pk)[12..31]$) within the timed execution window.
2. **Statistical Rigor & Confidence Intervals:** Across $N = 50$ iterations, the standard error of the mean is $\text{SE} = \frac{\text{SD}}{\sqrt{50}} \approx 0.141 \times \text{SD}$, and the 95% Confidence Interval half-width is $t_{0.025, 49} \cdot \text{SE} \approx 2.01 \cdot 0.141 \cdot \text{SD} \approx 0.284 \times \text{SD}$. For Falcon-512 at 1,000 txs in `compare-evm`, the 95% CI is $16.48 \pm 0.53\text{ ms}$ ($[15.95, 17.01]\text{ ms}$).
3. **Libraries Used:** Falcon-512 is implemented via `pqcrypto-falcon` v0.4 (wrapping C `liboqs` with AVX2 integer NTT assembly); ECDSA secp256k1 is implemented via `secp256k1` v0.29 (wrapping C `libsecp256k1`).
4. **Verification Speed vs. Payload Size:** ML-DSA-44 verifies slightly faster than Falcon-512 ($79,929\text{ sigs/s}$ vs. $64,766\text{ sigs/s}$) because ML-DSA operates entirely over $32\text{-bit}$ integer modular arithmetic in $\mathbb{Z}_q$, mapping natively into AVX2 integer registers without Falcon's Fast Fourier polynomial decompression. However, Falcon-512 wins decisively on payload size ($1,563\text{ B}$ vs $3,732\text{ B}$), making Falcon far superior for network gossip and block serialization.
5. **Throughput Definition:** These figures measure **cryptographic signature verification throughput (signatures/sec)** in the parallel Rayon admission gate. End-to-end blockchain transaction throughput is bound by sequential EVM state execution, account nonce checks, and Merkle Patricia Trie disk persistence to $\approx 1,500\text{--}2,500\text{ TPS}$.

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

*Analysis:* Storing unpruned lattice witnesses would bloat node disks by $\approx 1.53\text{ MB}$ per 1,000 Falcon transactions. Epoch pruning bounds disk growth on validating nodes to a constant function of transaction execution state, reclaiming **$93.6\%$ of historical disk space** ($1,526.37\text{ KB}$ purged per 1,000 txs) for Falcon-EVM while preserving auditability via the 32-byte header commitment.

### 8.4 Head-to-Head Comparative Evaluation: Falcon-EVM vs. Normal EVM (secp256k1 Baseline)

Using our bare-metal benchmarking framework (`qr-dlt-node compare-evm`), we conducted a head-to-head empirical evaluation between **Falcon-EVM** (EIP-2718 Type `0x46` envelope, native `0x15` precompile, dual-root SegWit pruning) and **Normal EVM** (standard ECDSA secp256k1 baseline via `libsecp256k1`) across $N = 50$ measured trials:

| Dimension | Normal EVM ($\text{secp256k1}$ Baseline) | Falcon-EVM (QR-DLT Sovereign) | Empirical Quantitative Impact |
| :--- | :---: | :---: | :---: |
| **Transaction Wire Footprint** | $110\text{ B}$ (Signature $65\text{ B}$, PubKey recovered) | $1,670\text{ B}$ (PubKey $897\text{ B}$, Sig $666\text{ B}$) | **$15.18\times$ "Lattice Tax"** on wire |
| **Parallel Verification Speed** | $50,405 \pm 2,379\text{ sigs/s}$ ($19.88 \pm 0.98\text{ ms}$) | **$61,332 \pm 5,897\text{ sigs/s}$** ($16.48 \pm 1.91\text{ ms}$) | **$1.22 \pm 0.04\times$ Speedup** ($95\%\text{ CI } [1.17, 1.26]$) |
| **Block Size (1,000 Transactions)** | $107.42\text{ KB}$ | $1,630.86\text{ KB}$ (Unpruned) / **$104.49\text{ KB}$ (Pruned)** | $1,526.37\text{ KB}$ purged after epoch depth $k > 100$ |
| **WAN Delay Model (100 Mbps, 100ms)** | $108.80\text{ ms}$ (Analytical model) | $233.60\text{ ms}$ (Unpruned) / **$108.56\text{ ms}$ (Pruned)** | Fresh blocks carry witnesses ($2.15\times$ slower); pruned sync matches classical |
| **Live P2P Socket Transit ($N=50$)** | $0.61 \pm 0.04\text{ ms}$ (Loopback socket) | $5.43 \pm 0.57\text{ ms}$ (Unpruned) / **$0.37 \pm 0.01\text{ ms}$ (Pruned)** | $93.1\%$ socket transit reduction on pruned payloads |
| **Base Intrinsic Gas** | $21,000\text{ gas}$ | $25,000\text{ gas}$ ($21\text{k base} + 4\text{k Falcon verify}$) | $+19.0\%$ intrinsic base reflecting admission verification |
| **Precompile Execution Gas** | $3,000\text{ gas}$ (`ecrecover` `0x01`) | $3,000\text{ gas}$ (`falcon512` `0x15`) | **Exact CPU parity**; calldata adds $+25,520\text{ gas}$ for 1.59 KB input |
| **On-Chain Total Verify Gas** | $4,552\text{ gas}$ (3k precompile + 1.55k calldata) | $\mathbf{28,520\text{ gas}}$ (3k precompile + 25.5k calldata) | Reflects transparent $1,595\text{ B}$ calldata ingestion |
| **ERC-4337 AA UserOp Gas** | $\mathbf{91,768\text{ gas}}$ (`EcdsaAccountAbstraction`) | $\mathbf{162,956\text{ gas}}$ (`FalconAccountAbstraction`) | $+71,188\text{ gas}$ delta ($+24\text{k calldata}$, $+44\text{k storage reads}$, $+3\text{k dispatch}$) |
| **Storage Bloat Reclamation** | $0.0\%$ (Signatures permanent in RLP state) | $\mathbf{93.6\%}$ Reclaimed ($1,526.37\text{ KB}$ purged / 1k txs) | Pruned historical storage matches classical footprint |
| **Quantum Threat Hardness** | Broken by Shor's algo ($1,200\text{--}1,450$ qubits) | **Computationally Hard** (NTRU lattice SVP/SIS) | Inapplicable to Shor's algorithm (NIST Security Level 1) |

*Opcode-Level Gas Deconstruction for ERC-4337 Smart Wallets:*
Our empirical measurement of $162,956\text{ gas}$ (Falcon) vs $91,768\text{ gas}$ (ECDSA) yields an exact $+71,188\text{ gas}$ delta:
1. **Calldata Expansion ($+23,968\text{ gas}$):** The Falcon UserOperation transmits an 897-byte public key and 666-byte signature ($1,563\text{ B}$ non-zero witness) vs $65\text{ B}$ for ECDSA, incurring $1,498 \times 16 = 23,968\text{ gas}$.
2. **Storage Slot Overhead ($+44,220\text{ gas}$):** In `FalconAccountAbstraction.sol`, the 897-byte public key is stored in contract state, spanning $\lceil 897 / 32 \rceil = 29$ storage slots. Reading this key during `executeUserOp` to prepare precompile input requires 29 `SLOAD` operations and array copying loops, compared to 1 single `SLOAD` for ECDSA `address public owner`. In optimized production implementations, the contract should store only `keccak256(pk)` (1 slot, $2,100\text{ gas}$) and supply the 897-byte public key in calldata, eliminating this $+44,220\text{ gas}$ penalty.
3. **Dispatch & Precompile Execution ($+3,000\text{ gas}$):** Staticcall dispatch into precompile `0x15`.

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
    • Derives Sender Address: keccak256(pk)[12..31]
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
     * Precompile execution is calibrated to $3,000\text{ gas}$, matching the cycle interpolation of EIP-8052 ($1,000\text{ gas}$ hash-to-point $+ 2,000\text{ gas}$ core verify) and `ecrecover` CPU execution parity.
     * Passing $1,595\text{ bytes}$ of non-zero calldata into the contract incurs standard EVM calldata costs ($\approx 16\text{ gas/byte} \approx 25,520\text{ gas}$), totaling $\approx 28,520\text{ gas}$ for on-chain contract calls.
   * **Bytecode Baseline:** Interpreting iterative polynomial NTT loops in un-precompiled Solidity bytecode consumes upwards of $2.4\text{M--}5.8\text{M gas}$ (with an empirical benchmark mean of $\approx 3.8\text{M gas}$), confirming that native precompiles are strictly indispensable.

3. **EIP-2718 Type `0x46` Falcon Transaction Envelope:**
   * Standard Ethereum transactions rely on ECDSA public key recovery (`ecrecover`). Because Falcon does not support recovery from signature alone, Type `0x46` explicitly carries the 897-byte public key alongside the signature:
     $$\text{FalconTx} = 0x46 \,\|\, \text{rlp}([ \text{chainId}, \text{nonce}, \text{maxPriorityFee}, \text{maxFee}, \text{gasLimit}, \text{to}, \text{value}, \text{data}, \text{accessList}, \text{falconPubKey}, \text{falconSig} ])$$
   * **Address Derivation:** Evaluated via $\text{Address} = \text{keccak256}(\text{falcon\_public\_key})[12..31]$, preserving 20-byte EVM address interoperability.
   * **Intrinsic Gas Formula:** $21,000 \text{ base} + \text{calldata gas} + \text{Falcon verification intrinsic gas } (\approx 4,000\text{ gas})$, directly reflecting envelope decoding, 897-byte address derivation ($204\text{ gas}$), and AVX2 NTT polynomial verification compute cycles.

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

* **Control Group (Normal EVM):** Standard Reth / Anvil instance executing classical ECDSA $\text{secp256k1}$ transactions via `libsecp256k1`.
* **Experimental Group (Falcon-EVM):** Sovereign QR-EVM node executing Falcon-512 Type `0x46` transactions with native precompile `0x15` and SegWit epoch pruning.

#### Head-to-Head Evaluation Matrix

| Metric | Normal EVM Chain (ECDSA Baseline) | Falcon-EVM Chain (Falcon-512) | Research Hypothesis / Systems Impact |
| :--- | :--- | :--- | :--- |
| **Cryptographic Scheme** | ECDSA ($\text{secp256k1}$) | Falcon-512 (Draft FIPS 206 / FN-DSA) | Full quantum resilience against Shor's discrete logarithm attack (NIST Security Level 1). |
| **Transaction Wire Footprint** | $\approx 110\text{ bytes}$ | $\approx 1,670\text{ bytes}$ | Falcon transactions are $\approx 15.2\times$ larger due to explicit 897-byte public key. |
| **Public Key Derivation** | Recovered on-the-fly (`ecrecover`) | Explicitly provided in envelope ($897\text{ B}$) | Eliminates malleability; requires SegWit pruning to prevent state bloat. |
| **Parallel Batch Verification TPS** | $50,405 \pm 2,379\text{ sigs/s}$ | $\mathbf{61,332 \pm 5,897\text{ sigs/s}}$ | **$1.22 \pm 0.04\times$ Speedup**: Falcon NTT verification maps onto AVX2 SIMD, beating ECC scalar multiplication. |
| **Block Propagation under WAN Delay** | $108.80\text{ ms}$ ($t_0$) | $233.60\text{ ms}$ ($2.15\times$, Unpruned) vs $108.56\text{ ms}$ (Pruned sync) | Fresh blocks carry witnesses ($2.15\times$ slower on wire); pruned sync matches classical wire latency. |
| **Smart Contract Verification Cost** | $3,000\text{ gas}$ (`ecrecover` `0x01`) | $3,000\text{ gas}$ (Precompile `0x15`) vs $\approx 3.8\text{M gas}$ (Solidity) | Precompile achieves CPU execution parity; calldata adds $+25,520\text{ gas}$. |
| **Disk State Bloat per 100k Transactions** | $\approx 11\text{ MB}$ | **$\approx 10.5\text{ MB}$** (Pruned) vs $163\text{ MB}$ (Unpruned) | Epoch pruning achieves storage parity with classical EVM chains ($93.6\%$ reclaimed). |
| **Quantum Attack Surface** | **Vulnerable** (CRQC breaks key offline) | **Secure** (NTRU lattice SVP/SIS hardness) | Eliminates Shor's algorithm collapse for both at-rest and in-flight transactions. |

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
| **Draft FIPS 206 FN-DSA parameter & format drift** | Medium (Interoperability failure) | Draft FIPS 206 modifies salt sampling and introduces public-key hashing into the digest ($c = H(r \parallel m \parallel H(pk))$), breaking binary compatibility with original Falcon (2018). Mitigate by validating against official draft FIPS 206 KAT test vectors. |
| **20-byte address collision margins under quantum search** | Medium (Address collision) | 20-byte addresses provide 80-bit classical collision resistance and $\approx 53.3$-bit quantum collision security (BHT algorithm) only under the assumption of large fault-tolerant QRAM. Under standard Grover second-preimage search, security remains at $2^{80}$. For long-term 128-bit quantum security, plan migration to 32-byte addresses (`keccak256(pk)[0..31]`). |
| **Excessive block propagation delay due to PQC key size** | Medium (Elevated orphan rates) | Fresh blocks carry witnesses ($2.15\times$ wire overhead); mitigate via compact block relay (BIP 152 style) where transactions verified in mempool are referenced by compact IDs. |
| **Prohibitive EVM calldata gas costs for Falcon signatures** | High (Adoption barrier) | Calldata costs $\approx 25,520\text{ gas}$ for 1.59 KB. Mitigate via native precompile `0x15` ($3,000\text{ gas}$ execution) and detached sidecar proofs in future EIP-4844-style blobs. |
| **Smart wallet storage bloat from public key persistence** | Medium (Gas overhead) | Storing an 897-byte public key in contract state requires 29 storage slots ($+44,220\text{ gas}$ in `SLOAD` operations). Mitigate by storing `keccak256(pk)` (1 slot, $2,100\text{ gas}$) in contract storage and passing the public key dynamically in calldata. |
| **Historical sync degradation on pruned validating nodes** | Low (Sync dependency) | Pruned nodes retain only the 32-byte `witness_root`; newly joining validators sync via weak subjectivity checkpoints or fetch historical witness blobs from dedicated archival nodes. |
| **Research novelty deemed incremental by reviewers** | Medium (Journal rejection) | Explicitly position against EIP-8052, EIP-7592, EIP-7619, and ZKNOX; emphasize that QR-DLT provides the first comprehensive end-to-end sovereign EVM chain with dual-root SegWit epoch pruning and empirical multi-node benchmarking. |


