# Quantum-Resilient Distributed Ledger (QR-DLT)

**Systems Optimization and Empirical Evaluation of Lattice-Based Digital Signatures in a From-Scratch Rust Blockchain Architecture**

**Principal Investigators:** Bashar Khan & Zaheer Khan  
**Target Environment:** Bare-Metal Linux (Ubuntu 22.04/24.04 LTS or WSL2) on Intel Core i5 (12th Gen Alder Lake, AVX2/BMI2/SHA-NI), 16 GB RAM.

---

## Overview

Contemporary distributed ledgers rely on classical elliptic curve cryptography ($\text{ECDSA}$, $\text{Ed25519}$), which will collapse completely under Shor's algorithm on Fault-Tolerant Quantum Computers. Post-quantum cryptographic standards (NIST FIPS 206 Falcon-512 and NIST FIPS 204 ML-DSA-44) provide quantum security, but introduce a severe **"Lattice Tax"**: keys and signatures are $16\times$ to $40\times$ larger ($1.5\text{ KB}$ to $3.7\text{ KB}$ vs. $96\text{ B}$ for Ed25519), causing severe P2P wire saturation, cache trashing, and disk state bloat.

**QR-DLT** is a high-performance, modular distributed ledger built from the ground up in Rust to evaluate and solve these systems-level bottlenecks through:
1. **Decoupled Segregated Witness Architecture:** Transaction state mutation intents (`TxIntent`, $\approx 60\text{ bytes}$) are segregated from heavy cryptographic proofs (`WitnessProof`).
2. **Dual-Root Block Commitments:** Block headers commit to both an `Intent Merkle Root` and a `Witness Merkle Root` via domain-separated BLAKE3 trees.
3. **Epoch-Based Witness Pruning:** Full nodes verify post-quantum signatures during consensus, but purge raw witness proofs past an epoch confirmation threshold ($k$ blocks), reclaiming **$98.3\%$ of ledger disk storage** while maintaining permanent 32-byte vector commitment auditability.
4. **Parallel Batch Verifier:** A work-stealing `Rayon` thread pool with hardware AVX2 acceleration achieving **$>34,000\text{ TPS}$ for ML-DSA-44** and **$>20,000\text{ TPS}$ for Falcon-512** on bare-metal CPUs.
5. **Decoupled Tokio P2P Gossip & PoA Consensus:** Asynchronous TCP framing routing compact transaction intents over a fast path and synchronizing heavy blocks across a 4-node local cluster.

---

## Workspace Architecture

The workspace is organized into 7 modular member crates:

```
qr-dlt/
├── Cargo.toml                  # Workspace manifest
├── benches/
│   ├── crypto_bench.rs         # Criterion microbenchmarks: Ed25519 vs Falcon vs ML-DSA
│   └── block_validation.rs     # Parallel batch verification scaling (100 to 1,000 txs)
├── crates/
│   ├── crypto/                 # Agnostic traits, Ed25519, Falcon-512, ML-DSA-44, BLAKE3 address
│   ├── types/                  # TxIntent, WitnessProof, BlockHeader, Block, BLAKE3 Merkle trees
│   ├── storage/                # sled transactional KV store, account ledger, epoch pruner
│   ├── mempool/                # Nonce/solvency admission filtering & Rayon batch verifier
│   ├── consensus/              # Deterministic round-robin Proof-of-Authority (PoA)
│   ├── network/                # Async Tokio P2P gossip engine & length-delimited framing
│   └── node/                   # Unified CLI node binary (qr-dlt-node), metrics profiler
└── scripts/
    ├── run_local_cluster.sh    # Spawns 4-node local devnet (ports 8001..8004)
    ├── simulate_latency.sh     # Injects WAN latency & packet loss via Linux 'tc netem'
    ├── generate_flamegraph.sh  # Generates CPU cache & flamegraph profiles
    └── plot_results.py         # Generates publication-ready vector charts (SVG)
```

---

## Prerequisites

Before testing locally, verify your system dependencies:

### 1. System Packages
```bash
# Ubuntu / Debian
sudo apt-get update
sudo apt-get install -y build-essential cmake pkg-config python3
```

### 2. Rust Toolchain
Ensure the Rust toolchain (Rust 2024 edition supported, 1.85+) is installed:
```bash
rustc --version
cargo --version
```

### 3. Hardware AVX2 Support
Check if your CPU supports hardware AVX2 vector extensions:
```bash
lscpu | grep -i avx2
```

---

## Local Testing & Verification Guide

Follow these sequential steps to test all components locally:

### Step 1: Run the Full Workspace Test Suite

Execute all unit and integration tests across all 7 workspace crates:

```bash
cargo test --workspace
```

**Expected Result:** 17 tests passed (0 failed, 0 warnings):
* `qr_dlt_crypto`: Keygen, signing, verification, tamper rejection, and BLAKE3 address derivation for all 3 schemes.
* `qr_dlt_types`: Dual Merkle root commitments, vector inclusion proofs, and pruned block conversions.
* `qr_dlt_storage`: Account debit/credit state transitions, block persistence, and epoch pruning.
* `qr_dlt_mempool`: Nonce sequence filtering, solvency validation, and Rayon parallel batch verifier.
* `qr_dlt_consensus`: Round-robin Proof-of-Authority slot assignment and out-of-turn proposer rejection.
* `qr_dlt_network`: Tokio TCP socket loopback broadcast and frame decoding.

---

### Step 2: Generate Post-Quantum Keypairs via CLI

Use the node CLI to generate classical and post-quantum keypairs:

```bash
# Classical Ed25519 baseline
cargo run -p qr-dlt-node -- keygen --scheme ed25519

# NIST FIPS 206 Falcon-512
cargo run -p qr-dlt-node -- keygen --scheme falcon512

# NIST FIPS 204 ML-DSA-44
cargo run -p qr-dlt-node -- keygen --scheme ml-dsa44
```

**Sample Output:**
```
==================================================
  QR-DLT Cryptographic Keypair Generated
==================================================
Scheme:       Falcon-512
Address:      0xfc0dd0c13a6afffd6a99e06ef01d293ec581182f
Public Key:   0x0911... (897 bytes)
Expected Sig: 666 bytes
==================================================
```

---

### Step 3: Run Standalone Synthetic Block Validation

Benchmark block assembly, payload metrics, and parallel verification throughput:

```bash
# Benchmark ML-DSA-44 with a 1,000-transaction block
cargo run -p qr-dlt-node -- bench-block --scheme ml-dsa44 --tx-count 1000

# Benchmark Falcon-512 with a 1,000-transaction block
cargo run -p qr-dlt-node -- bench-block --scheme falcon512 --tx-count 1000
```

**Output will report:**
* Intent Payload vs. Witness Payload size
* Witness overhead percentage ($>96\%$ to $98\%$)
* Parallel batch verification duration and transactions per second ($\text{TPS}$)
* Process Resident Set Size memory ($\text{RSS MB}$)

---

### Step 4: Run the Empirical Evaluation Suite & Generate Academic Charts

Run the automated evaluation suite that measures the Lattice Tax, batch verification scaling (100, 500, 1,000 txs), and epoch-based witness pruning:

```bash
# 1. Run evaluation suite and export JSON metrics
cargo run -p qr-dlt-node -- evaluate --output-file empirical_results.json --max-batch 1000

# 2. Generate publication-ready vector charts (SVG)
python3 scripts/plot_results.py empirical_results.json
```

**Generated Visualizations:**
* `figure1_crypto_payloads.svg`: Cryptographic payload overhead comparison (The Lattice Tax).
* `figure2_batch_throughput.svg`: Parallel batch verification scaling across batch sizes.
* `figure3_storage_pruning.svg`: Visual breakdown of raw witness payload vs. retained intent state.

---

### Step 5: Launch the 4-Node Local Consensus Devnet

Spawn 4 local validating nodes on loopback (`127.0.0.1:8001..8004`) with isolated storage directories:

```bash
# Run cluster in foreground (press Ctrl+C to stop)
./scripts/run_local_cluster.sh

# Or run for a fixed duration (e.g. 10 seconds)
./scripts/run_local_cluster.sh --duration 10
```

**Nodes Initialized:**
* **Node 1 (`127.0.0.1:8001`):** Ed25519 Bootstrap Validator
* **Node 2 (`127.0.0.1:8002`):** Falcon-512 Validator
* **Node 3 (`127.0.0.1:8003`):** ML-DSA-44 Validator
* **Node 4 (`127.0.0.1:8004`):** Falcon-512 Pruned Validator (prune depth: 50 blocks)

To inspect live peer logs:
```bash
tail -f data/cluster/node1/node.log
tail -f data/cluster/node2/node.log
```

---

### Step 6: Emulate Real-World WAN Latency & Packet Loss

Simulate realistic cross-continental WAN network delays using Linux `tc netem`:

```bash
# Inject 100ms latency and 0.5% packet loss on loopback
sudo ./scripts/simulate_latency.sh --delay 100ms --loss 0.5%

# Clear traffic shaping rules after testing
sudo ./scripts/simulate_latency.sh --clear
```

---

### Step 7: Run Criterion Microbenchmarks

Run microsecond-accurate microbenchmarks with native CPU optimizations:

```bash
# Benchmark KeyGen, Sign, and Verify for Ed25519 vs Falcon-512 vs ML-DSA-44
RUSTFLAGS="-C target-cpu=native" cargo bench --bench crypto_bench

# Benchmark batch verification scaling across 100 to 1,000 transactions
RUSTFLAGS="-C target-cpu=native" cargo bench --bench block_validation
```

---

### Step 8: CPU Cache & Flamegraph Profiling

Analyze memory bandwidth stalls and CPU hotspots during batch verification:

```bash
# Profile Falcon-512 batch verification with 2,000 transactions
./scripts/generate_flamegraph.sh falcon512 2000

# Profile ML-DSA-44 batch verification with 2,000 transactions
./scripts/generate_flamegraph.sh ml-dsa44 2000
```
This generates an interactive SVG flamegraph (`flamegraph_*.svg`) identifying CPU instruction bottlenecks.

---

## Empirical Benchmark Summary

Key empirical results recorded on local bare-metal Intel Core i5 Alder Lake:

### 1. The Lattice Tax (Cryptographic Overhead)
* **Ed25519:** Public Key: $32\text{ B}$, Signature: $64\text{ B}$ $\rightarrow$ **$96\text{ B}$ ($1.0\times$)**
* **Falcon-512:** Public Key: $897\text{ B}$, Signature: $666\text{ B}$ $\rightarrow$ **$1,563\text{ B}$ ($16.3\times$)**
* **ML-DSA-44:** Public Key: $1,312\text{ B}$, Signature: $2,420\text{ B}$ $\rightarrow$ **$3,732\text{ B}$ ($38.9\times$)**
* **Block Payload Share:** In ML-DSA-44, witness proofs account for **$98.3\%$ of total block bytes**.

### 2. Parallel Batch Verification Throughput (1,000 txs)
* **ML-DSA-44:** **$34,662\text{ TPS}$** ($28.85\text{ ms}$)
* **Falcon-512:** **$20,402\text{ TPS}$** ($49.02\text{ ms}$)
* **Ed25519:** **$501\text{ TPS}$** ($1,994.87\text{ ms}$, unvectorized scalar curve)

### 3. Epoch-Based Storage Reclamation
* **Raw Witness Payload (500 txs):** $1,832.03\text{ KB}$
* **Retained Intent State:** $31.25\text{ KB}$
* **Reclaimed Disk Storage:** **$98.3\%$ space reduction** while preserving the 32-byte header commitment root.

---

## Future Scope: Falcon EVM Indexer & Transition

* **Falcon EVM Indexer:** A high-throughput Rust indexer ingesting EVM blocks and decoupled Falcon-512 signatures via an auxiliary PQC sidecar / ERC-4337 bundler.
* **Comparative Transition Analysis:** Benchmarking against local EVM nodes (`Anvil` / `Reth`) to measure state transition latency, calldata gas costs ($16\text{ gas/byte}$), precompile vs. smart contract verification, and mempool quantum front-running resistance under simulated WAN latency.

---

## License

MIT OR Apache-2.0
