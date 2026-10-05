mod cli;
mod metrics;

use anyhow::Result;
use clap::Parser;
use cli::{Cli, Commands, SchemeArg};
use metrics::ProcessMetrics;
use qr_dlt_crypto::{
    generate_keypair, CryptoScheme, CryptoSigner, Ed25519Signer, Falcon512Signer, MlDsa44Signer,
};
use qr_dlt_mempool::{BatchVerifier, Mempool};
use qr_dlt_network::{NetworkMessage, P2pService};
use qr_dlt_storage::LedgerStore;
use qr_dlt_types::{Block, Transaction, TxIntent, WitnessProof};
use serde::Serialize;
use std::fs;
use std::sync::Arc;
use std::time::{Instant, SystemTime, UNIX_EPOCH};
use tracing::{info, Level};
use tracing_subscriber::FmtSubscriber;

#[derive(Serialize)]
struct EmpiricalReport {
    timestamp: u64,
    system: String,
    schemes: Vec<SchemeInfo>,
    batch_scaling: Vec<ScalingEntry>,
    pruning: PruningEvaluation,
}

#[derive(Serialize)]
struct SchemeInfo {
    name: String,
    public_key_bytes: usize,
    signature_bytes: usize,
    witness_total_bytes: usize,
    lattice_tax_multiplier: f64,
}

#[derive(Serialize)]
struct ScalingEntry {
    scheme: String,
    batch_size: usize,
    verification_time_ms: f64,
    throughput_tps: f64,
}

#[derive(Serialize)]
struct PruningEvaluation {
    blocks_evaluated: usize,
    txs_per_block: usize,
    total_txs: usize,
    unpruned_witness_bytes: usize,
    retained_intent_bytes: usize,
    reclaimed_space_percent: f64,
}

fn generate_batch(scheme: CryptoScheme, count: usize) -> Vec<Transaction> {
    let mut txs = Vec::with_capacity(count);
    for _i in 0..count {
        let signer: Box<dyn CryptoSigner> = match scheme {
            CryptoScheme::Ed25519 => Box::new(Ed25519Signer::generate()),
            CryptoScheme::Falcon512 => Box::new(Falcon512Signer::generate()),
            CryptoScheme::MlDsa44 => Box::new(MlDsa44Signer::generate()),
        };

        let intent = TxIntent {
            nonce: 1,
            sender_address: signer.address(),
            recipient_address: [9u8; 20],
            amount: 100,
            fee: 1,
        };

        let intent_hash = intent.hash();
        let sig = signer.sign(&intent_hash).unwrap();
        let witness = match scheme {
            CryptoScheme::Ed25519 => WitnessProof::Ed25519 {
                public_key: signer.public_key_bytes().try_into().unwrap(),
                signature: sig.try_into().unwrap(),
            },
            CryptoScheme::Falcon512 => WitnessProof::Falcon512 {
                public_key: signer.public_key_bytes(),
                signature: sig,
            },
            CryptoScheme::MlDsa44 => WitnessProof::MlDsa44 {
                public_key: signer.public_key_bytes(),
                signature: sig,
            },
        };

        txs.push(Transaction::new(intent, witness));
    }
    txs
}

#[tokio::main]
async fn main() -> Result<()> {
    let subscriber = FmtSubscriber::builder()
        .with_max_level(Level::INFO)
        .finish();
    let _ = tracing::subscriber::set_global_default(subscriber);

    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { scheme } => {
            let crypto_scheme = match scheme {
                SchemeArg::Ed25519 => CryptoScheme::Ed25519,
                SchemeArg::Falcon512 => CryptoScheme::Falcon512,
                SchemeArg::MlDsa44 => CryptoScheme::MlDsa44,
            };

            let signer = generate_keypair(crypto_scheme);
            let pk = signer.public_key_bytes();
            let addr = signer.address();

            println!("==================================================");
            println!("  QR-DLT Cryptographic Keypair Generated");
            println!("==================================================");
            println!("Scheme:       {}", crypto_scheme.name());
            println!("Address:      0x{}", hex::encode(addr));
            println!("Public Key:   0x{} ({} bytes)", hex::encode(&pk), pk.len());
            println!("Expected Sig: {} bytes", crypto_scheme.signature_len());
            println!("==================================================");
        }

        Commands::BenchBlock { scheme, tx_count } => {
            let crypto_scheme = match scheme {
                SchemeArg::Ed25519 => CryptoScheme::Ed25519,
                SchemeArg::Falcon512 => CryptoScheme::Falcon512,
                SchemeArg::MlDsa44 => CryptoScheme::MlDsa44,
            };

            println!("--- Generating synthetic batch of {} {} transactions ---", tx_count, crypto_scheme.name());
            let gen_start = Instant::now();
            let txs = generate_batch(crypto_scheme, tx_count);
            let gen_duration = gen_start.elapsed();
            println!("Batch generated in {:.3} ms", gen_duration.as_secs_f64() * 1000.0);

            // Assemble Block
            let block = Block::new([0u8; 32], 1, 1000, [0u8; 20], txs);

            let intent_bytes = bincode::serialize(&block.to_pruned()).unwrap().len();
            let total_block_bytes = bincode::serialize(&block).unwrap().len();
            let witness_bytes = total_block_bytes.saturating_sub(intent_bytes);

            println!("Block Payload Stats:");
            println!("  Total Block Size:      {:.2} KB", total_block_bytes as f64 / 1024.0);
            println!("  Intent Payload:        {:.2} KB", intent_bytes as f64 / 1024.0);
            println!("  Witness Proof Payload: {:.2} KB ({:.1}% of block)",
                     witness_bytes as f64 / 1024.0,
                     (witness_bytes as f64 / total_block_bytes as f64) * 100.0);

            // Batch Verification
            let verifier = BatchVerifier::new();
            let verify_start = Instant::now();
            verifier.verify_all(&block.transactions).expect("All signatures must verify");
            let verify_duration = verify_start.elapsed();

            let verify_ms = verify_duration.as_secs_f64() * 1000.0;
            let tps = tx_count as f64 / verify_duration.as_secs_f64();

            println!("Batch Verification Results:");
            println!("  Verification Time:     {:.3} ms", verify_ms);
            println!("  Throughput:            {:.0} tx/sec", tps);
            if let Some(rss) = ProcessMetrics::get_rss_mb() {
                println!("  Node Memory (RSS):     {:.2} MB", rss);
            }
        }

        Commands::Evaluate { output_file, max_batch } => {
            println!("============================================================");
            println!("  Executing QR-DLT Empirical Systems Evaluation Suite       ");
            println!("============================================================");

            // 1. Cryptographic Taxonomy & Overhead Evaluation
            let mut schemes_info = Vec::new();
            let ed_total = 32 + 64;
            for scheme in [CryptoScheme::Ed25519, CryptoScheme::Falcon512, CryptoScheme::MlDsa44] {
                let pk_len = scheme.public_key_len();
                let sig_len = scheme.signature_len();
                let total = pk_len + sig_len;
                let multiplier = total as f64 / ed_total as f64;

                println!("Scheme: {:<12} | PK: {:>4} B | Sig: {:>4} B | Total: {:>5} B | Lattice Tax: {:.1}x",
                         scheme.name(), pk_len, sig_len, total, multiplier);

                schemes_info.push(SchemeInfo {
                    name: scheme.name().to_string(),
                    public_key_bytes: pk_len,
                    signature_bytes: sig_len,
                    witness_total_bytes: total,
                    lattice_tax_multiplier: multiplier,
                });
            }

            // 2. Parallel Batch Verification Scaling
            println!("\n--- Benchmarking Batch Verification Scaling ---");
            let verifier = BatchVerifier::new();
            let mut scaling_entries = Vec::new();
            let batch_sizes: Vec<usize> = [100, 500, 1000]
                .iter()
                .filter(|&&s| s <= max_batch)
                .cloned()
                .collect();

            for &size in &batch_sizes {
                for scheme in [CryptoScheme::Ed25519, CryptoScheme::Falcon512, CryptoScheme::MlDsa44] {
                    print!("  Verifying {:<10} ({} txs)... ", scheme.name(), size);
                    let batch = generate_batch(scheme, size);

                    let start = Instant::now();
                    verifier.verify_all(&batch).expect("verification failed");
                    let elapsed = start.elapsed();

                    let ms = elapsed.as_secs_f64() * 1000.0;
                    let tps = size as f64 / elapsed.as_secs_f64();
                    println!("{:>8.2} ms | {:>7.0} tx/sec", ms, tps);

                    scaling_entries.push(ScalingEntry {
                        scheme: scheme.name().to_string(),
                        batch_size: size,
                        verification_time_ms: ms,
                        throughput_tps: tps,
                    });
                }
            }

            // 3. Epoch-Based Witness Pruning Efficiency
            println!("\n--- Evaluating Epoch-Based Witness Pruning ---");
            let store = LedgerStore::open_temporary()?;
            let num_blocks = 5;
            let txs_per_block = 100;
            let mut total_witness_bytes = 0;
            let mut total_intent_bytes = 0;

            for h in 1..=num_blocks {
                let batch = generate_batch(CryptoScheme::MlDsa44, txs_per_block);
                for tx in &batch {
                    store.put_account(&tx.intent.sender_address, &qr_dlt_storage::AccountState::new(1_000_000, 0))?;
                    total_witness_bytes += bincode::serialize(&tx.witness)?.len();
                    total_intent_bytes += bincode::serialize(&tx.intent)?.len();
                }
                let block = Block::new([0u8; 32], h as u64, 1000 + h as u64, [0u8; 20], batch);
                store.commit_block(&block)?;
            }

            let purged = store.prune_witnesses_older_than(num_blocks as u64)?;
            let total_bytes = total_witness_bytes + total_intent_bytes;
            let reclaimed_pct = (total_witness_bytes as f64 / total_bytes as f64) * 100.0;

            println!("  Blocks Processed:        {}", num_blocks);
            println!("  Total Transactions:      {}", num_blocks * txs_per_block);
            println!("  Witness Records Purged:  {}", purged);
            println!("  Raw Witness Space:       {:.2} KB", total_witness_bytes as f64 / 1024.0);
            println!("  Retained Intent Space:   {:.2} KB", total_intent_bytes as f64 / 1024.0);
            println!("  Reclaimed Disk Space:    {:.1}%", reclaimed_pct);

            let pruning_eval = PruningEvaluation {
                blocks_evaluated: num_blocks,
                txs_per_block,
                total_txs: num_blocks * txs_per_block,
                unpruned_witness_bytes: total_witness_bytes,
                retained_intent_bytes: total_intent_bytes,
                reclaimed_space_percent: reclaimed_pct,
            };

            let report = EmpiricalReport {
                timestamp: SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs(),
                system: "Linux x86_64 (AVX2/BMI2/SHA-NI)".into(),
                schemes: schemes_info,
                batch_scaling: scaling_entries,
                pruning: pruning_eval,
            };

            let json = serde_json::to_string_pretty(&report)?;
            fs::write(&output_file, json)?;
            println!("\nEmpirical results saved to: {:?}", output_file);
        }

        Commands::Run {
            bind_addr,
            peers,
            db_path,
            validator_scheme,
            max_block_txs: _max_block_txs,
            prune_depth,
        } => {
            let crypto_scheme = match validator_scheme {
                SchemeArg::Ed25519 => CryptoScheme::Ed25519,
                SchemeArg::Falcon512 => CryptoScheme::Falcon512,
                SchemeArg::MlDsa44 => CryptoScheme::MlDsa44,
            };

            let validator_signer = generate_keypair(crypto_scheme);
            let validator_addr = validator_signer.address();

            info!("Starting QR-DLT Node...");
            info!("  Validator Address: 0x{}", hex::encode(validator_addr));
            info!("  Signature Scheme:  {}", crypto_scheme.name());
            info!("  Storage Path:      {:?}", db_path);
            info!("  P2P Listen Addr:   {}", bind_addr);

            let store = Arc::new(LedgerStore::open(&db_path)?);
            let mempool = Arc::new(Mempool::new());

            let (p2p, mut inbound_rx) = P2pService::new(bind_addr);
            p2p.start_server().await?;

            for peer in peers {
                info!("Dialing peer {}", peer);
                if let Err(e) = p2p.connect_peer(peer).await {
                    tracing::warn!("Could not connect to initial peer {}: {:?}", peer, e);
                }
            }

            // Inbound message loop
            info!("Node initialized. Ready for P2P traffic.");
            while let Some((sender, msg)) = inbound_rx.recv().await {
                match msg {
                    NetworkMessage::FastTxIntent(intent) => {
                        info!("Received FastTxIntent from {}: nonce {}", sender, intent.nonce);
                    }
                    NetworkMessage::FullTransaction(tx) => {
                        if let Ok(tx_hash) = mempool.admit(tx, &store) {
                            info!("Admitted transaction 0x{} from {}", hex::encode(&tx_hash[0..8]), sender);
                        }
                    }
                    NetworkMessage::BlockBroadcast(block) => {
                        info!("Received Block #{} from {} with {} txs", block.header.height, sender, block.transactions.len());
                        if block.verify_roots() {
                            let _ = store.commit_block(&block);
                            if let Some(depth) = prune_depth {
                                if block.header.height > depth {
                                    let _ = store.prune_witnesses_older_than(block.header.height - depth);
                                }
                            }
                        }
                    }
                    NetworkMessage::StatusPing { latest_height, node_id } => {
                        info!("Ping from node {} (height {})", node_id, latest_height);
                    }
                    NetworkMessage::StatusPong { latest_height, node_id } => {
                        info!("Pong from node {} (height {})", node_id, latest_height);
                    }
                    _ => {}
                }
            }
        }
    }

    Ok(())
}

mod hex {
    pub fn encode(bytes: impl AsRef<[u8]>) -> String {
        bytes.as_ref().iter().map(|b| format!("{:02x}", b)).collect()
    }
}
