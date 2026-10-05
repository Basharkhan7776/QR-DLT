use clap::{Parser, Subcommand, ValueEnum};
use std::net::SocketAddr;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "qr-dlt-node")]
#[command(author = "Bashar Khan & Zaheer Khan")]
#[command(version = "0.1.0")]
#[command(about = "Quantum-Resilient Distributed Ledger (QR-DLT) Node Runtime")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Generates a cryptographic keypair (Ed25519, Falcon-512, or ML-DSA-44)
    Keygen {
        #[arg(short, long, value_enum, default_value_t = SchemeArg::Ed25519)]
        scheme: SchemeArg,
    },

    /// Runs a validating or observing node instance
    Run {
        /// P2P listening address
        #[arg(short, long, default_value = "127.0.0.1:8001")]
        bind_addr: SocketAddr,

        /// Seed peer addresses to connect to
        #[arg(short, long, value_delimiter = ',')]
        peers: Vec<SocketAddr>,

        /// Directory path for persistent sled state storage
        #[arg(short, long, default_value = "./data/node")]
        db_path: PathBuf,

        /// Cryptographic scheme for the node validator key
        #[arg(long, value_enum, default_value_t = SchemeArg::Ed25519)]
        validator_scheme: SchemeArg,

        /// Maximum transactions to include per block proposal
        #[arg(long, default_value_t = 1000)]
        max_block_txs: usize,

        /// Run in pruned mode with specified epoch depth (e.g. 100 blocks)
        #[arg(long)]
        prune_depth: Option<u64>,
    },

    /// Executes a standalone block generation and batch verification benchmark
    BenchBlock {
        #[arg(short, long, value_enum, default_value_t = SchemeArg::Ed25519)]
        scheme: SchemeArg,

        #[arg(short, long, default_value_t = 1000)]
        tx_count: usize,
    },

    /// Runs a comprehensive empirical evaluation measuring cryptographic overhead,
    /// batch verification throughput, and epoch pruning efficiency across all schemes.
    Evaluate {
        /// File path to save structured empirical JSON metrics
        #[arg(short, long, default_value = "empirical_results.json")]
        output_file: PathBuf,

        /// Maximum batch size for scaling measurements
        #[arg(long, default_value_t = 1000)]
        max_batch: usize,
    },
}

#[derive(Copy, Clone, Debug, PartialEq, Eq, ValueEnum)]
pub enum SchemeArg {
    Ed25519,
    Falcon512,
    MlDsa44,
}
