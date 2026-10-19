//! Sovereign Falcon-512 CLI Wallet & Transaction Signer (`falcon-signer`).
//!
//! Provides utilities to generate post-quantum Falcon-512 keys, construct and sign EIP-2718 Type 0x46
//! transactions, query node balances, and broadcast signed transactions over Ethereum JSON-RPC 2.0.

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use jsonrpsee::core::client::ClientT;
use jsonrpsee::http_client::HttpClientBuilder;
use jsonrpsee::rpc_params;
use qr_dlt_crypto::{evm_address_from_falcon_pubkey, CryptoSigner, Falcon512Signer};
use qr_dlt_types::FalconTransaction;
use std::fs;
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(name = "falcon-signer")]
#[command(author = "Bashar Khan & Zaheer Khan")]
#[command(version = "0.1.0")]
#[command(about = "Sovereign Falcon-512 Key Management & Type 0x46 EVM Transaction Signer")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Generates a fresh Falcon-512 keypair and derives the 20-byte Keccak-256 address.
    Keygen {
        /// Optional directory path to save secret.key and public.key
        #[arg(short, long)]
        out_dir: Option<PathBuf>,
    },

    /// Derives the 20-byte EVM address from a Falcon-512 public key.
    Address {
        /// Public key hex string or path to public key file
        #[arg(short, long)]
        pubkey: String,
    },

    /// Signs an EIP-2718 Type 0x46 transaction and outputs the enveloped raw hex.
    SignTx {
        /// EVM Chain ID (e.g. 1337)
        #[arg(long, default_value_t = 1337)]
        chain_id: u64,

        /// Account nonce
        #[arg(long, default_value_t = 0)]
        nonce: u64,

        /// Gas fee in wei
        #[arg(long, default_value_t = 1_000_000_000)]
        gas_fee: u128,

        /// Gas limit
        #[arg(long, default_value_t = 100_000)]
        gas_limit: u64,

        /// Recipient address (20-byte hex). Omit for contract deployment.
        #[arg(long)]
        to: Option<String>,

        /// Amount in wei to transfer
        #[arg(long, default_value_t = 0)]
        value: u128,

        /// Calldata hex (e.g. 0x60806040...)
        #[arg(long, default_value = "0x")]
        data: String,

        /// Secret key hex or file path
        #[arg(long)]
        secret_key: String,

        /// Public key hex or file path
        #[arg(long)]
        pubkey: String,
    },

    /// Signs and broadcasts an EIP-2718 Type 0x46 transaction to an Ethereum JSON-RPC endpoint.
    SendTx {
        /// JSON-RPC HTTP URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc_url: String,

        /// Pre-signed raw transaction hex (if provided, signs are skipped)
        #[arg(long)]
        raw_tx: Option<String>,

        /// EVM Chain ID
        #[arg(long, default_value_t = 1337)]
        chain_id: u64,

        /// Account nonce
        #[arg(long, default_value_t = 0)]
        nonce: u64,

        /// Gas fee in wei
        #[arg(long, default_value_t = 1_000_000_000)]
        gas_fee: u128,

        /// Gas limit
        #[arg(long, default_value_t = 100_000)]
        gas_limit: u64,

        /// Recipient address (20-byte hex). Omit for contract deployment.
        #[arg(long)]
        to: Option<String>,

        /// Amount in wei to transfer
        #[arg(long, default_value_t = 0)]
        value: u128,

        /// Calldata hex
        #[arg(long, default_value = "0x")]
        data: String,

        /// Secret key hex or file path
        #[arg(long)]
        secret_key: Option<String>,

        /// Public key hex or file path
        #[arg(long)]
        pubkey: Option<String>,
    },

    /// Queries the account balance in wei and ETH via JSON-RPC.
    Balance {
        /// 20-byte EVM address (hex)
        #[arg(short, long)]
        address: String,

        /// JSON-RPC HTTP URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc_url: String,
    },

    /// Queries the latest block number via JSON-RPC.
    BlockNumber {
        /// JSON-RPC HTTP URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc_url: String,
    },

    /// Executes an EVM call simulation without committing state.
    Call {
        /// Target contract address
        #[arg(long)]
        to: String,

        /// Calldata hex
        #[arg(long, default_value = "0x")]
        data: String,

        /// Optional caller address
        #[arg(long)]
        from: Option<String>,

        /// JSON-RPC HTTP URL
        #[arg(long, default_value = "http://127.0.0.1:8545")]
        rpc_url: String,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { out_dir } => {
            let signer = Falcon512Signer::generate();
            let pk_bytes = signer.public_key_bytes();
            let sk_bytes = signer.secret_key_bytes();
            let addr = evm_address_from_falcon_pubkey(&pk_bytes);

            let addr_hex = format!("0x{}", hex::encode(addr));
            let pk_hex = hex::encode(&pk_bytes);
            let sk_hex = hex::encode(&sk_bytes);

            println!("=== Generated Sovereign Falcon-512 Keypair ===");
            println!("Derived EVM Address : {}", addr_hex);
            println!("Public Key Size     : {} bytes", pk_bytes.len());
            println!("Secret Key Size     : {} bytes", sk_bytes.len());
            println!("Public Key (hex)    : {}", pk_hex);
            println!("Secret Key (hex)    : {}", sk_hex);

            if let Some(dir) = out_dir {
                fs::create_dir_all(&dir)
                    .with_context(|| format!("Failed to create directory {:?}", dir))?;
                fs::write(dir.join("falcon.pub"), &pk_hex)?;
                fs::write(dir.join("falcon.sec"), &sk_hex)?;
                fs::write(dir.join("address.txt"), &addr_hex)?;
                println!("Saved keys and address to {:?}", dir);
            }
        }

        Commands::Address { pubkey } => {
            let pk_bytes = read_or_parse_hex(&pubkey)?;
            if pk_bytes.len() != 897 {
                bail!(
                    "Invalid Falcon-512 public key size: expected 897 bytes, got {}",
                    pk_bytes.len()
                );
            }
            let addr = evm_address_from_falcon_pubkey(&pk_bytes);
            println!("0x{}", hex::encode(addr));
        }

        Commands::SignTx {
            chain_id,
            nonce,
            gas_fee,
            gas_limit,
            to,
            value,
            data,
            secret_key,
            pubkey,
        } => {
            let sk_bytes = read_or_parse_hex(&secret_key)?;
            let pk_bytes = read_or_parse_hex(&pubkey)?;
            let signer = Falcon512Signer::from_bytes(&sk_bytes, &pk_bytes)
                .map_err(|e| anyhow::anyhow!("Failed to construct Falcon-512 signer: {}", e))?;

            let to_addr = match to {
                Some(s) => Some(parse_address_hex(&s)?),
                None => None,
            };

            let data_bytes = parse_hex_data(&data)?;
            let tx = build_and_sign_tx(
                &signer,
                chain_id,
                nonce,
                gas_fee,
                gas_limit,
                to_addr,
                value,
                data_bytes,
            )?;

            let raw_bytes = tx.encode_enveloped();
            let raw_hex = format!("0x{}", hex::encode(raw_bytes));
            let tx_hash = format!("0x{}", hex::encode(tx.tx_hash()));

            println!("Transaction Hash : {}", tx_hash);
            println!("Raw Type 0x46 Hex: {}", raw_hex);
        }

        Commands::SendTx {
            rpc_url,
            raw_tx,
            chain_id,
            nonce,
            gas_fee,
            gas_limit,
            to,
            value,
            data,
            secret_key,
            pubkey,
        } => {
            let raw_hex = match raw_tx {
                Some(hex_str) => hex_str,
                None => {
                    let sk_str = secret_key.context("Must provide --secret-key when --raw-tx is not specified")?;
                    let pk_str = pubkey.context("Must provide --pubkey when --raw-tx is not specified")?;
                    let sk_bytes = read_or_parse_hex(&sk_str)?;
                    let pk_bytes = read_or_parse_hex(&pk_str)?;
                    let signer = Falcon512Signer::from_bytes(&sk_bytes, &pk_bytes)
                        .map_err(|e| anyhow::anyhow!("Failed to construct Falcon-512 signer: {}", e))?;

                    let to_addr = match to {
                        Some(s) => Some(parse_address_hex(&s)?),
                        None => None,
                    };
                    let data_bytes = parse_hex_data(&data)?;
                    let tx = build_and_sign_tx(
                        &signer,
                        chain_id,
                        nonce,
                        gas_fee,
                        gas_limit,
                        to_addr,
                        value,
                        data_bytes,
                    )?;
                    format!("0x{}", hex::encode(tx.encode_enveloped()))
                }
            };

            let client = HttpClientBuilder::default().build(&rpc_url)?;
            let res: String = client
                .request("eth_sendRawTransaction", rpc_params![raw_hex])
                .await?;

            println!("Broadcast successful! Tx Hash: {}", res);
        }

        Commands::Balance { address, rpc_url } => {
            let client = HttpClientBuilder::default().build(&rpc_url)?;
            let balance_hex: String = client
                .request("eth_getBalance", rpc_params![address, "latest"])
                .await?;

            let clean = balance_hex.trim().strip_prefix("0x").unwrap_or(&balance_hex);
            let wei = u128::from_str_radix(clean, 16).unwrap_or(0);
            let eth = (wei as f64) / 1e18;

            println!("Balance: {} wei ({:.6} ETH)", wei, eth);
        }

        Commands::BlockNumber { rpc_url } => {
            let client = HttpClientBuilder::default().build(&rpc_url)?;
            let block_hex: String = client
                .request("eth_blockNumber", rpc_params![])
                .await?;

            let clean = block_hex.trim().strip_prefix("0x").unwrap_or(&block_hex);
            let num = u64::from_str_radix(clean, 16).unwrap_or(0);
            println!("Current Block Height: {} ({})", num, block_hex);
        }

        Commands::Call {
            to,
            data,
            from,
            rpc_url,
        } => {
            let client = HttpClientBuilder::default().build(&rpc_url)?;
            let req = serde_json::json!({
                "to": to,
                "data": data,
                "from": from,
            });

            let out_hex: String = client.request("eth_call", rpc_params![req, "latest"]).await?;
            println!("Call Result: {}", out_hex);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn build_and_sign_tx(
    signer: &Falcon512Signer,
    chain_id: u64,
    nonce: u64,
    gas_fee: u128,
    gas_limit: u64,
    to: Option<[u8; 20]>,
    value: u128,
    data: Vec<u8>,
) -> Result<FalconTransaction> {
    let pk = signer.public_key_bytes();
    let mut tx = FalconTransaction::new(
        chain_id, nonce, gas_fee, gas_limit, to, value, data, pk, Vec::new(),
    );
    let sig = signer
        .sign(&tx.signing_hash())
        .map_err(|e| anyhow::anyhow!("Signing failed: {}", e))?;
    tx.falcon_signature = sig;
    Ok(tx)
}

fn read_or_parse_hex(input: &str) -> Result<Vec<u8>> {
    let raw = if let Ok(content) = fs::read_to_string(input) {
        content.trim().to_string()
    } else {
        input.trim().to_string()
    };
    let clean = raw.strip_prefix("0x").unwrap_or(&raw);
    let bytes = hex::decode(clean)
        .with_context(|| format!("Failed to decode hex string (length {})", clean.len()))?;
    Ok(bytes)
}

fn parse_address_hex(s: &str) -> Result<[u8; 20]> {
    let clean = s.trim().strip_prefix("0x").unwrap_or(s);
    let bytes = hex::decode(clean)
        .with_context(|| format!("Invalid address hex string '{}'", s))?;
    if bytes.len() != 20 {
        bail!("Address must be 20 bytes, got {}", bytes.len());
    }
    let mut addr = [0u8; 20];
    addr.copy_from_slice(&bytes);
    Ok(addr)
}

fn parse_hex_data(s: &str) -> Result<Vec<u8>> {
    let clean = s.trim().strip_prefix("0x").unwrap_or(s);
    if clean.is_empty() {
        return Ok(Vec::new());
    }
    hex::decode(clean).with_context(|| format!("Invalid data hex string '{}'", s))
}
