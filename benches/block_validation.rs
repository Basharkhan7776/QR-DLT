use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion};
use qr_dlt_crypto::{CryptoSigner, Ed25519Signer, Falcon512Signer, MlDsa44Signer};
use qr_dlt_mempool::BatchVerifier;
use qr_dlt_types::{Transaction, TxIntent, WitnessProof};

fn generate_ed25519_batch(count: usize) -> Vec<Transaction> {
    let mut txs = Vec::with_capacity(count);
    for i in 0..count {
        let signer = Ed25519Signer::generate();
        let intent = TxIntent {
            nonce: (i + 1) as u64,
            sender_address: signer.address(),
            recipient_address: [1u8; 20],
            amount: 100,
            fee: 1,
        };
        let sig = signer.sign(&intent.hash()).unwrap();
        txs.push(Transaction::new(
            intent,
            WitnessProof::Ed25519 {
                public_key: signer.public_key_bytes().try_into().unwrap(),
                signature: sig.try_into().unwrap(),
            },
        ));
    }
    txs
}

fn generate_falcon512_batch(count: usize) -> Vec<Transaction> {
    let mut txs = Vec::with_capacity(count);
    for i in 0..count {
        let signer = Falcon512Signer::generate();
        let intent = TxIntent {
            nonce: (i + 1) as u64,
            sender_address: signer.address(),
            recipient_address: [2u8; 20],
            amount: 200,
            fee: 2,
        };
        let sig = signer.sign(&intent.hash()).unwrap();
        txs.push(Transaction::new(
            intent,
            WitnessProof::Falcon512 {
                public_key: signer.public_key_bytes(),
                signature: sig,
            },
        ));
    }
    txs
}

fn generate_mldsa44_batch(count: usize) -> Vec<Transaction> {
    let mut txs = Vec::with_capacity(count);
    for i in 0..count {
        let signer = MlDsa44Signer::generate();
        let intent = TxIntent {
            nonce: (i + 1) as u64,
            sender_address: signer.address(),
            recipient_address: [3u8; 20],
            amount: 300,
            fee: 3,
        };
        let sig = signer.sign(&intent.hash()).unwrap();
        txs.push(Transaction::new(
            intent,
            WitnessProof::MlDsa44 {
                public_key: signer.public_key_bytes(),
                signature: sig,
            },
        ));
    }
    txs
}

fn bench_batch_validation(c: &mut Criterion) {
    let verifier = BatchVerifier::new();

    let mut group = c.benchmark_group("BatchValidationScaling");
    group.sample_size(10); // Use modest sample size for large batch benchmarks

    for &size in &[100, 500, 1000] {
        let ed_batch = generate_ed25519_batch(size);
        group.bench_with_input(BenchmarkId::new("Ed25519", size), &ed_batch, |b, batch| {
            b.iter(|| black_box(verifier.verify_all(black_box(batch)).unwrap()))
        });

        let falcon_batch = generate_falcon512_batch(size);
        group.bench_with_input(BenchmarkId::new("Falcon-512", size), &falcon_batch, |b, batch| {
            b.iter(|| black_box(verifier.verify_all(black_box(batch)).unwrap()))
        });

        let mldsa_batch = generate_mldsa44_batch(size);
        group.bench_with_input(BenchmarkId::new("ML-DSA-44", size), &mldsa_batch, |b, batch| {
            b.iter(|| black_box(verifier.verify_all(black_box(batch)).unwrap()))
        });
    }

    group.finish();
}

criterion_group!(benches, bench_batch_validation);
criterion_main!(benches);
