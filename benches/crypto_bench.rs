use criterion::{black_box, criterion_group, criterion_main, Criterion};
use qr_dlt_crypto::{
    verify_signature, CryptoScheme, CryptoSigner, Ed25519Signer, Falcon512Signer, MlDsa44Signer,
};

fn bench_keygen(c: &mut Criterion) {
    let mut group = c.benchmark_group("KeyGen");
    group.bench_function("Ed25519", |b| {
        b.iter(|| black_box(Ed25519Signer::generate()))
    });
    group.bench_function("Falcon-512", |b| {
        b.iter(|| black_box(Falcon512Signer::generate()))
    });
    group.bench_function("ML-DSA-44", |b| {
        b.iter(|| black_box(MlDsa44Signer::generate()))
    });
    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let mut group = c.benchmark_group("Sign");
    let msg = b"Benchmark transaction payload representing a standard ledger state mutation";

    let ed_signer = Ed25519Signer::generate();
    group.bench_function("Ed25519", |b| {
        b.iter(|| black_box(ed_signer.sign(black_box(msg)).unwrap()))
    });

    let falcon_signer = Falcon512Signer::generate();
    group.bench_function("Falcon-512", |b| {
        b.iter(|| black_box(falcon_signer.sign(black_box(msg)).unwrap()))
    });

    let mldsa_signer = MlDsa44Signer::generate();
    group.bench_function("ML-DSA-44", |b| {
        b.iter(|| black_box(mldsa_signer.sign(black_box(msg)).unwrap()))
    });
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let mut group = c.benchmark_group("Verify");
    let msg = b"Benchmark transaction payload representing a standard ledger state mutation";

    let ed_signer = Ed25519Signer::generate();
    let ed_sig = ed_signer.sign(msg).unwrap();
    let ed_pk = ed_signer.public_key_bytes();
    group.bench_function("Ed25519", |b| {
        b.iter(|| {
            black_box(
                verify_signature(
                    CryptoScheme::Ed25519,
                    black_box(msg),
                    black_box(&ed_sig),
                    black_box(&ed_pk),
                )
                .unwrap(),
            )
        })
    });

    let falcon_signer = Falcon512Signer::generate();
    let falcon_sig = falcon_signer.sign(msg).unwrap();
    let falcon_pk = falcon_signer.public_key_bytes();
    group.bench_function("Falcon-512", |b| {
        b.iter(|| {
            black_box(
                verify_signature(
                    CryptoScheme::Falcon512,
                    black_box(msg),
                    black_box(&falcon_sig),
                    black_box(&falcon_pk),
                )
                .unwrap(),
            )
        })
    });

    let mldsa_signer = MlDsa44Signer::generate();
    let mldsa_sig = mldsa_signer.sign(msg).unwrap();
    let mldsa_pk = mldsa_signer.public_key_bytes();
    group.bench_function("ML-DSA-44", |b| {
        b.iter(|| {
            black_box(
                verify_signature(
                    CryptoScheme::MlDsa44,
                    black_box(msg),
                    black_box(&mldsa_sig),
                    black_box(&mldsa_pk),
                )
                .unwrap(),
            )
        })
    });
    group.finish();
}

criterion_group!(benches, bench_keygen, bench_sign, bench_verify);
criterion_main!(benches);
