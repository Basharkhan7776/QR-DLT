use qr_dlt_crypto::CryptoError;
use qr_dlt_types::Transaction;
use rayon::prelude::*;

/// Parallel batch verifier leveraging Rayon work-stealing thread pools
/// to accelerate post-quantum and classical signature validation.
pub struct BatchVerifier {
    thread_pool: Option<rayon::ThreadPool>,
}

impl BatchVerifier {
    /// Creates a batch verifier utilizing the global Rayon thread pool.
    pub fn new() -> Self {
        Self { thread_pool: None }
    }

    /// Creates a batch verifier bound to an explicit thread pool
    /// (e.g. pinned to Alder Lake P-cores or E-cores for comparative benchmarking).
    pub fn with_thread_count(num_threads: usize) -> Result<Self, rayon::ThreadPoolBuildError> {
        let pool = rayon::ThreadPoolBuilder::new()
            .num_threads(num_threads)
            .thread_name(|idx| format!("qr-dlt-verifier-{}", idx))
            .build()?;
        Ok(Self {
            thread_pool: Some(pool),
        })
    }

    /// Verifies all transactions in parallel. Returns indices of any invalid transactions.
    pub fn verify_batch(&self, txs: &[Transaction]) -> Vec<(usize, CryptoError)> {
        let verify_fn = || {
            txs.par_iter()
                .enumerate()
                .filter_map(|(idx, tx)| match tx.verify_signature() {
                    Ok(()) => None,
                    Err(e) => Some((idx, e)),
                })
                .collect()
        };

        match &self.thread_pool {
            Some(pool) => pool.install(verify_fn),
            None => verify_fn(),
        }
    }

    /// Verifies all transactions in parallel, returning Ok(()) only if 100% of signatures are valid.
    pub fn verify_all(&self, txs: &[Transaction]) -> Result<(), (usize, CryptoError)> {
        let failed = self.verify_batch(txs);
        if let Some(first_failure) = failed.into_iter().next() {
            Err(first_failure)
        } else {
            Ok(())
        }
    }
}

impl Default for BatchVerifier {
    fn default() -> Self {
        Self::new()
    }
}
