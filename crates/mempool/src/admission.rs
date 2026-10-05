use crate::error::MempoolError;
use qr_dlt_storage::LedgerStore;
use qr_dlt_types::Transaction;

/// Validates that an incoming transaction satisfies all consensus admission criteria.
pub fn validate_admission(
    tx: &Transaction,
    store: &LedgerStore,
    pending_sender_nonce: Option<u64>,
) -> Result<(), MempoolError> {
    // 1. Fee validation
    if tx.intent.fee == 0 {
        return Err(MempoolError::ZeroFee);
    }

    // 2. Address recovery validation
    let derived_address = tx.witness.recover_address();
    if derived_address != tx.intent.sender_address {
        return Err(MempoolError::AddressMismatch(format!(
            "Derived 0x{} != declared 0x{}",
            hex::encode(derived_address),
            hex::encode(tx.intent.sender_address)
        )));
    }

    // 3. Account balance and nonce validation against ledger state
    let account = store.get_account(&tx.intent.sender_address)?;
    let base_nonce = pending_sender_nonce.unwrap_or(account.nonce);
    let expected_nonce = base_nonce + 1;

    if tx.intent.nonce != expected_nonce {
        return Err(MempoolError::InvalidNonce {
            expected: expected_nonce,
            actual: tx.intent.nonce,
        });
    }

    let required_balance = tx.intent.amount.checked_add(tx.intent.fee).ok_or_else(|| {
        MempoolError::InsufficientBalance {
            available: account.balance,
            required: u64::MAX,
        }
    })?;

    if account.balance < required_balance {
        return Err(MempoolError::InsufficientBalance {
            available: account.balance,
            required: required_balance,
        });
    }

    // 4. Cryptographic signature verification
    tx.verify_signature()
        .map_err(|e| MempoolError::InvalidSignature(format!("{:?}", e)))?;

    Ok(())
}

mod hex {
    pub fn encode(bytes: [u8; 20]) -> String {
        bytes.iter().map(|b| format!("{:02x}", b)).collect()
    }
}
