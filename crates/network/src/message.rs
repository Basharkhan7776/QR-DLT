use qr_dlt_types::{Block, Transaction, TxIntent, WitnessProof};
use serde::{Deserialize, Serialize};

/// Network wire protocol messages supporting decoupled fast-path and heavy-path gossip.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum NetworkMessage {
    /// Fast-path transaction intent broadcast (~60 bytes).
    FastTxIntent(TxIntent),

    /// Full transaction broadcast (intent + witness).
    FullTransaction(Transaction),

    /// Heavy-path request for witness proof given its 32-byte intent hash.
    WitnessRequest { intent_hash: [u8; 32] },

    /// Heavy-path witness proof response.
    WitnessResponse {
        intent_hash: [u8; 32],
        witness: WitnessProof,
    },

    /// Broadcast of a newly proposed and signed block.
    BlockBroadcast(Block),

    /// Node liveness and synchronization status ping.
    StatusPing {
        latest_height: u64,
        node_id: String,
    },

    /// Node liveness and synchronization status pong.
    StatusPong {
        latest_height: u64,
        node_id: String,
    },
}
