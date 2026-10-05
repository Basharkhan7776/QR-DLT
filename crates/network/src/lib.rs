//! Asynchronous Tokio P2P gossip engine and framing for QR-DLT.

pub mod codec;
pub mod message;
pub mod service;

pub use codec::{read_message, write_message};
pub use message::NetworkMessage;
pub use service::{P2pService, PeerId};

#[cfg(test)]
mod tests {
    use super::*;
    use qr_dlt_types::TxIntent;
    use std::net::SocketAddr;
    use std::time::Duration;
    use tokio::time::sleep;

    #[tokio::test]
    async fn test_p2p_loopback_broadcast() {
        let addr1: SocketAddr = "127.0.0.1:18001".parse().unwrap();
        let addr2: SocketAddr = "127.0.0.1:18002".parse().unwrap();

        let (node1, _rx1) = P2pService::new(addr1);
        let (node2, mut rx2) = P2pService::new(addr2);

        node1.start_server().await.unwrap();
        node2.start_server().await.unwrap();

        sleep(Duration::from_millis(50)).await;

        // Node 1 connects to Node 2
        node1.connect_peer(addr2).await.unwrap();

        sleep(Duration::from_millis(100)).await;

        let sample_intent = TxIntent {
            nonce: 1,
            sender_address: [1u8; 20],
            recipient_address: [2u8; 20],
            amount: 500,
            fee: 5,
        };

        // Node 1 broadcasts fast-path intent
        node1.broadcast(NetworkMessage::FastTxIntent(sample_intent.clone())).await;

        // Node 2 should receive the message
        let received = tokio::time::timeout(Duration::from_secs(2), rx2.recv())
            .await
            .expect("Should not timeout")
            .expect("Should receive message");

        assert_eq!(received.1, NetworkMessage::FastTxIntent(sample_intent));
    }
}
