use crate::codec::{read_message, write_message};
use crate::message::NetworkMessage;
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{mpsc, RwLock};
use tracing::{debug, error, info};

pub type PeerId = SocketAddr;

/// Tokio-based asynchronous P2P networking service.
pub struct P2pService {
    bind_addr: SocketAddr,
    peers: Arc<RwLock<HashMap<PeerId, mpsc::Sender<NetworkMessage>>>>,
    inbound_sender: mpsc::Sender<(PeerId, NetworkMessage)>,
}

impl P2pService {
    /// Initializes P2P service, returning the service handle and inbound message receiver.
    pub fn new(
        bind_addr: SocketAddr,
    ) -> (Self, mpsc::Receiver<(PeerId, NetworkMessage)>) {
        let (inbound_sender, inbound_receiver) = mpsc::channel(1024);
        let service = Self {
            bind_addr,
            peers: Arc::new(RwLock::new(HashMap::new())),
            inbound_sender,
        };
        (service, inbound_receiver)
    }

    /// Spawns the TCP listener to accept incoming peer connections.
    pub async fn start_server(&self) -> Result<(), std::io::Error> {
        let listener = TcpListener::bind(self.bind_addr).await?;
        let peers = self.peers.clone();
        let inbound_tx = self.inbound_sender.clone();

        tokio::spawn(async move {
            info!("P2P server listening on {}", listener.local_addr().unwrap());
            loop {
                match listener.accept().await {
                    Ok((stream, peer_addr)) => {
                        debug!("Accepted connection from peer {}", peer_addr);
                        Self::spawn_peer_connection(stream, peer_addr, peers.clone(), inbound_tx.clone());
                    }
                    Err(e) => {
                        error!("TCP accept error: {:?}", e);
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    /// Connects to a remote peer address.
    pub async fn connect_peer(&self, target_addr: SocketAddr) -> Result<(), std::io::Error> {
        let stream = TcpStream::connect(target_addr).await?;
        Self::spawn_peer_connection(
            stream,
            target_addr,
            self.peers.clone(),
            self.inbound_sender.clone(),
        );
        Ok(())
    }

    fn spawn_peer_connection(
        stream: TcpStream,
        peer_addr: SocketAddr,
        peers: Arc<RwLock<HashMap<PeerId, mpsc::Sender<NetworkMessage>>>>,
        inbound_tx: mpsc::Sender<(PeerId, NetworkMessage)>,
    ) {
        let (mut reader, mut writer) = stream.into_split();
        let (outbound_tx, mut outbound_rx) = mpsc::channel::<NetworkMessage>(256);

        // Register peer outbound queue
        {
            let peers = peers.clone();
            tokio::spawn(async move {
                peers.write().await.insert(peer_addr, outbound_tx);
            });
        }

        // Writer task: sends queued messages to the TCP socket
        tokio::spawn(async move {
            while let Some(msg) = outbound_rx.recv().await {
                if let Err(e) = write_message(&mut writer, &msg).await {
                    debug!("Failed to write to peer {}: {:?}", peer_addr, e);
                    break;
                }
            }
        });

        // Reader task: reads messages from TCP socket and forwards to inbound_tx
        tokio::spawn(async move {
            loop {
                match read_message(&mut reader).await {
                    Ok(msg) => {
                        if inbound_tx.send((peer_addr, msg)).await.is_err() {
                            break; // Node shutting down
                        }
                    }
                    Err(_) => {
                        break; // Connection closed
                    }
                }
            }
            peers.write().await.remove(&peer_addr);
            debug!("Peer {} disconnected", peer_addr);
        });
    }

    /// Broadcasts a network message to all currently connected peers.
    pub async fn broadcast(&self, message: NetworkMessage) {
        let peers = self.peers.read().await;
        for (peer_addr, tx) in peers.iter() {
            if let Err(e) = tx.send(message.clone()).await {
                debug!("Failed to queue message for peer {}: {:?}", peer_addr, e);
            }
        }
    }

    /// Count of currently connected peers.
    pub async fn peer_count(&self) -> usize {
        self.peers.read().await.len()
    }
}
