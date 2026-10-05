use crate::message::NetworkMessage;
use std::io;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const MAX_FRAME_SIZE: usize = 16 * 1024 * 1024; // 16 MB max frame size for PQC blocks

/// Writes a length-prefixed serialized NetworkMessage to an async writer.
pub async fn write_message<W: AsyncWriteExt + Unpin>(
    writer: &mut W,
    message: &NetworkMessage,
) -> io::Result<()> {
    let payload = bincode::serialize(message)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    if payload.len() > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Payload exceeds maximum frame size: {} bytes", payload.len()),
        ));
    }

    let length = payload.len() as u32;
    writer.write_all(&length.to_be_bytes()).await?;
    writer.write_all(&payload).await?;
    writer.flush().await?;
    Ok(())
}

/// Reads a length-prefixed serialized NetworkMessage from an async reader.
pub async fn read_message<R: AsyncReadExt + Unpin>(reader: &mut R) -> io::Result<NetworkMessage> {
    let mut len_bytes = [0u8; 4];
    reader.read_exact(&mut len_bytes).await?;
    let length = u32::from_be_bytes(len_bytes) as usize;

    if length > MAX_FRAME_SIZE {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!("Incoming frame exceeds maximum size: {} bytes", length),
        ));
    }

    let mut buffer = vec![0u8; length];
    reader.read_exact(&mut buffer).await?;

    let message: NetworkMessage = bincode::deserialize(&buffer)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
    Ok(message)
}
