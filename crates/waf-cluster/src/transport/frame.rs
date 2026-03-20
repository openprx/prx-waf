/// Length-prefixed JSON frame codec for QUIC streams.
///
/// Wire format:
/// ```text
/// ┌──────────────────┬────────────────────────────────┐
/// │  u32 (4 bytes)   │  JSON bytes (variable length)  │
/// │  big-endian len  │  serde_json::to_vec(msg)        │
/// └──────────────────┴────────────────────────────────┘
/// ```
use anyhow::{Context, Result};
use bytes::{BufMut, BytesMut};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Serialize `msg` and write it as a length-prefixed JSON frame
pub async fn write_frame<T, W>(writer: &mut W, msg: &T) -> Result<()>
where
    T: Serialize,
    W: AsyncWrite + Unpin,
{
    let json = serde_json::to_vec(msg).context("failed to serialize cluster message")?;
    let len = json.len() as u32;
    let mut buf = BytesMut::with_capacity(4 + json.len());
    buf.put_u32(len);
    buf.put_slice(&json);
    writer
        .write_all(&buf)
        .await
        .context("failed to write cluster frame")?;
    Ok(())
}

/// Read a length-prefixed JSON frame and deserialize it into `T`
pub async fn read_frame<T, R>(reader: &mut R) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    R: AsyncRead + Unpin,
{
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("failed to read cluster frame length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    let mut data = vec![0u8; len];
    reader
        .read_exact(&mut data)
        .await
        .context("failed to read cluster frame body")?;
    let msg: T = serde_json::from_slice(&data).context("failed to deserialize cluster message")?;
    Ok(msg)
}
