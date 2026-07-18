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

/// Maximum accepted frame body length (16 MiB).
///
/// A length-prefix larger than this is rejected **before** any buffer is
/// allocated, so a malicious (but validly-authenticated) peer cannot advertise
/// a multi-gigabyte length and force an out-of-memory allocation (H-8).
pub const MAX_FRAME_LEN: usize = 16 * 1024 * 1024;

/// Serialize `msg` and write it as a length-prefixed JSON frame
pub async fn write_frame<T, W>(writer: &mut W, msg: &T) -> Result<()>
where
    T: Serialize + Sync,
    W: AsyncWrite + Unpin + Send,
{
    let json = serde_json::to_vec(msg).context("failed to serialize cluster message")?;
    if json.len() > MAX_FRAME_LEN {
        anyhow::bail!(
            "cluster message too large: {} bytes exceeds MAX_FRAME_LEN ({} bytes)",
            json.len(),
            MAX_FRAME_LEN
        );
    }
    // Guaranteed to fit in u32 because MAX_FRAME_LEN < u32::MAX.
    let len = u32::try_from(json.len()).context("cluster frame length exceeds u32")?;
    let mut buf = BytesMut::with_capacity(4 + json.len());
    buf.put_u32(len);
    buf.put_slice(&json);
    writer.write_all(&buf).await.context("failed to write cluster frame")?;
    Ok(())
}

/// Read a length-prefixed JSON frame and deserialize it into `T`
pub async fn read_frame<T, R>(reader: &mut R) -> Result<T>
where
    T: for<'de> Deserialize<'de>,
    R: AsyncRead + Unpin + Send,
{
    let mut len_buf = [0u8; 4];
    reader
        .read_exact(&mut len_buf)
        .await
        .context("failed to read cluster frame length")?;
    let len = u32::from_be_bytes(len_buf) as usize;
    if len > MAX_FRAME_LEN {
        return Err(anyhow::anyhow!(
            "cluster frame length {len} exceeds MAX_FRAME_LEN ({MAX_FRAME_LEN} bytes); rejecting before allocation"
        ));
    }
    let mut data = vec![0u8; len];
    reader
        .read_exact(&mut data)
        .await
        .context("failed to read cluster frame body")?;
    let msg: T = serde_json::from_slice(&data).context("failed to deserialize cluster message")?;
    Ok(msg)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn read_frame_rejects_oversized_length_before_allocation() {
        // Advertise a length one byte over the limit; only the 4-byte prefix is
        // provided. A correct implementation must reject on the length check
        // rather than attempt to allocate/read the body.
        let bogus_len = u32::try_from(MAX_FRAME_LEN + 1).expect("limit + 1 fits in u32");
        let bytes = bogus_len.to_be_bytes();
        let mut reader = &bytes[..];
        let result = read_frame::<serde_json::Value, _>(&mut reader).await;
        assert!(result.is_err(), "oversized frame length must be rejected");
        let msg = result.err().map(|e| e.to_string()).unwrap_or_default();
        assert!(msg.contains("MAX_FRAME_LEN"), "error should mention the frame limit: {msg}");
    }

    #[tokio::test]
    async fn write_then_read_roundtrip_small_frame() {
        let value = serde_json::json!({ "hello": "world", "n": 42 });
        let mut buf: Vec<u8> = Vec::new();
        write_frame(&mut buf, &value).await.expect("write_frame");
        let mut reader = &buf[..];
        let decoded: serde_json::Value = read_frame(&mut reader).await.expect("read_frame");
        assert_eq!(decoded, value);
    }

    #[tokio::test]
    async fn write_frame_rejects_body_exceeding_limit() {
        // A ~17 MiB string serializes past MAX_FRAME_LEN and must be refused.
        let big = "a".repeat(MAX_FRAME_LEN + 1024);
        let value = serde_json::Value::String(big);
        let mut buf: Vec<u8> = Vec::new();
        let result = write_frame(&mut buf, &value).await;
        assert!(result.is_err(), "oversized message must be refused on write");
        assert!(buf.is_empty(), "nothing should be written for an oversized frame");
    }
}
