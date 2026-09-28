//! Chrome native messaging framing: a 4-byte length in the host's native
//! byte order, then that many bytes of UTF-8 JSON. Nothing else may ever be
//! written to the pipe.

use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

/// The browser's limit for host → extension; ours are a few hundred bytes.
pub const MAX_FRAME: usize = 1024 * 1024;

pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
    if data.len() > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "frame exceeds 1 MiB"));
    }
    let mut buf = Vec::with_capacity(4 + data.len());
    buf.extend_from_slice(&(data.len() as u32).to_ne_bytes());
    buf.extend_from_slice(data);
    w.write_all(&buf).await?;
    w.flush().await
}

/// `Ok(None)` at a clean end of stream: the browser closed the pipe.
pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Option<Vec<u8>>> {
    let mut len = [0u8; 4];
    match r.read_exact(&mut len).await {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => return Ok(None),
        Err(e) => return Err(e),
    }
    let len = u32::from_ne_bytes(len) as usize;
    if len > MAX_FRAME {
        return Err(std::io::Error::new(std::io::ErrorKind::InvalidData, "frame exceeds 1 MiB"));
    }
    let mut data = vec![0u8; len];
    r.read_exact(&mut data).await?;
    Ok(Some(data))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn round_trip_then_clean_eof() {
        let (mut a, mut b) = tokio::io::duplex(256);
        write_frame(&mut a, br#"{"command":"connected"}"#).await.unwrap();
        write_frame(&mut a, b"").await.unwrap();
        drop(a);
        assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), br#"{"command":"connected"}"#);
        assert_eq!(read_frame(&mut b).await.unwrap().unwrap(), b"");
        assert!(read_frame(&mut b).await.unwrap().is_none());
    }

    #[tokio::test]
    async fn length_prefix_is_native_order() {
        let (mut a, mut b) = tokio::io::duplex(64);
        write_frame(&mut a, b"abc").await.unwrap();
        let mut raw = [0u8; 7];
        b.read_exact(&mut raw).await.unwrap();
        assert_eq!(raw[..4], 3u32.to_ne_bytes());
        assert_eq!(&raw[4..], b"abc");
    }

    #[tokio::test]
    async fn oversize_is_refused_both_ways() {
        let (mut a, mut b) = tokio::io::duplex(64);
        assert!(write_frame(&mut a, &vec![0u8; MAX_FRAME + 1]).await.is_err());
        a.write_all(&((MAX_FRAME as u32) + 1).to_ne_bytes()).await.unwrap();
        assert!(read_frame(&mut b).await.is_err());
    }

    #[tokio::test]
    async fn truncated_body_is_an_error_not_eof() {
        let (mut a, mut b) = tokio::io::duplex(64);
        a.write_all(&10u32.to_ne_bytes()).await.unwrap();
        a.write_all(b"abc").await.unwrap();
        drop(a);
        assert!(read_frame(&mut b).await.is_err());
    }
}
