//! Noise leaves framing to the application: each message on the TCP stream is
//! a 2-byte big-endian length followed by that many bytes.
//!
//! The encoder and decoder work on byte buffers, so the phone can drive them
//! from Kotlin over a socket it owns; the async read/write below are the
//! PC's convenience over a tokio stream.

/// The largest Noise message, and therefore the largest frame.
pub const MAX_FRAME: usize = 65535;

#[derive(Debug, thiserror::Error)]
#[error("frame exceeds 65535 bytes")]
pub struct Oversize;

/// `len(2, big-endian) || data`.
pub fn encode(data: &[u8]) -> Result<Vec<u8>, Oversize> {
    let len = u16::try_from(data.len()).map_err(|_| Oversize)?;
    let mut buf = Vec::with_capacity(2 + data.len());
    buf.extend_from_slice(&len.to_be_bytes());
    buf.extend_from_slice(data);
    Ok(buf)
}

/// Accumulates bytes as they arrive and yields whole frames.
#[derive(Debug, Default)]
pub struct Decoder {
    buf: Vec<u8>,
}

impl Decoder {
    pub fn push(&mut self, bytes: &[u8]) {
        self.buf.extend_from_slice(bytes);
    }

    /// The next complete frame, if the bytes for one have arrived.
    pub fn next_frame(&mut self) -> Option<Vec<u8>> {
        let len = u16::from_be_bytes([*self.buf.first()?, *self.buf.get(1)?]) as usize;
        if self.buf.len() < 2 + len {
            return None;
        }
        let frame = self.buf[2..2 + len].to_vec();
        self.buf.drain(..2 + len);
        Some(frame)
    }

    /// Bytes waiting for the rest of their frame.
    pub fn pending(&self) -> usize {
        self.buf.len()
    }
}

#[cfg(feature = "tokio")]
pub use io::{read_frame, write_frame};

#[cfg(feature = "tokio")]
mod io {
    use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

    pub async fn write_frame<W: AsyncWrite + Unpin>(w: &mut W, data: &[u8]) -> std::io::Result<()> {
        let buf = super::encode(data).map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidInput, e))?;
        w.write_all(&buf).await?;
        w.flush().await
    }

    pub async fn read_frame<R: AsyncRead + Unpin>(r: &mut R) -> std::io::Result<Vec<u8>> {
        let mut len = [0u8; 2];
        r.read_exact(&mut len).await?;
        let mut data = vec![0u8; u16::from_be_bytes(len) as usize];
        r.read_exact(&mut data).await?;
        Ok(data)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encode_and_decode_in_pieces() {
        let a = encode(b"hello").unwrap();
        let b = encode(b"").unwrap();
        assert_eq!(a, [0, 5, b'h', b'e', b'l', b'l', b'o']);
        assert_eq!(b, [0, 0]);
        let mut d = Decoder::default();
        d.push(&a[..3]);
        assert_eq!(d.next_frame(), None);
        d.push(&a[3..]);
        d.push(&b);
        assert_eq!(d.next_frame().as_deref(), Some(&b"hello"[..]));
        assert_eq!(d.next_frame().as_deref(), Some(&b""[..]));
        assert_eq!(d.next_frame(), None);
        assert_eq!(d.pending(), 0);
        assert!(encode(&vec![0u8; MAX_FRAME + 1]).is_err());
        assert!(encode(&vec![0u8; MAX_FRAME]).is_ok());
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn round_trip() {
        let (mut a, mut b) = tokio::io::duplex(1024);
        write_frame(&mut a, b"hello").await.unwrap();
        write_frame(&mut a, b"").await.unwrap();
        assert_eq!(read_frame(&mut b).await.unwrap(), b"hello");
        assert_eq!(read_frame(&mut b).await.unwrap(), b"");
    }

    #[cfg(feature = "tokio")]
    #[tokio::test]
    async fn oversize_is_refused() {
        let (mut a, _b) = tokio::io::duplex(16);
        assert!(write_frame(&mut a, &vec![0u8; MAX_FRAME + 1]).await.is_err());
    }
}
