//! The phone's address announcement: one UDP packet,
//! `nonce(24) || XChaCha20-Poly1305(hello_key, nonce, aad, {ip, port, seq})`.
//! No plaintext identifier, so a stranger who receives it sees random bytes.

use chacha20poly1305::{
    XChaCha20Poly1305, XNonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};

const AAD: &[u8] = b"bwphone/v3/hello";
const NONCE_LEN: usize = 24;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Hello {
    pub ip: String,
    pub port: u16,
    /// Monotonic. The PC ignores anything not higher than the last one seen.
    pub seq: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum HelloError {
    #[error("packet too short")]
    Short,
    #[error("does not authenticate under this pairing's hello key")]
    Auth,
    #[error("malformed body")]
    Body,
}

pub fn seal(hello_key: &[u8; 32], hello: &Hello) -> Vec<u8> {
    let mut nonce = [0u8; NONCE_LEN];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let body = serde_json::to_vec(hello).expect("Hello always serialises");
    let ct = XChaCha20Poly1305::new(hello_key.into())
        .encrypt(XNonce::from_slice(&nonce), Payload { msg: &body, aad: AAD })
        .expect("XChaCha20-Poly1305 encryption does not fail");
    [nonce.as_slice(), &ct].concat()
}

pub fn open(hello_key: &[u8; 32], packet: &[u8]) -> Result<Hello, HelloError> {
    if packet.len() < NONCE_LEN + 16 {
        return Err(HelloError::Short);
    }
    let (nonce, ct) = packet.split_at(NONCE_LEN);
    let body = XChaCha20Poly1305::new(hello_key.into())
        .decrypt(XNonce::from_slice(nonce), Payload { msg: ct, aad: AAD })
        .map_err(|_| HelloError::Auth)?;
    serde_json::from_slice(&body).map_err(|_| HelloError::Body)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn seal_open_and_reject_other_keys() {
        let key = [5u8; 32];
        let h = Hello { ip: "10.0.0.7".into(), port: 8731, seq: 12 };
        let pkt = seal(&key, &h);
        assert_eq!(open(&key, &pkt).unwrap(), h);
        assert!(matches!(open(&[6u8; 32], &pkt), Err(HelloError::Auth)));
        let mut bad = pkt.clone();
        *bad.last_mut().unwrap() ^= 1;
        assert!(matches!(open(&key, &bad), Err(HelloError::Auth)));
        assert_ne!(seal(&key, &h), pkt, "nonce must be fresh");
    }
}
