//! Everything the PC and the phone must agree on byte for byte: the Noise
//! channel and its framing, the message types, and the values both sides derive
//! from a handshake (emoji, pairing words, hello key, mDNS name).
//!
//! No platform code lives here, so the same crate can later be exposed to
//! Kotlin through uniffi.

pub mod emoji;
pub mod frame;
pub mod hello;
pub mod mdns;
pub mod msg;
pub mod noise;
pub mod pairing;

use base64::Engine as _;
use rand::RngCore as _;
use sha2::{Digest as _, Sha256};

/// Protocol version carried in every message and in the Noise prologue.
pub const PROTOCOL_VERSION: u8 = 3;

/// TCP port the phone listens on unless pairing chose another.
pub const DEFAULT_PHONE_PORT: u16 = 8731;

/// UDP port `bwphone-hello` listens on for phone hellos unless pairing chose another.
pub const DEFAULT_HELLO_PORT: u16 = 8732;

pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn unb64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(s)
}

/// A fresh random identifier, used for `account_id` and `req_id`.
pub fn random_id() -> [u8; 16] {
    let mut id = [0u8; 16];
    rand::rngs::OsRng.fill_bytes(&mut id);
    id
}

/// Human-comparable fingerprint of a public key: the first 10 bytes of its
/// SHA-256, as five groups of four hex digits.
pub fn short_fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest[..10]
        .chunks(2)
        .map(|pair| format!("{:02x}{:02x}", pair[0], pair[1]))
        .collect::<Vec<_>>()
        .join(" ")
}

#[cfg(test)]
mod tests {
    #[test]
    fn fingerprint_shape() {
        let fp = super::short_fingerprint(b"key");
        assert_eq!(fp.len(), 24);
        assert_eq!(fp.split(' ').count(), 5);
    }
}
