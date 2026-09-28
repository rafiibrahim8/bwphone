//! Values derived once, at pairing, from the pairing transcript:
//! `SHA-256(NKpsk0 handshake hash || PairHello bytes)`. Folding the PairHello
//! in means the six words also cover the phone's X25519 key.

use base64::Engine as _;
use hkdf::Hkdf;
use sha2::{Digest as _, Sha256};
use zeroize::Zeroizing;

pub const QR_VERSION: u8 = 3;

pub fn transcript(handshake_hash: &[u8; 32], pair_hello_bytes: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(handshake_hash);
    h.update(pair_hello_bytes);
    h.finalize().into()
}

fn expand<const N: usize>(transcript: &[u8; 32], info: &[u8]) -> [u8; N] {
    let mut out = [0u8; N];
    Hkdf::<Sha256>::new(None, transcript)
        .expand(info, &mut out)
        .expect("valid HKDF-SHA256 length");
    out
}

/// Six BIP-39 words (66 bits) both screens show and the person compares.
pub fn words(transcript: &[u8; 32]) -> [&'static str; 6] {
    let bits: [u8; 9] = expand(transcript, b"bwphone/v3/sas");
    let list = bip39::Language::English.word_list();
    let mut acc: u128 = 0;
    for b in bits {
        acc = (acc << 8) | b as u128;
    }
    // 72 bits read; keep the top 66.
    acc >>= 6;
    let mut out = [""; 6];
    for (i, w) in out.iter_mut().enumerate() {
        let idx = ((acc >> (11 * (5 - i))) & 0x7FF) as usize;
        *w = list[idx];
    }
    out
}

pub fn hello_key(transcript: &[u8; 32]) -> Zeroizing<[u8; 32]> {
    Zeroizing::new(expand(transcript, b"bwphone/v3/hello"))
}

pub fn pairing_id(transcript: &[u8; 32]) -> [u8; 16] {
    expand(transcript, b"bwphone/v3/pairing-id")
}

/// What the PC's QR code carries.
#[derive(Debug, Clone, PartialEq)]
pub struct QrPayload {
    pub pc_pub: [u8; 32],
    pub token: [u8; 32],
    pub ip: std::net::Ipv4Addr,
    pub pair_port: u16,
    pub hello_port: u16,
}

impl QrPayload {
    /// `version(1) || pc_pub(32) || token(32) || ipv4(4) || pair_port(2) || hello_port(2)`,
    /// base64url without padding.
    pub fn encode(&self) -> String {
        let mut b = Vec::with_capacity(73);
        b.push(QR_VERSION);
        b.extend_from_slice(&self.pc_pub);
        b.extend_from_slice(&self.token);
        b.extend_from_slice(&self.ip.octets());
        b.extend_from_slice(&self.pair_port.to_be_bytes());
        b.extend_from_slice(&self.hello_port.to_be_bytes());
        base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(b)
    }

    pub fn decode(s: &str) -> Option<Self> {
        let b = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(s.trim()).ok()?;
        if b.len() != 73 || b[0] != QR_VERSION {
            return None;
        }
        Some(Self {
            pc_pub: b[1..33].try_into().ok()?,
            token: b[33..65].try_into().ok()?,
            ip: std::net::Ipv4Addr::new(b[65], b[66], b[67], b[68]),
            pair_port: u16::from_be_bytes([b[69], b[70]]),
            hello_port: u16::from_be_bytes([b[71], b[72]]),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn qr_round_trip_and_rejects_other_versions() {
        let q = QrPayload {
            pc_pub: [1; 32],
            token: [2; 32],
            ip: "192.168.1.20".parse().unwrap(),
            pair_port: 40000,
            hello_port: 8732,
        };
        assert_eq!(QrPayload::decode(&q.encode()), Some(q.clone()));
        let mut raw = base64::engine::general_purpose::URL_SAFE_NO_PAD.decode(q.encode()).unwrap();
        raw[0] = 2;
        assert_eq!(QrPayload::decode(&base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw)), None);
    }

    #[test]
    fn words_depend_on_the_whole_transcript() {
        let a = transcript(&[0; 32], b"{\"x25519_pub\":\"A\"}");
        let b = transcript(&[0; 32], b"{\"x25519_pub\":\"B\"}");
        assert_ne!(words(&a), words(&b));
        assert_eq!(words(&a), words(&a));
    }
}
