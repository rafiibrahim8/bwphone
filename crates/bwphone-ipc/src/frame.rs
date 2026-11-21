//! The CBOR frames the SDK's Noise crypto provider puts in an envelope's
//! `payload` (`bitwarden-ipc/src/crypto_provider/noise/crypto_provider.rs`,
//! `Frame`). serde's default externally tagged enum, through `ciborium`:
//! a newtype variant is a one-entry map keyed by the variant name, and
//! `CryptoInvalidated` is the bare text string.

use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use crate::IpcError;

/// The suite is the initiator's choice, named in its `HandshakeStart`.
/// The browser uses the default, `Noise_NN_P256_AESGCM_SHA256`.
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum CipherSuite {
    Noise_NN_25519_ChaChaPoly_BLAKE2s,
    Noise_NN_25519_AESGCM_SHA256,
    Noise_NN_P256_AESGCM_SHA256,
}

impl CipherSuite {
    pub fn name(&self) -> &'static str {
        match self {
            Self::Noise_NN_25519_ChaChaPoly_BLAKE2s => "Noise_NN_25519_ChaChaPoly_BLAKE2s",
            Self::Noise_NN_25519_AESGCM_SHA256 => "Noise_NN_25519_AESGCM_SHA256",
            Self::Noise_NN_P256_AESGCM_SHA256 => "Noise_NN_P256_AESGCM_SHA256",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HandshakeStart {
    pub ciphersuite: CipherSuite,
    /// A CBOR array of integers, not a byte string: `Vec<u8>` without `serde_bytes`.
    pub noise_frame: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct HandshakeFinish {
    pub noise_frame: Vec<u8>,
}

/// AEAD ciphertext under the raw split keys, with its explicit nonce.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TransportFrame {
    /// A CBOR byte string.
    pub payload: ByteBuf,
    pub nonce: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Frame {
    HandshakeStart(HandshakeStart),
    HandshakeFinish(HandshakeFinish),
    TransportFrame(TransportFrame),
    CryptoInvalidated,
}

impl Frame {
    pub fn to_cbor(&self) -> Vec<u8> {
        let mut buf = Vec::new();
        ciborium::into_writer(self, &mut buf).expect("writing CBOR to a Vec cannot fail");
        buf
    }

    pub fn from_cbor(bytes: &[u8]) -> Result<Self, IpcError> {
        ciborium::from_reader(bytes).map_err(|_| IpcError::Cbor)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A complete `HandshakeStart` with `noise_frame = [4,1,2]`, as the SDK's
    /// own `ciborium` writes it (`.ignore/SDK-IPC.md`).
    const SDK_HANDSHAKE_START: [u8; 74] = [
        161, 110, 72, 97, 110, 100, 115, 104, 97, 107, 101, 83, 116, 97, 114, 116, 162, 107, 99, 105, 112, 104, 101, 114,
        115, 117, 105, 116, 101, 120, 27, 78, 111, 105, 115, 101, 95, 78, 78, 95, 80, 50, 53, 54, 95, 65, 69, 83, 71, 67,
        77, 95, 83, 72, 65, 50, 53, 54, 107, 110, 111, 105, 115, 101, 95, 102, 114, 97, 109, 101, 131, 4, 1, 2,
    ];

    #[test]
    fn handshake_start_matches_the_sdk_bytes() {
        let frame = Frame::HandshakeStart(HandshakeStart {
            ciphersuite: CipherSuite::Noise_NN_P256_AESGCM_SHA256,
            noise_frame: vec![4, 1, 2],
        });
        assert_eq!(frame.to_cbor(), SDK_HANDSHAKE_START);
        assert_eq!(Frame::from_cbor(&SDK_HANDSHAKE_START).unwrap(), frame);
    }

    #[test]
    fn crypto_invalidated_is_a_bare_string() {
        let mut expected = vec![0x71];
        expected.extend_from_slice(b"CryptoInvalidated");
        assert_eq!(Frame::CryptoInvalidated.to_cbor(), expected);
        assert_eq!(Frame::from_cbor(&expected).unwrap(), Frame::CryptoInvalidated);
    }

    #[test]
    fn finish_is_transparent_and_transport_payload_is_a_byte_string() {
        let finish = Frame::HandshakeFinish(HandshakeFinish { noise_frame: vec![7] }).to_cbor();
        // {"HandshakeFinish": [7]}
        let mut expected = vec![0xa1, 0x6f];
        expected.extend_from_slice(b"HandshakeFinish");
        expected.extend_from_slice(&[0x81, 0x07]);
        assert_eq!(finish, expected);

        let transport = Frame::TransportFrame(TransportFrame { payload: ByteBuf::from(vec![9, 9]), nonce: 1 }).to_cbor();
        // {"TransportFrame": {"payload": h'0909', "nonce": 1}}
        let mut expected = vec![0xa1, 0x6e];
        expected.extend_from_slice(b"TransportFrame");
        expected.extend_from_slice(&[0xa2, 0x67]);
        expected.extend_from_slice(b"payload");
        expected.extend_from_slice(&[0x42, 9, 9, 0x65]);
        expected.extend_from_slice(b"nonce");
        expected.push(0x01);
        assert_eq!(transport, expected);
    }

    #[test]
    fn garbage_and_unknown_suites_are_errors() {
        assert!(Frame::from_cbor(b"").is_err());
        assert!(Frame::from_cbor(&[0xff, 0x00]).is_err());
        let mut odd = SDK_HANDSHAKE_START;
        odd[40] = b'X'; // corrupt the suite name
        assert!(Frame::from_cbor(&odd).is_err());
    }
}
