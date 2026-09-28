//! The Bitwarden browser extension's native-messaging protocol, as the
//! daemon must speak it. Verified against `bitwarden/clients` at
//! `browser-v2026.9.0`: `apps/browser/src/background/nativeMessaging.background.ts`
//! and `apps/desktop/src/services/biometric-message-handler.service.ts`.
//!
//! - [`frame`]: 4-byte native-endian length prefix on stdio.
//! - [`handshake`]: `setupEncryption`, RSA-OAEP-SHA1 of a 64-byte session key.
//! - [`session`]: EncString type 2 over every later message.
//! - [`msg`]: the commands, statuses and reply shapes.
//! - [`peer`]: one connection's state machine over all of the above.

pub mod frame;
pub mod handshake;
pub mod msg;
pub mod peer;
pub mod session;

use base64::Engine as _;

#[derive(Debug, thiserror::Error)]
pub enum NmError {
    #[error("malformed json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("base64: {0}")]
    Base64(#[from] base64::DecodeError),
    #[error("setupEncryption public key is not an RSA SPKI key")]
    PublicKey,
    #[error("encryption type {0} is not AesCbc256_HmacSha256_B64")]
    EncryptionType(u8),
    #[error("{0}")]
    Malformed(&'static str),
    #[error("message does not authenticate under this session key")]
    Mac,
    #[error("no secure channel: setupEncryption has not completed")]
    NoChannel,
}

/// Standard base64 with padding, as `Utils.fromBufferToB64` produces.
pub fn b64(bytes: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(bytes)
}

pub fn unb64(s: &str) -> Result<Vec<u8>, base64::DecodeError> {
    base64::engine::general_purpose::STANDARD.decode(s)
}

#[cfg(test)]
pub(crate) mod tests {
    use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::DecodePrivateKey as _};

    /// A fixed RSA-2048 keypair standing in for the extension's per-session key.
    const EXTENSION_KEY: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCq5QDN64hZSm6z
7OLtYSVJxx/hDsAVSOH5jeS3tPADQlMaB1MEgBwLKr00wSQtw17tJBK0LI3+/Ima
+HtZJu04LEhE9/Nh1rkToAB0+BObzkpYx9V4P0UhJgdo8x1bjupLrfafVos85CEL
RxDA7gtOJcqkkFItrxBIJjLx+yGDmXwYioDJve+T7tePxHAdqgY4ItatHmYPo3ey
wHCfd82w36sFdnWM0ex2T1sXEMJUFyErnAyr86m8np2ohZVBIhXE5o3KjQ2V7nI2
eiaIz67n8ag97bqgwkFIX5IIsSitsIAXnNUWnPpb+anDz1FC+VjlKA01KPm90ZP+
4TM9sAyjAgMBAAECggEAEVKDIVxVhs9/pydE3VDyiabweUyYdc/ccAJNA74Ichwf
9kx1wsgFj7A2W4mUVDswfRMh/jdh8U3B2P6E6kWC2CXM8Yi8l9c/DVkzkqeuvSVM
7fDbl4O6SyDisWWrPSOgZiltDTulg3eQTedXMGcwqCw2fTXPzqenG9kbYuHUxNT4
kwEAsMgTj0hgRA11M8nowQfeVS3Qtzjxb1Mz2lwO9OfsEBgQwNI0IYES9bkqo5bi
MctD8wufWhtdjKzwGA7WseczY5P1m678UmRrZcCOXJzA/+nXlqinJI7zJUrwP5nY
pJlH8IbVMf6K+6gEWuiFEzNsUH1vUJyV4gftas1pAQKBgQDRTZF1YLXd8QzSX0p7
v2QmmO1wmJgTa8kSpWt695wInDkEr0xIgF9Ac7D4fTVByMv5yqxdrJtLAbn9IkMf
9w0HQL+K4T4C+QzTmdKxh19JMFHBGV2mpas+QBIpl7gpITujbW4FOkTpYAIDB+5x
PCP9FC1VxXik9ZlwUu+lGh6BgQKBgQDRBbgfMB8jqFuLUchn2oLlGLDvCcRo39Rb
j8r9sC+TQQLyVJ5LErspV9qtaKQcW5p4jLJEC7tk8eVfW20qc3kvUiyWhA8j6B7u
chS3jVRWkNoln7GprVA1Rrp6gXaRnvNUkvyT56Thg3kPC5xu7I5f35qpuHS45iCw
nZOfrwBYIwKBgGOCE2PQxOZt0gC6mTjYN486Kbjcc4DYP9KDnuPpkN9vFpSpmwTl
M2P7HOom7QkHpCJwPx6SD4rLmVdF0NADrsgB+o7Wo5raOUTo3wjUKXMsa9H4c1Pl
c9K2t2va3A2B5U6/mg0WNOkXYh16ydxAEYQi8aLTrZYPxhFm/NRr5JEBAoGAaYe5
rgVds2MM1Qo1ZDmuXHxa2FTWFRzs2k1+7xZE7tOj6TVPthd+5yC0B1kNgkO9eZ+P
YUuLESwP4lUGiKhERt/2IwgJnNdUxo5SZ1mzewEnIle+GyylkkBjZfZ3Jo5ZzBlp
7ELHvBPkyvPRxy8nsr/yFj5KsA9/8audHMH+KoECgYEAgL/h47tMbzqAx54kwTxU
XqCsgOly75BFu0QFMGlix3zMDeTf7HSO97runCicOx3cLjjqTlFez5WlokmdQJz0
a+Nf7b59rnfNXVTgESem0Wx3gJLYGs97QokCn8aN3GCWekfdjBJK+O6tAa9gsOH4
PQnakctn8mhKxp4yVRCI4Pk=
-----END PRIVATE KEY-----";

    pub fn extension_keypair() -> (RsaPrivateKey, RsaPublicKey) {
        let private = RsaPrivateKey::from_pkcs8_pem(EXTENSION_KEY).unwrap();
        let public = RsaPublicKey::from(&private);
        (private, public)
    }
}
