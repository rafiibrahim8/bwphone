//! The responder side of the SDK's Noise NN channel
//! (`bitwarden-ipc/src/crypto_provider/noise/{handshake,transport_state}.rs`).
//!
//! - No prologue, no static keys, empty handshake payloads. NN is
//!   encrypted but not authenticated: whoever answers the pipe is "the
//!   desktop app", as with `setupEncryption`. The real gate is
//!   `SO_PEERCRED` on the daemon's socket.
//! - After the handshake the SDK does not use Noise's transport mode. It
//!   takes the raw split keys (initiator→responder, responder→initiator)
//!   and seals each payload itself with the suite's AEAD, empty associated
//!   data, and an explicit `u64` nonce carried in the frame. Nonces start
//!   at 1; a received nonce not above the last one is a replay.
//!
//! The handshake runs in snow, with its default DH and hash (the SDK's
//! resolver delegates to the same ones, so the bytes match) and an RNG
//! that never hands snow a P-256 scalar it would panic on. The transport
//! AEAD is done here, with `aes-gcm` / `chacha20poly1305`; the nonce layout
//! is snow's (bytes 4..12: big-endian for AES-GCM, little-endian for
//! ChaChaPoly). The AES round keys and the ChaCha key are wiped on drop; the
//! AES-GCM GHASH subkey is not, a temporary limitation (SPECIFICATION.md
//! §15). Wiping is hygiene, not a boundary in any case: snow
//! does not wipe its handshake state, whose ephemeral key and the public
//! handshake bytes re-derive both transport keys, and anything that can
//! read the daemon's memory can take the user key anyway.

use aes_gcm::{
    Aes256Gcm,
    aead::{AeadInPlace as _, KeyInit as _},
};
use chacha20poly1305::ChaCha20Poly1305;
use rand::RngCore as _;
use snow::{
    params::{CipherChoice, DHChoice, HashChoice},
    resolvers::{CryptoResolver, DefaultResolver},
    types::{Cipher, Dh, Hash, Random},
};
use zeroize::Zeroizing;

use crate::{
    IpcError,
    frame::{CipherSuite, HandshakeFinish, HandshakeStart, TransportFrame},
};

const MAX_MESSAGE: usize = 65535;
const TAG_LEN: usize = 16;
/// The largest plaintext one transport frame carries; the SDK fragments
/// anything larger, which no biometrics message comes near.
pub const MAX_PLAINTEXT: usize = MAX_MESSAGE - TAG_LEN;

/// The order of the P-256 group, big-endian.
const P256_N: [u8; 32] = [
    0xff, 0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xbc, 0xe6, 0xfa, 0xad,
    0xa7, 0x17, 0x9e, 0x84, 0xf3, 0xb9, 0xca, 0xc2, 0xfc, 0x63, 0x25, 0x51,
];

/// A 32-byte big-endian value snow's P-256 accepts as a private key.
fn is_p256_scalar(b: &[u8]) -> bool {
    b.len() == 32 && b.iter().any(|&x| x != 0) && b < &P256_N[..]
}

/// Fills `dest`, redrawing any 32-byte draw that is not a valid P-256
/// scalar: snow's `P256::generate` unwraps `SecretKey::from_bytes` and
/// would panic (abort, in release) about once in 2^32 handshakes. An
/// ephemeral key is the only 32-byte draw in NN, and for X25519 the
/// redraw only skips a 2^-32 sliver of keys.
fn fill_scalar_safe(dest: &mut [u8], mut fill: impl FnMut(&mut [u8]) -> Result<(), snow::Error>) -> Result<(), snow::Error> {
    loop {
        fill(dest)?;
        if dest.len() != 32 || is_p256_scalar(dest) {
            return Ok(());
        }
    }
}

struct ScalarSafeRng;

impl Random for ScalarSafeRng {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        fill_scalar_safe(dest, |d| rand::rngs::OsRng.try_fill_bytes(d).map_err(|_| snow::Error::Rng))
    }
}

/// snow's default primitives with [`ScalarSafeRng`].
struct Resolver;

impl CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(ScalarSafeRng))
    }
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        DefaultResolver.resolve_dh(choice)
    }
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        DefaultResolver.resolve_hash(choice)
    }
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        DefaultResolver.resolve_cipher(choice)
    }
}

/// One direction's AEAD, keyed once. The AES round keys and the ChaCha key
/// are wiped on drop; the AES-GCM GHASH subkey is not (SPECIFICATION.md §15,
/// "Temporary: GHASH subkey left in freed memory").
enum Aead {
    AesGcm(Box<Aes256Gcm>),
    ChaChaPoly(Box<ChaCha20Poly1305>),
}

impl Aead {
    fn new(suite: CipherSuite, key: &[u8; 32]) -> Self {
        match suite {
            CipherSuite::Noise_NN_25519_ChaChaPoly_BLAKE2s => Self::ChaChaPoly(Box::new(ChaCha20Poly1305::new(key.into()))),
            CipherSuite::Noise_NN_25519_AESGCM_SHA256 | CipherSuite::Noise_NN_P256_AESGCM_SHA256 => {
                Self::AesGcm(Box::new(Aes256Gcm::new(key.into())))
            }
        }
    }

    fn nonce(&self, n: u64) -> [u8; 12] {
        let mut out = [0u8; 12];
        match self {
            Self::AesGcm(_) => out[4..].copy_from_slice(&n.to_be_bytes()),
            Self::ChaChaPoly(_) => out[4..].copy_from_slice(&n.to_le_bytes()),
        }
        out
    }

    /// `ct || tag` → plaintext, in a buffer that never reallocates.
    fn open(&self, n: u64, sealed: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
        let (ct, tag) = sealed.split_at(sealed.len().checked_sub(TAG_LEN)?);
        let nonce = self.nonce(n);
        let mut buf = Zeroizing::new(ct.to_vec());
        let ok = match self {
            Self::AesGcm(c) => c.decrypt_in_place_detached((&nonce).into(), &[], &mut buf, tag.into()),
            Self::ChaChaPoly(c) => c.decrypt_in_place_detached((&nonce).into(), &[], &mut buf, tag.into()),
        };
        ok.ok().map(|()| buf)
    }

    /// plaintext → `ct || tag`. The plaintext is copied once, into the buffer
    /// that is then encrypted in place, sized so it never reallocates.
    fn seal(&self, n: u64, plaintext: &[u8]) -> Vec<u8> {
        let nonce = self.nonce(n);
        let mut buf = Vec::with_capacity(plaintext.len() + TAG_LEN);
        buf.extend_from_slice(plaintext);
        let tag = match self {
            Self::AesGcm(c) => c.encrypt_in_place_detached((&nonce).into(), &[], &mut buf),
            Self::ChaChaPoly(c) => c.encrypt_in_place_detached((&nonce).into(), &[], &mut buf),
        }
        .expect("a frame-sized plaintext is within both AEADs' limits");
        buf.extend_from_slice(&tag);
        buf
    }
}

/// One established channel. The transport keys live only inside the two
/// AEADs (see [`Aead`] for what is wiped on drop).
pub struct Session {
    send: Aead,
    recv: Aead,
    send_nonce: u64,
    recv_nonce: u64,
}

impl std::fmt::Debug for Session {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Session").field("send_nonce", &self.send_nonce).field("recv_nonce", &self.recv_nonce).finish()
    }
}

/// Answers a `HandshakeStart`: the finish to send back, and the session.
pub fn respond(start: &HandshakeStart) -> Result<(HandshakeFinish, Session), IpcError> {
    let params = start.ciphersuite.name().parse().map_err(|_| IpcError::Handshake)?;
    let mut state = snow::Builder::with_resolver(params, Box::new(Resolver)).build_responder().map_err(|_| IpcError::Handshake)?;
    let mut buf = Zeroizing::new(vec![0u8; MAX_MESSAGE]);
    state.read_message(&start.noise_frame, &mut buf).map_err(|_| IpcError::Handshake)?;
    let len = state.write_message(&[], &mut buf).map_err(|_| IpcError::Handshake)?;
    let finish = HandshakeFinish { noise_frame: buf[..len].to_vec() };
    if !state.is_handshake_finished() {
        return Err(IpcError::Handshake);
    }
    let (i2r, r2i) = state.dangerously_get_raw_split();
    let (i2r, r2i) = (Zeroizing::new(i2r), Zeroizing::new(r2i));
    let session = Session {
        send: Aead::new(start.ciphersuite, &r2i),
        recv: Aead::new(start.ciphersuite, &i2r),
        send_nonce: 0,
        recv_nonce: 0,
    };
    Ok((finish, session))
}

impl Session {
    /// Decrypts a frame from the extension. Replays and forgeries are errors
    /// and leave the state as it was.
    pub fn open(&mut self, frame: &TransportFrame) -> Result<Zeroizing<Vec<u8>>, IpcError> {
        if frame.nonce <= self.recv_nonce {
            return Err(IpcError::Replay);
        }
        if frame.payload.len() < TAG_LEN || frame.payload.len() > MAX_MESSAGE {
            return Err(IpcError::Decrypt);
        }
        let out = self.recv.open(frame.nonce, &frame.payload).ok_or(IpcError::Decrypt)?;
        self.recv_nonce = frame.nonce;
        Ok(out)
    }

    /// Encrypts a payload for the extension under the next nonce.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<TransportFrame, IpcError> {
        if plaintext.len() > MAX_PLAINTEXT {
            return Err(IpcError::TooLarge);
        }
        // A reused nonce breaks the AEAD; 2^64 messages cannot happen, but never wrap.
        self.send_nonce = self.send_nonce.checked_add(1).ok_or(IpcError::TooLarge)?;
        Ok(TransportFrame { payload: self.send.seal(self.send_nonce, plaintext).into(), nonce: self.send_nonce })
    }
}

/// The extension's side, built the way the SDK builds it: for tests that
/// play the browser. Not used by the daemon.
#[cfg(any(test, feature = "browser"))]
pub mod initiator {
    use super::*;

    /// snow's own cipher, so tests cross-check [`Aead`] against it.
    fn transport_cipher(suite: CipherSuite) -> CipherChoice {
        match suite {
            CipherSuite::Noise_NN_25519_ChaChaPoly_BLAKE2s => CipherChoice::ChaChaPoly,
            CipherSuite::Noise_NN_25519_AESGCM_SHA256 | CipherSuite::Noise_NN_P256_AESGCM_SHA256 => CipherChoice::AESGCM,
        }
    }

    pub struct Initiator {
        pub suite: CipherSuite,
        state: Option<snow::HandshakeState>,
        send_key: [u8; 32],
        recv_key: [u8; 32],
        pub send_nonce: u64,
        recv_nonce: u64,
    }

    impl Initiator {
        pub fn start(suite: CipherSuite) -> (Self, HandshakeStart) {
            let mut state = snow::Builder::new(suite.name().parse().unwrap()).build_initiator().unwrap();
            let mut buf = vec![0u8; MAX_MESSAGE];
            let len = state.write_message(&[], &mut buf).unwrap();
            let me = Self { suite, state: Some(state), send_key: [0; 32], recv_key: [0; 32], send_nonce: 0, recv_nonce: 0 };
            (me, HandshakeStart { ciphersuite: suite, noise_frame: buf[..len].to_vec() })
        }

        pub fn finish(&mut self, finish: &HandshakeFinish) {
            let mut state = self.state.take().unwrap();
            let mut buf = vec![0u8; MAX_MESSAGE];
            state.read_message(&finish.noise_frame, &mut buf).unwrap();
            let (i2r, r2i) = state.dangerously_get_raw_split();
            (self.send_key, self.recv_key) = (i2r, r2i);
        }

        fn aead(&self, key: &[u8; 32]) -> Box<dyn snow::types::Cipher> {
            let mut c = DefaultResolver.resolve_cipher(&transport_cipher(self.suite)).unwrap();
            c.set(key);
            c
        }

        pub fn seal(&mut self, plaintext: &[u8]) -> TransportFrame {
            self.send_nonce += 1;
            let mut out = vec![0u8; plaintext.len() + TAG_LEN];
            let len = self.aead(&self.send_key).encrypt(self.send_nonce, &[], plaintext, &mut out);
            out.truncate(len);
            TransportFrame { payload: out.into(), nonce: self.send_nonce }
        }

        pub fn open(&mut self, frame: &TransportFrame) -> Vec<u8> {
            assert!(frame.nonce > self.recv_nonce, "responder reused a nonce");
            let mut out = vec![0u8; frame.payload.len()];
            let len = self.aead(&self.recv_key).decrypt(frame.nonce, &[], &frame.payload, &mut out).unwrap();
            self.recv_nonce = frame.nonce;
            out.truncate(len);
            out
        }
    }

}

#[cfg(test)]
pub(crate) mod tests {
    use super::{initiator::Initiator, *};

    #[test]
    fn every_suite_round_trips_both_ways() {
        for suite in [
            CipherSuite::Noise_NN_P256_AESGCM_SHA256,
            CipherSuite::Noise_NN_25519_AESGCM_SHA256,
            CipherSuite::Noise_NN_25519_ChaChaPoly_BLAKE2s,
        ] {
            let (mut browser, start) = Initiator::start(suite);
            let (finish, mut session) = respond(&start).unwrap();
            browser.finish(&finish);

            let frame = browser.seal(b"request");
            assert_eq!(frame.nonce, 1, "the SDK's first nonce is 1");
            assert_eq!(&*session.open(&frame).unwrap(), b"request");
            let reply = session.seal(b"reply").unwrap();
            assert_eq!(reply.nonce, 1);
            assert_eq!(browser.open(&reply), b"reply");
            assert_eq!(browser.open(&session.seal(b"again").unwrap()), b"again");
        }
    }

    #[test]
    fn p256_ephemeral_is_an_uncompressed_point() {
        let (_, start) = Initiator::start(CipherSuite::Noise_NN_P256_AESGCM_SHA256);
        assert_eq!(start.noise_frame.len(), 65);
        assert_eq!(start.noise_frame[0], 0x04);
    }

    #[test]
    fn replays_forgeries_and_skips() {
        let (mut browser, start) = Initiator::start(CipherSuite::Noise_NN_P256_AESGCM_SHA256);
        let (finish, mut session) = respond(&start).unwrap();
        browser.finish(&finish);

        let first = browser.seal(b"one");
        session.open(&first).unwrap();
        assert!(matches!(session.open(&first), Err(IpcError::Replay)));

        let mut forged = browser.seal(b"two");
        forged.payload[0] ^= 1;
        assert!(matches!(session.open(&forged), Err(IpcError::Decrypt)));
        // A failed frame does not advance the window: the next honest one still opens.
        browser.send_nonce += 5; // skipping ahead is allowed, going back is not
        assert_eq!(&*session.open(&browser.seal(b"three")).unwrap(), b"three");

        let mut short = browser.seal(b"");
        short.payload = vec![0u8; 3].into();
        assert!(matches!(session.open(&short), Err(IpcError::Decrypt)));
    }

    #[test]
    fn p256_scalar_range() {
        assert!(!is_p256_scalar(&[0u8; 32]));
        assert!(!is_p256_scalar(&[0xffu8; 32]));
        assert!(!is_p256_scalar(&P256_N));
        let mut below = P256_N;
        below[31] -= 1;
        assert!(is_p256_scalar(&below));
        assert!(is_p256_scalar(&[1u8; 32]));
        assert!(!is_p256_scalar(&[1u8; 31]));
    }

    #[test]
    fn out_of_range_draws_are_redrawn() {
        let mut draws = vec![[0xffu8; 32], [0u8; 32], P256_N, [7u8; 32]].into_iter();
        let mut dest = [0u8; 32];
        fill_scalar_safe(&mut dest, |d| {
            d.copy_from_slice(&draws.next().unwrap());
            Ok(())
        })
        .unwrap();
        assert_eq!(dest, [7u8; 32]);
        // Other lengths pass through untouched.
        let mut short = [0u8; 16];
        fill_scalar_safe(&mut short, |d| {
            d.fill(0);
            Ok(())
        })
        .unwrap();
        assert!(fill_scalar_safe(&mut dest, |_| Err(snow::Error::Rng)).is_err());
    }

    #[test]
    fn a_garbage_handshake_is_refused() {
        let start = HandshakeStart { ciphersuite: CipherSuite::Noise_NN_P256_AESGCM_SHA256, noise_frame: vec![4, 1, 2] };
        assert!(matches!(respond(&start), Err(IpcError::Handshake)));
    }
}
