//! The two Noise handshakes and the encrypted channel they produce.
//!
//! - Steady state: `Noise_KK_25519_ChaChaPoly_SHA256`. The PC initiates,
//!   the phone responds; both statics were exchanged at pairing.
//! - Pairing: `Noise_NKpsk0_25519_ChaChaPoly_SHA256`. The phone initiates,
//!   knowing the PC's static from the QR code, with the QR token as PSK.
//!
//! Both handshake messages always carry empty payloads; the first request
//! travels as the first transport message, so it is forward-secret.
//!
//! # Why the core is sans-I/O
//!
//! The phone runs this same crate, through uniffi, so both ends share one
//! Noise implementation and agreement is structural rather than hoped for.
//! Kotlin cannot hand a socket across that boundary, and the phone must own
//! its socket anyway: it binds it to the Wi-Fi `Network`, never cellular or
//! VPN. So [`Handshake`] and [`Transport`] are state machines over byte
//! buffers — a frame in, a frame out — and the tokio [`Channel`] is one thin
//! driver for them, used on the PC. The fake phone uses the same driver;
//! the real one drives the state machines from Kotlin.

use snow::{Builder, HandshakeState, TransportState, params::NoiseParams};
use zeroize::Zeroizing;

use crate::frame::MAX_FRAME;

pub const KK_PARAMS: &str = "Noise_KK_25519_ChaChaPoly_SHA256";
pub const PAIR_PARAMS: &str = "Noise_NKpsk0_25519_ChaChaPoly_SHA256";

const KK_PROLOGUE_PREFIX: &[u8] = b"bwphone/v3/kk/";
const PAIR_PROLOGUE: &[u8] = b"bwphone/v3/pair";

#[derive(Debug, thiserror::Error)]
pub enum ChannelError {
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("noise: {0}")]
    Noise(#[from] snow::Error),
    #[error("malformed message: {0}")]
    Json(#[from] serde_json::Error),
    #[error("handshake is not finished")]
    NotFinished,
}

/// An X25519 static keypair. The private half is zeroised on drop.
pub struct StaticKeypair {
    pub private: Zeroizing<[u8; 32]>,
    pub public: [u8; 32],
}

impl StaticKeypair {
    pub fn generate() -> Result<Self, ChannelError> {
        let kp = Builder::new(params(KK_PARAMS)).generate_keypair()?;
        let mut private = Zeroizing::new([0u8; 32]);
        private.copy_from_slice(&kp.private);
        let mut public = [0u8; 32];
        public.copy_from_slice(&kp.public);
        Ok(Self { private, public })
    }

    /// The keypair a stored private key belongs to: what the phone does at
    /// start, and the PC after reading the wallet.
    pub fn from_private(private: &[u8; 32]) -> Self {
        use snow::resolvers::CryptoResolver as _;
        let mut dh = snow::resolvers::DefaultResolver
            .resolve_dh(&snow::params::DHChoice::Curve25519)
            .expect("Curve25519 is always resolvable");
        dh.set(private);
        let mut public = [0u8; 32];
        public.copy_from_slice(dh.pubkey());
        Self { private: Zeroizing::new(*private), public }
    }
}

/// Prologue for the steady-state handshake: protocol version plus pairing ID.
/// A single byte of disagreement fails the handshake.
pub fn kk_prologue(pairing_id: &[u8; 16]) -> Vec<u8> {
    [KK_PROLOGUE_PREFIX, pairing_id.as_slice()].concat()
}

fn params(s: &str) -> NoiseParams {
    s.parse().expect("hard-coded Noise params parse")
}

/// A handshake in progress. Ask whose turn it is, write or read one
/// message, repeat until finished, then take the [`Transport`].
pub struct Handshake {
    hs: HandshakeState,
}

impl Handshake {
    /// PC side of the steady-state handshake.
    pub fn kk_initiator(local_private: &[u8; 32], remote_public: &[u8; 32], pairing_id: &[u8; 16]) -> Result<Self, ChannelError> {
        let hs = Builder::new(params(KK_PARAMS))
            .local_private_key(local_private)?
            .remote_public_key(remote_public)?
            .prologue(&kk_prologue(pairing_id))?
            .build_initiator()?;
        Ok(Self { hs })
    }

    /// Phone side of the steady-state handshake.
    pub fn kk_responder(local_private: &[u8; 32], remote_public: &[u8; 32], pairing_id: &[u8; 16]) -> Result<Self, ChannelError> {
        let hs = Builder::new(params(KK_PARAMS))
            .local_private_key(local_private)?
            .remote_public_key(remote_public)?
            .prologue(&kk_prologue(pairing_id))?
            .build_responder()?;
        Ok(Self { hs })
    }

    /// Phone side of pairing: initiator, with the PC key and token from the QR code.
    pub fn pair_initiator(pc_public: &[u8; 32], token: &[u8; 32]) -> Result<Self, ChannelError> {
        let hs = Builder::new(params(PAIR_PARAMS))
            .remote_public_key(pc_public)?
            .psk(0, token)?
            .prologue(PAIR_PROLOGUE)?
            .build_initiator()?;
        Ok(Self { hs })
    }

    /// PC side of pairing: responder, holding the static key shown in the QR code.
    pub fn pair_responder(pc_private: &[u8; 32], token: &[u8; 32]) -> Result<Self, ChannelError> {
        let hs = Builder::new(params(PAIR_PARAMS))
            .local_private_key(pc_private)?
            .psk(0, token)?
            .prologue(PAIR_PROLOGUE)?
            .build_responder()?;
        Ok(Self { hs })
    }

    pub fn is_my_turn(&self) -> bool {
        self.hs.is_my_turn()
    }

    pub fn is_finished(&self) -> bool {
        self.hs.is_handshake_finished()
    }

    /// The next handshake message to send, always with an empty payload.
    pub fn write_message(&mut self) -> Result<Vec<u8>, ChannelError> {
        let mut buf = vec![0u8; MAX_FRAME];
        let n = self.hs.write_message(&[], &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    /// Consume the peer's handshake message. A non-empty payload is a peer
    /// we do not speak to.
    pub fn read_message(&mut self, message: &[u8]) -> Result<(), ChannelError> {
        let mut buf = vec![0u8; MAX_FRAME];
        let n = self.hs.read_message(message, &mut buf)?;
        if n != 0 {
            return Err(snow::Error::Decrypt.into());
        }
        Ok(())
    }

    pub fn into_transport(self) -> Result<Transport, ChannelError> {
        if !self.hs.is_handshake_finished() {
            return Err(ChannelError::NotFinished);
        }
        let mut handshake_hash = [0u8; 32];
        handshake_hash.copy_from_slice(self.hs.get_handshake_hash());
        Ok(Transport { transport: self.hs.into_transport_mode()?, handshake_hash })
    }
}

/// The established channel's cipher states: one message in, one out.
pub struct Transport {
    transport: TransportState,
    handshake_hash: [u8; 32],
}

impl Transport {
    /// The final handshake hash. Identical on both ends of one session and
    /// never repeated across sessions; the emoji and pairing words derive from it.
    pub fn handshake_hash(&self) -> &[u8; 32] {
        &self.handshake_hash
    }

    /// One Noise transport message, ready to frame.
    pub fn seal(&mut self, plaintext: &[u8]) -> Result<Vec<u8>, ChannelError> {
        let mut buf = vec![0u8; MAX_FRAME];
        let n = self.transport.write_message(plaintext, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }

    pub fn open(&mut self, message: &[u8]) -> Result<Zeroizing<Vec<u8>>, ChannelError> {
        let mut buf = Zeroizing::new(vec![0u8; message.len()]);
        let n = self.transport.read_message(message, &mut buf)?;
        buf.truncate(n);
        Ok(buf)
    }
}

#[cfg(feature = "tokio")]
pub use io::{Channel, drive, kk_initiate, kk_respond, pair_initiate, pair_respond};

#[cfg(feature = "tokio")]
mod io {
    use serde::{Serialize, de::DeserializeOwned};
    use tokio::io::{AsyncRead, AsyncWrite};
    use zeroize::Zeroizing;

    use super::{ChannelError, Handshake, Transport};
    use crate::frame::{read_frame, write_frame};

    /// An established, encrypted channel over a stream: the PC's driver
    /// for a [`Transport`].
    pub struct Channel<S> {
        stream: S,
        transport: Transport,
    }

    impl<S: AsyncRead + AsyncWrite + Unpin> Channel<S> {
        pub fn handshake_hash(&self) -> &[u8; 32] {
            self.transport.handshake_hash()
        }

        pub async fn send(&mut self, plaintext: &[u8]) -> Result<(), ChannelError> {
            let message = self.transport.seal(plaintext)?;
            write_frame(&mut self.stream, &message).await?;
            Ok(())
        }

        pub async fn recv(&mut self) -> Result<Zeroizing<Vec<u8>>, ChannelError> {
            let frame = read_frame(&mut self.stream).await?;
            self.transport.open(&frame)
        }

        pub async fn send_json<T: Serialize>(&mut self, value: &T) -> Result<(), ChannelError> {
            let bytes = Zeroizing::new(serde_json::to_vec(value)?);
            self.send(&bytes).await
        }

        pub async fn recv_json<T: DeserializeOwned>(&mut self) -> Result<T, ChannelError> {
            let bytes = self.recv().await?;
            Ok(serde_json::from_slice(&bytes)?)
        }

        pub fn into_inner(self) -> S {
            self.stream
        }
    }

    /// Run a handshake to completion over a stream.
    pub async fn drive<S: AsyncRead + AsyncWrite + Unpin>(
        mut hs: Handshake,
        mut stream: S,
    ) -> Result<Channel<S>, ChannelError> {
        while !hs.is_finished() {
            if hs.is_my_turn() {
                let message = hs.write_message()?;
                write_frame(&mut stream, &message).await?;
            } else {
                let frame = read_frame(&mut stream).await?;
                hs.read_message(&frame)?;
            }
        }
        Ok(Channel { stream, transport: hs.into_transport()? })
    }

    /// PC side of the steady-state handshake.
    pub async fn kk_initiate<S: AsyncRead + AsyncWrite + Unpin>(
        stream: S,
        local_private: &[u8; 32],
        remote_public: &[u8; 32],
        pairing_id: &[u8; 16],
    ) -> Result<Channel<S>, ChannelError> {
        drive(Handshake::kk_initiator(local_private, remote_public, pairing_id)?, stream).await
    }

    /// Phone side of the steady-state handshake.
    pub async fn kk_respond<S: AsyncRead + AsyncWrite + Unpin>(
        stream: S,
        local_private: &[u8; 32],
        remote_public: &[u8; 32],
        pairing_id: &[u8; 16],
    ) -> Result<Channel<S>, ChannelError> {
        drive(Handshake::kk_responder(local_private, remote_public, pairing_id)?, stream).await
    }

    /// PC side of pairing: responder, holding the static key shown in the QR code.
    pub async fn pair_respond<S: AsyncRead + AsyncWrite + Unpin>(
        stream: S,
        pc_private: &[u8; 32],
        token: &[u8; 32],
    ) -> Result<Channel<S>, ChannelError> {
        drive(Handshake::pair_responder(pc_private, token)?, stream).await
    }

    /// Phone side of pairing: initiator, with the PC key and token from the QR code.
    pub async fn pair_initiate<S: AsyncRead + AsyncWrite + Unpin>(
        stream: S,
        pc_public: &[u8; 32],
        token: &[u8; 32],
    ) -> Result<Channel<S>, ChannelError> {
        drive(Handshake::pair_initiator(pc_public, token)?, stream).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pair_of_keys() -> (StaticKeypair, StaticKeypair) {
        (StaticKeypair::generate().unwrap(), StaticKeypair::generate().unwrap())
    }

    /// Both sides by hand, no I/O: what the phone does from Kotlin.
    #[test]
    fn kk_sans_io_round_trip() {
        let (pc, phone) = pair_of_keys();
        let id = [7u8; 16];
        let mut l = Handshake::kk_initiator(&pc.private, &phone.public, &id).unwrap();
        let mut p = Handshake::kk_responder(&phone.private, &pc.public, &id).unwrap();
        assert!(l.is_my_turn() && !p.is_my_turn());

        let m1 = l.write_message().unwrap();
        assert_eq!(m1.len(), 48, "32-byte ephemeral plus a 16-byte tag over an empty payload");
        p.read_message(&m1).unwrap();
        assert!(!l.is_my_turn() && p.is_my_turn());
        assert!(!l.is_finished() && !p.is_finished());

        let m2 = p.write_message().unwrap();
        assert!(p.is_finished());
        l.read_message(&m2).unwrap();
        assert!(l.is_finished());

        let mut lt = l.into_transport().unwrap();
        let mut pt = p.into_transport().unwrap();
        assert_eq!(lt.handshake_hash(), pt.handshake_hash());

        let ct = lt.seal(b"ping").unwrap();
        assert_ne!(&ct[..], b"ping");
        assert_eq!(&*pt.open(&ct).unwrap(), b"ping");
        let ct = pt.seal(b"pong").unwrap();
        assert_eq!(&*lt.open(&ct).unwrap(), b"pong");
        assert!(lt.open(&ct).is_err(), "a replayed message fails");
    }

    #[test]
    fn unfinished_handshake_has_no_transport() {
        let (pc, phone) = pair_of_keys();
        let l = Handshake::kk_initiator(&pc.private, &phone.public, &[0; 16]).unwrap();
        assert!(matches!(l.into_transport(), Err(ChannelError::NotFinished)));
    }

    #[test]
    fn from_private_recovers_the_public_key() {
        let kp = StaticKeypair::generate().unwrap();
        let again = StaticKeypair::from_private(&kp.private);
        assert_eq!(again.public, kp.public);
        assert_eq!(*again.private, *kp.private);
    }

    #[test]
    fn pairing_sans_io_and_wrong_token() {
        let pc = StaticKeypair::generate().unwrap();
        let token = [9u8; 32];
        let mut p = Handshake::pair_initiator(&pc.public, &token).unwrap();
        let mut l = Handshake::pair_responder(&pc.private, &token).unwrap();
        l.read_message(&p.write_message().unwrap()).unwrap();
        p.read_message(&l.write_message().unwrap()).unwrap();
        assert_eq!(p.into_transport().unwrap().handshake_hash(), l.into_transport().unwrap().handshake_hash());

        let mut p = Handshake::pair_initiator(&pc.public, &[8u8; 32]).unwrap();
        let mut l = Handshake::pair_responder(&pc.private, &token).unwrap();
        assert!(l.read_message(&p.write_message().unwrap()).is_err(), "pairing succeeded with the wrong token");
    }

    #[cfg(feature = "tokio")]
    mod with_tokio {
        use super::*;
        use crate::frame::MAX_FRAME;

        #[tokio::test]
        async fn kk_round_trip_and_matching_hash() {
            let (pc, phone) = pair_of_keys();
            let id = [7u8; 16];
            let (a, b) = tokio::io::duplex(MAX_FRAME * 2);
            let phone_pub = phone.public;
            let pc_pub = pc.public;
            let responder = tokio::spawn(async move {
                let mut ch = kk_respond(b, &phone.private, &pc_pub, &id).await.unwrap();
                let got = ch.recv().await.unwrap();
                ch.send(b"pong").await.unwrap();
                (got.to_vec(), *ch.handshake_hash())
            });
            let mut ch = kk_initiate(a, &pc.private, &phone_pub, &id).await.unwrap();
            ch.send(b"ping").await.unwrap();
            assert_eq!(&*ch.recv().await.unwrap(), b"pong");
            let (got, phone_hash) = responder.await.unwrap();
            assert_eq!(got, b"ping");
            assert_eq!(&phone_hash, ch.handshake_hash());
        }

        #[tokio::test]
        async fn kk_fails_without_the_pc_key() {
            let (pc, phone) = pair_of_keys();
            let impostor = StaticKeypair::generate().unwrap();
            let id = [1u8; 16];
            let (a, b) = tokio::io::duplex(MAX_FRAME * 2);
            let phone_pub = phone.public;
            let pc_pub = pc.public;
            let responder =
                tokio::spawn(async move { kk_respond(b, &phone.private, &pc_pub, &id).await.is_err() });
            let _ = kk_initiate(a, &impostor.private, &phone_pub, &id).await;
            let _ = pc;
            assert!(responder.await.unwrap(), "phone accepted a handshake from the wrong PC key");
        }

        #[tokio::test]
        async fn kk_fails_on_pairing_id_mismatch() {
            let (pc, phone) = pair_of_keys();
            let (a, b) = tokio::io::duplex(MAX_FRAME * 2);
            let phone_pub = phone.public;
            let pc_pub = pc.public;
            let responder = tokio::spawn(async move {
                kk_respond(b, &phone.private, &pc_pub, &[2u8; 16]).await.is_err()
            });
            let _ = kk_initiate(a, &pc.private, &phone_pub, &[3u8; 16]).await;
            assert!(responder.await.unwrap());
        }

        #[tokio::test]
        async fn pairing_round_trip_over_a_stream() {
            let pc = StaticKeypair::generate().unwrap();
            let pc_pub = pc.public;
            let token = [9u8; 32];
            let (a, b) = tokio::io::duplex(MAX_FRAME * 2);
            let lp = pc.private.clone();
            let responder = tokio::spawn(async move { *pair_respond(b, &lp, &token).await.unwrap().handshake_hash() });
            let ch = pair_initiate(a, &pc_pub, &token).await.unwrap();
            assert_eq!(&responder.await.unwrap(), ch.handshake_hash());
        }
    }
}
