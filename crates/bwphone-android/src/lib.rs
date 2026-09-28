//! What the Android app calls. Every value both devices must agree on byte
//! for byte — the Noise handshakes and cipher states, the framing, the
//! message shapes, the emoji, the pairing words and keys, the hello, the
//! mDNS name — comes from `bwphone-transport` through this surface, so the
//! phone never reimplements any of it.
//!
//! # Why a sans-I/O surface
//!
//! Kotlin cannot pass a socket across uniffi, and it should not: the phone
//! must bind its listener to the Wi-Fi `Network` (never cellular or VPN),
//! rebind on `onAvailable`/`onLost`, and drop pre-auth connections after
//! 5 s — all of which is Android's `ConnectivityManager` territory. So Kotlin
//! owns the socket and moves bytes; this crate owns everything that must
//! agree with the PC. A [`Handshake`] and a [`Transport`] are state
//! machines: a frame in, a frame out, and the [`FrameDecoder`] turns a
//! stream of bytes into frames.
//!
//! What stays native in Kotlin: the Keystore key and its
//! `BiometricPrompt(CryptoObject(cipher))` decrypt, the UI, and the network.
//!
//! Every function here is plain and synchronous, and objects are internally
//! locked, so they can be used from any thread.

uniffi::setup_scaffolding!();

use std::sync::{Arc, Mutex};

use bwphone_transport::{
    PROTOCOL_VERSION, b64, emoji, frame, hello, mdns,
    msg::{self, Request, RequestBody, Response},
    noise::{self, ChannelError, StaticKeypair},
    pairing, unb64,
};
use zeroize::Zeroize as _;

#[derive(Debug, thiserror::Error, uniffi::Error)]
#[uniffi(flat_error)]
pub enum TransportError {
    /// A handshake or transport message did not authenticate: the wrong
    /// key, the wrong pairing ID, a replay, or garbage.
    #[error("noise: {0}")]
    Noise(String),
    #[error("malformed: {0}")]
    Malformed(String),
    /// Used out of order, e.g. `into_transport` before the handshake ended.
    #[error("state: {0}")]
    State(String),
}

type R<T> = Result<T, TransportError>;

impl From<ChannelError> for TransportError {
    fn from(e: ChannelError) -> Self {
        match e {
            ChannelError::Noise(e) => Self::Noise(e.to_string()),
            ChannelError::NotFinished => Self::State(e.to_string()),
            other => Self::Malformed(other.to_string()),
        }
    }
}

fn bytes32(v: &[u8], what: &str) -> R<[u8; 32]> {
    v.try_into().map_err(|_| TransportError::Malformed(format!("{what} must be 32 bytes")))
}

fn bytes16(v: &[u8], what: &str) -> R<[u8; 16]> {
    v.try_into().map_err(|_| TransportError::Malformed(format!("{what} must be 16 bytes")))
}

/// The phone's X25519 channel identity: proves "this is the paired phone",
/// nothing more. Stored sealed under a Keystore key, excluded from backup.
#[derive(uniffi::Object)]
pub struct StaticKey {
    inner: StaticKeypair,
}

#[uniffi::export]
impl StaticKey {
    /// Fresh, at pairing.
    #[uniffi::constructor]
    pub fn generate() -> R<Arc<Self>> {
        Ok(Arc::new(Self { inner: StaticKeypair::generate()? }))
    }

    /// From the stored private key, at every start.
    #[uniffi::constructor]
    pub fn from_private(private: Vec<u8>) -> R<Arc<Self>> {
        let mut private = private;
        let key = bytes32(&private, "private key");
        private.zeroize();
        Ok(Arc::new(Self { inner: StaticKeypair::from_private(&key?) }))
    }

    pub fn public(&self) -> Vec<u8> {
        self.inner.public.to_vec()
    }

    /// For storage only. Never leaves the phone.
    pub fn private(&self) -> Vec<u8> {
        self.inner.private.to_vec()
    }
}

/// A handshake in progress. Loop: if `is_my_turn`, send `write_message`;
/// else feed the next frame to `read_message`; until `is_finished`; then
/// `into_transport`.
#[derive(uniffi::Object)]
pub struct Handshake {
    inner: Mutex<Option<noise::Handshake>>,
}

impl Handshake {
    fn with<T>(&self, f: impl FnOnce(&mut noise::Handshake) -> R<T>) -> R<T> {
        let mut guard = self.inner.lock().unwrap();
        let hs = guard.as_mut().ok_or_else(|| TransportError::State("handshake already consumed".into()))?;
        f(hs)
    }
}

#[uniffi::export]
impl Handshake {
    /// Steady state: the PC connects, the phone responds.
    #[uniffi::constructor]
    pub fn kk_responder(phone_key: Arc<StaticKey>, pc_public: Vec<u8>, pairing_id: Vec<u8>) -> R<Arc<Self>> {
        let hs = noise::Handshake::kk_responder(
            &phone_key.inner.private,
            &bytes32(&pc_public, "PC public key")?,
            &bytes16(&pairing_id, "pairing id")?,
        )?;
        Ok(Arc::new(Self { inner: Mutex::new(Some(hs)) }))
    }

    /// Pairing: the phone connects to the address in the QR code, with the
    /// PC's key and the token from it.
    #[uniffi::constructor]
    pub fn pair_initiator(pc_public: Vec<u8>, token: Vec<u8>) -> R<Arc<Self>> {
        let hs = noise::Handshake::pair_initiator(&bytes32(&pc_public, "PC public key")?, &bytes32(&token, "token")?)?;
        Ok(Arc::new(Self { inner: Mutex::new(Some(hs)) }))
    }

    pub fn is_my_turn(&self) -> R<bool> {
        self.with(|hs| Ok(hs.is_my_turn()))
    }

    pub fn is_finished(&self) -> R<bool> {
        self.with(|hs| Ok(hs.is_finished()))
    }

    /// The next handshake message; frame it with [`frame_encode`] and send.
    pub fn write_message(&self) -> R<Vec<u8>> {
        self.with(|hs| Ok(hs.write_message()?))
    }

    /// One received frame's contents.
    pub fn read_message(&self, message: Vec<u8>) -> R<()> {
        self.with(|hs| Ok(hs.read_message(&message)?))
    }

    /// Consumes the handshake; further calls on it fail.
    pub fn into_transport(&self) -> R<Arc<Transport>> {
        let hs = self
            .inner
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| TransportError::State("handshake already consumed".into()))?;
        Ok(Arc::new(Transport { inner: Mutex::new(hs.into_transport()?) }))
    }
}

/// The established channel. Messages must be opened in the order they
/// were sealed; Noise numbers them.
#[derive(uniffi::Object)]
pub struct Transport {
    inner: Mutex<noise::Transport>,
}

#[uniffi::export]
impl Transport {
    /// 32 bytes, identical on both ends of this session and never repeated.
    pub fn handshake_hash(&self) -> Vec<u8> {
        self.inner.lock().unwrap().handshake_hash().to_vec()
    }

    pub fn seal(&self, plaintext: Vec<u8>) -> R<Vec<u8>> {
        Ok(self.inner.lock().unwrap().seal(&plaintext)?)
    }

    pub fn open(&self, message: Vec<u8>) -> R<Vec<u8>> {
        Ok(self.inner.lock().unwrap().open(&message)?.to_vec())
    }
}

/// This session's emoji index, from the handshake hash and both nonces:
/// the PC's from its unwrap request, the phone's from `phone_nonce()`
/// sent back in `prompt_posted`. Never from `h` alone — see the transport
/// crate's `emoji` docs.
#[uniffi::export]
pub fn emoji_index(handshake_hash: Vec<u8>, pc_nonce: Vec<u8>, phone_nonce: Vec<u8>) -> R<u32> {
    Ok(emoji::index(&bytes32(&handshake_hash, "handshake hash")?, &bytes32(&pc_nonce, "PC nonce")?, &bytes32(&phone_nonce, "phone nonce")?) as u32)
}

/// 32 bytes from the OS CSPRNG: the phone's half of the emoji derivation,
/// generated after the PC's nonce has arrived and sent with `prompt_posted`.
#[uniffi::export]
pub fn phone_nonce() -> Vec<u8> {
    let mut n = vec![0u8; emoji::NONCE_LEN];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut n);
    n
}

/// `len(2, big-endian) || message`.
#[uniffi::export]
pub fn frame_encode(message: Vec<u8>) -> R<Vec<u8>> {
    frame::encode(&message).map_err(|e| TransportError::Malformed(e.to_string()))
}

/// Feed it whatever the socket read; take frames out as they complete.
#[derive(uniffi::Object)]
pub struct FrameDecoder {
    inner: Mutex<frame::Decoder>,
}

#[uniffi::export]
impl FrameDecoder {
    #[uniffi::constructor]
    pub fn new() -> Arc<Self> {
        Arc::new(Self { inner: Mutex::new(frame::Decoder::default()) })
    }

    pub fn push(&self, bytes: Vec<u8>) {
        self.inner.lock().unwrap().push(&bytes);
    }

    pub fn next_frame(&self) -> Option<Vec<u8>> {
        self.inner.lock().unwrap().next_frame()
    }
}

/// What the PC asks. Binary fields arrive decoded and length-checked.
#[derive(Debug, Clone, PartialEq, Eq, uniffi::Enum)]
pub enum PhoneRequest {
    /// Answer `Pong`; show nothing.
    Ping,
    /// Compare `H(rsa_ct)` to the account's pin first; refuse a mismatch
    /// without a prompt. Then reply `PromptPosted` with a fresh `phone_nonce()`,
    /// derive the emoji with `emoji_index`, emoji pick, then `BiometricPrompt`.
    /// `host` is caller-supplied text: log it if you like, never show it.
    Unwrap { account: Vec<u8>, rsa_ct: Vec<u8>, expires_in_ms: u64, nonce: Vec<u8>, host: String },
    /// Refuse unless the Enrol screen is open.
    EnrolBegin { account: Vec<u8>, label_hint: String },
    /// Write-once, Enrol screen only.
    SetPin { account: Vec<u8>, pin: Vec<u8> },
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct ParsedRequest {
    pub req_id: String,
    pub request: PhoneRequest,
}

/// Decode an opened transport message. Refuses any protocol version but 3.
#[uniffi::export]
pub fn parse_request(plaintext: Vec<u8>) -> R<ParsedRequest> {
    let req: Request = serde_json::from_slice(&plaintext).map_err(|e| TransportError::Malformed(e.to_string()))?;
    if req.v != PROTOCOL_VERSION {
        return Err(TransportError::Malformed(format!("protocol version {} is not {PROTOCOL_VERSION}", req.v)));
    }
    let account = |s: &str| unb64(s).ok().and_then(|v| bytes16(&v, "account").ok()).ok_or_else(|| TransportError::Malformed("account is not 16 bytes".into()));
    let request = match req.body {
        RequestBody::Ping => PhoneRequest::Ping,
        RequestBody::Unwrap { account: a, rsa_ct, expires_in_ms, nonce, context } => {
            let rsa_ct = unb64(&rsa_ct).map_err(|e| TransportError::Malformed(e.to_string()))?;
            if rsa_ct.len() != 256 {
                return Err(TransportError::Malformed("rsa_ct is not 256 bytes".into()));
            }
            let nonce = unb64(&nonce).map_err(|e| TransportError::Malformed(e.to_string()))?;
            let nonce = bytes32(&nonce, "nonce")?.to_vec();
            PhoneRequest::Unwrap { account: account(&a)?.to_vec(), rsa_ct, expires_in_ms, nonce, host: context.host }
        }
        RequestBody::EnrolBegin { account: a, label_hint } => PhoneRequest::EnrolBegin { account: account(&a)?.to_vec(), label_hint },
        RequestBody::SetPin { account: a, pin } => {
            let pin = unb64(&pin).map_err(|e| TransportError::Malformed(e.to_string()))?;
            PhoneRequest::SetPin { account: account(&a)?.to_vec(), pin: bytes32(&pin, "pin")?.to_vec() }
        }
    };
    Ok(ParsedRequest { req_id: req.req_id, request })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, uniffi::Enum)]
pub enum PhoneStatus {
    /// Interim: the prompt is on screen. Ends the PC's reach phase.
    PromptPosted,
    Ok,
    Pong,
    Denied,
    /// None of these: the PC raises an alarm.
    Rejected,
    PinMismatch,
    RateLimited,
    Busy,
    Expired,
    Invalidated,
    UnknownAccount,
    NotAllowed,
    /// enrol_begin for a name this phone already has.
    LabelTaken,
    Error,
}

impl From<PhoneStatus> for msg::Status {
    fn from(s: PhoneStatus) -> Self {
        match s {
            PhoneStatus::PromptPosted => Self::PromptPosted,
            PhoneStatus::Ok => Self::Ok,
            PhoneStatus::Pong => Self::Pong,
            PhoneStatus::Denied => Self::Denied,
            PhoneStatus::Rejected => Self::Rejected,
            PhoneStatus::PinMismatch => Self::PinMismatch,
            PhoneStatus::RateLimited => Self::RateLimited,
            PhoneStatus::Busy => Self::Busy,
            PhoneStatus::Expired => Self::Expired,
            PhoneStatus::Invalidated => Self::Invalidated,
            PhoneStatus::UnknownAccount => Self::UnknownAccount,
            PhoneStatus::NotAllowed => Self::NotAllowed,
            PhoneStatus::LabelTaken => Self::LabelTaken,
            PhoneStatus::Error => Self::Error,
        }
    }
}

/// A reply, ready to `seal`. `nonce` (from `phone_nonce()`) only with
/// `PromptPosted`; `k_wrap` only with `Ok` to an unwrap; `rsa_pub` (SPKI DER)
/// and `label` only with `Ok` to `enrol_begin`.
#[uniffi::export]
pub fn encode_response(req_id: String, status: PhoneStatus, nonce: Option<Vec<u8>>, k_wrap: Option<Vec<u8>>, rsa_pub: Option<Vec<u8>>, label: Option<String>) -> Vec<u8> {
    let mut r = Response::status(&req_id, status.into());
    r.nonce = nonce.map(|n| b64(&n));
    r.k_wrap = k_wrap.map(|k| b64(&k));
    r.rsa_pub = rsa_pub.map(|k| b64(&k));
    r.label = label;
    serde_json::to_vec(&r).expect("Response always serialises")
}

/// The 32 emojis, in index order. Compiled in, so both ends index one list.
#[uniffi::export]
pub fn emoji_list() -> Vec<String> {
    emoji::EMOJI.iter().map(|s| (*s).to_owned()).collect()
}

/// The five to show, the real one among four distinct decoys, shuffled.
/// Randomness is the OS CSPRNG (`getrandom`), the same source as `SecureRandom`.
#[uniffi::export]
pub fn phone_choices(real_index: u32) -> R<Vec<u32>> {
    if real_index as usize >= emoji::EMOJI.len() {
        return Err(TransportError::Malformed("emoji index out of range".into()));
    }
    Ok(emoji::phone_choices(real_index as usize, &mut rand::rngs::OsRng).iter().map(|&i| i as u32).collect())
}

#[derive(Debug, Clone, PartialEq, Eq, uniffi::Record)]
pub struct QrPayload {
    pub pc_pub: Vec<u8>,
    pub token: Vec<u8>,
    pub ip: String,
    pub pair_port: u16,
    pub hello_port: u16,
}

/// The QR code's text. Refuses any version but 3.
#[uniffi::export]
pub fn decode_qr(text: String) -> R<QrPayload> {
    let q = pairing::QrPayload::decode(&text).ok_or_else(|| TransportError::Malformed("not a bwphone v3 QR code".into()))?;
    Ok(QrPayload { pc_pub: q.pc_pub.to_vec(), token: q.token.to_vec(), ip: q.ip.to_string(), pair_port: q.pair_port, hello_port: q.hello_port })
}

/// The first transport message of pairing, phone to PC. Keep the
/// exact bytes: they go into the transcript.
#[uniffi::export]
pub fn encode_pair_hello(x25519_pub: Vec<u8>, listen_port: u16, device_label: String) -> Vec<u8> {
    let hello = msg::PairHello { v: PROTOCOL_VERSION, x25519_pub: b64(&x25519_pub), listen_port, device_label };
    serde_json::to_vec(&hello).expect("PairHello always serialises")
}

#[uniffi::export]
pub fn encode_pair_confirm(confirmed: bool) -> Vec<u8> {
    serde_json::to_vec(&msg::PairConfirm { v: PROTOCOL_VERSION, confirmed }).expect("PairConfirm always serialises")
}

/// The PC's answer: whether the person confirmed the six words there.
/// Neither side commits anything until it has sent and received `true`.
#[uniffi::export]
pub fn parse_pair_confirm(plaintext: Vec<u8>) -> R<bool> {
    let c: msg::PairConfirm = serde_json::from_slice(&plaintext).map_err(|e| TransportError::Malformed(e.to_string()))?;
    if c.v != PROTOCOL_VERSION {
        return Err(TransportError::Malformed("wrong protocol version".into()));
    }
    Ok(c.confirmed)
}

/// `SHA-256(handshake hash || PairHello bytes)`: what the words and keys derive from.
#[uniffi::export]
pub fn pairing_transcript(handshake_hash: Vec<u8>, pair_hello_bytes: Vec<u8>) -> R<Vec<u8>> {
    Ok(pairing::transcript(&bytes32(&handshake_hash, "handshake hash")?, &pair_hello_bytes).to_vec())
}

/// Six BIP-39 words both screens show.
#[uniffi::export]
pub fn pairing_words(transcript: Vec<u8>) -> R<Vec<String>> {
    Ok(pairing::words(&bytes32(&transcript, "transcript")?).iter().map(|w| (*w).to_owned()).collect())
}

#[uniffi::export]
pub fn hello_key(transcript: Vec<u8>) -> R<Vec<u8>> {
    Ok(pairing::hello_key(&bytes32(&transcript, "transcript")?).to_vec())
}

#[uniffi::export]
pub fn pairing_id(transcript: Vec<u8>) -> R<Vec<u8>> {
    Ok(pairing::pairing_id(&bytes32(&transcript, "transcript")?).to_vec())
}

/// One UDP packet announcing the phone's address; random bytes to anyone else.
#[uniffi::export]
pub fn seal_hello(hello_key: Vec<u8>, ip: String, port: u16, seq: u64) -> R<Vec<u8>> {
    Ok(hello::seal(&bytes32(&hello_key, "hello key")?, &hello::Hello { ip, port, seq }))
}

/// Today's mDNS name for the PC, e.g. `k3j…q7.local`; `unix_secs` from the phone's clock.
#[uniffi::export]
pub fn mdns_name_now(hello_key: Vec<u8>, unix_secs: i64) -> R<String> {
    Ok(mdns::name_now(&bytes32(&hello_key, "hello key")?, unix_secs))
}

/// Five groups of four hex digits, for confirming an RSA public key on both screens.
#[uniffi::export]
pub fn short_fingerprint(bytes: Vec<u8>) -> String {
    bwphone_transport::short_fingerprint(&bytes)
}

#[uniffi::export]
pub fn protocol_version() -> u8 {
    PROTOCOL_VERSION
}

#[cfg(test)]
mod tests {
    use super::*;
    use bwphone_transport::msg::Status;

    /// The phone, through this surface; the PC, through the crate
    /// directly. No sockets: bytes are carried by hand, framed both ways.
    #[test]
    fn phone_answers_a_pc_unwrap_request() {
        let phone = StaticKey::generate().unwrap();
        let pc = StaticKeypair::generate().unwrap();
        let pairing_id = vec![5u8; 16];

        let mut l = noise::Handshake::kk_initiator(&pc.private, &bytes32(&phone.public(), "").unwrap(), &[5; 16]).unwrap();
        let p = Handshake::kk_responder(phone.clone(), pc.public.to_vec(), pairing_id).unwrap();

        // PC → phone, through a byte stream the phone decodes in pieces.
        let wire = frame_encode(l.write_message().unwrap()).unwrap();
        let decoder = FrameDecoder::new();
        decoder.push(wire[..10].to_vec());
        assert!(decoder.next_frame().is_none());
        decoder.push(wire[10..].to_vec());
        assert!(!p.is_my_turn().unwrap());
        p.read_message(decoder.next_frame().unwrap()).unwrap();
        assert!(p.is_my_turn().unwrap() && !p.is_finished().unwrap());

        l.read_message(&p.write_message().unwrap()).unwrap();
        assert!(p.is_finished().unwrap());
        let pt = p.into_transport().unwrap();
        assert!(matches!(p.is_my_turn(), Err(TransportError::State(_))), "consumed");
        let mut lt = l.into_transport().unwrap();
        assert_eq!(pt.handshake_hash(), lt.handshake_hash().to_vec());

        let account = [1u8; 16];
        let pc_nonce = [4u8; 32];
        let req = Request::new(
            "r1".into(),
            RequestBody::Unwrap { account: b64(&account), rsa_ct: b64(&[7u8; 256]), expires_in_ms: 45_000, nonce: b64(&pc_nonce), context: msg::Context { host: "PC".into() } },
        );
        let ct = lt.seal(&serde_json::to_vec(&req).unwrap()).unwrap();
        let parsed = parse_request(pt.open(ct).unwrap()).unwrap();
        assert_eq!(parsed.req_id, "r1");
        assert_eq!(parsed.request, PhoneRequest::Unwrap { account: account.to_vec(), rsa_ct: vec![7; 256], expires_in_ms: 45_000, nonce: pc_nonce.to_vec(), host: "PC".into() });

        let pn = phone_nonce();
        assert_eq!(pn.len(), 32);
        assert_ne!(pn, phone_nonce());
        let idx = emoji_index(pt.handshake_hash(), pc_nonce.to_vec(), pn.clone()).unwrap();
        assert_eq!(idx as usize, emoji::index(lt.handshake_hash(), &pc_nonce, &bytes32(&pn, "").unwrap()));
        assert!(emoji_index(vec![0; 31], pc_nonce.to_vec(), pn.clone()).is_err());
        let choices = phone_choices(idx).unwrap();
        assert_eq!(choices.len(), 5);
        assert!(choices.contains(&idx));

        let posted = pt.seal(encode_response("r1".into(), PhoneStatus::PromptPosted, Some(pn.clone()), None, None, None)).unwrap();
        let r: Response = serde_json::from_slice(&lt.open(&posted).unwrap()).unwrap();
        assert_eq!((r.req_id.as_str(), r.status, r.k_wrap), ("r1", Status::PromptPosted, None));
        assert_eq!(unb64(&r.nonce.unwrap()).unwrap(), pn, "the PC derives the same emoji from this");

        let ok = pt.seal(encode_response("r1".into(), PhoneStatus::Ok, None, Some(vec![9; 32]), None, None)).unwrap();
        let r: Response = serde_json::from_slice(&lt.open(&ok).unwrap()).unwrap();
        assert_eq!(r.status, Status::Ok);
        assert_eq!(unb64(&r.k_wrap.unwrap()).unwrap(), vec![9; 32]);
    }

    #[test]
    fn request_parsing_refuses_bad_shapes() {
        let ping = serde_json::to_vec(&Request::new("p".into(), RequestBody::Ping)).unwrap();
        assert_eq!(parse_request(ping).unwrap().request, PhoneRequest::Ping);

        let mut old = serde_json::to_value(Request::new("p".into(), RequestBody::Ping)).unwrap();
        old["v"] = 2.into();
        assert!(matches!(parse_request(serde_json::to_vec(&old).unwrap()), Err(TransportError::Malformed(_))));

        let short = Request::new("s".into(), RequestBody::SetPin { account: b64(&[1; 16]), pin: b64(&[1; 31]) });
        assert!(matches!(parse_request(serde_json::to_vec(&short).unwrap()), Err(TransportError::Malformed(m)) if m.contains("pin")));
        let bad_account = Request::new("s".into(), RequestBody::EnrolBegin { account: b64(&[1; 15]), label_hint: "x".into() });
        assert!(matches!(parse_request(serde_json::to_vec(&bad_account).unwrap()), Err(TransportError::Malformed(m)) if m.contains("account")));
        assert!(parse_request(b"not json".to_vec()).is_err());
        assert!(phone_choices(32).is_err());
    }

    #[test]
    fn pairing_surface_matches_the_crate() {
        let q = pairing::QrPayload { pc_pub: [1; 32], token: [2; 32], ip: "192.168.1.20".parse().unwrap(), pair_port: 40000, hello_port: 8732 };
        let decoded = decode_qr(q.encode()).unwrap();
        assert_eq!(decoded, QrPayload { pc_pub: vec![1; 32], token: vec![2; 32], ip: "192.168.1.20".into(), pair_port: 40000, hello_port: 8732 });
        assert!(decode_qr("nope".into()).is_err());

        let hello = encode_pair_hello(vec![3; 32], 8731, "Pixel".into());
        let parsed: msg::PairHello = serde_json::from_slice(&hello).unwrap();
        assert_eq!(parsed.device_label, "Pixel");
        let t = pairing_transcript(vec![4; 32], hello.clone()).unwrap();
        assert_eq!(t, pairing::transcript(&[4; 32], &hello).to_vec());
        assert_eq!(pairing_words(t.clone()).unwrap(), pairing::words(&bytes32(&t, "").unwrap()).to_vec());
        assert_eq!(hello_key(t.clone()).unwrap().len(), 32);
        assert_eq!(pairing_id(t.clone()).unwrap().len(), 16);
        assert!(parse_pair_confirm(encode_pair_confirm(true)).unwrap());
        assert!(!parse_pair_confirm(encode_pair_confirm(false)).unwrap());
        assert!(pairing_words(vec![0; 31]).is_err());

        let key = hello_key(t).unwrap();
        let pkt = seal_hello(key.clone(), "10.0.0.7".into(), 8731, 3).unwrap();
        let opened = hello::open(&bytes32(&key, "").unwrap(), &pkt).unwrap();
        assert_eq!((opened.ip.as_str(), opened.port, opened.seq), ("10.0.0.7", 8731, 3));
        assert!(mdns_name_now(key, 1_790_500_000).unwrap().ends_with(".local"));
        assert_eq!(short_fingerprint(b"key".to_vec()).len(), 24);
        assert_eq!(protocol_version(), 3);
    }

    #[test]
    fn static_key_round_trips_through_storage() {
        let k = StaticKey::generate().unwrap();
        let again = StaticKey::from_private(k.private()).unwrap();
        assert_eq!(again.public(), k.public());
        assert!(StaticKey::from_private(vec![0; 31]).is_err());
    }
}
