//! Adversarial interop check: drives `bwphone_ipc::peer::Peer` with an
//! initiator rebuilt from Bitwarden's own sources, NOT from `noise::initiator`
//! (which is bwphone's code). Every type below mirrors a type in
//! `sdk-internal@5b7fbb41` or `clients@browser-v2026.11.0`, with the file
//! named next to it. If any of these tests fails, the real extension would
//! not interoperate.

use bwphone_ipc::{
    envelope::Us,
    peer::{Event, Peer},
    rpc::{Response, Status},
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;
use serde_json::{Value, json};
use snow::resolvers::{CryptoResolver as _, DefaultResolver};

// ---- crates/bitwarden-ipc/src/endpoint.rs ---------------------------------
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
enum HostId {
    Own,
    Id(i32),
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
enum Endpoint {
    Web { tab_id: i32, document_id: String },
    BrowserForeground { id: i32 },
    BrowserBackground { id: HostId },
    Cli { id: HostId },
    DesktopRenderer,
    DesktopMain,
}
#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
enum Source {
    Web { tab_id: i32, document_id: String, origin: String },
    BrowserForeground { id: i32 },
    BrowserBackground { id: HostId },
    Cli { id: HostId },
    DesktopRenderer,
    DesktopMain,
}
impl Source {
    fn to_endpoint(&self) -> Endpoint {
        match self.clone() {
            Source::Web { tab_id, document_id, .. } => Endpoint::Web { tab_id, document_id },
            Source::BrowserForeground { id } => Endpoint::BrowserForeground { id },
            Source::BrowserBackground { id } => Endpoint::BrowserBackground { id },
            Source::Cli { id } => Endpoint::Cli { id },
            Source::DesktopRenderer => Endpoint::DesktopRenderer,
            Source::DesktopMain => Endpoint::DesktopMain,
        }
    }
}

// ---- crates/bitwarden-ipc/src/crypto_provider/noise/{handshake,transport_state,crypto_provider}.rs
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
enum CipherSuite {
    Noise_NN_25519_ChaChaPoly_BLAKE2s,
    Noise_NN_25519_AESGCM_SHA256,
    Noise_NN_P256_AESGCM_SHA256,
}
impl CipherSuite {
    fn name(&self) -> &'static str {
        match self {
            Self::Noise_NN_25519_ChaChaPoly_BLAKE2s => "Noise_NN_25519_ChaChaPoly_BLAKE2s",
            Self::Noise_NN_25519_AESGCM_SHA256 => "Noise_NN_25519_AESGCM_SHA256",
            Self::Noise_NN_P256_AESGCM_SHA256 => "Noise_NN_P256_AESGCM_SHA256",
        }
    }
    fn cipher(&self) -> snow::params::CipherChoice {
        match self {
            Self::Noise_NN_25519_ChaChaPoly_BLAKE2s => snow::params::CipherChoice::ChaChaPoly,
            _ => snow::params::CipherChoice::AESGCM,
        }
    }
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct HandshakeStartMessage {
    ciphersuite: CipherSuite,
    noise_frame: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(transparent)]
struct HandshakeFinishMessage {
    noise_frame: Vec<u8>,
}
#[derive(Debug, Clone, Serialize, Deserialize)]
struct TransportFrame {
    payload: ByteBuf,
    nonce: u64,
}
#[derive(Debug, Serialize, Deserialize)]
enum SdkFrame {
    HandshakeStart(HandshakeStartMessage),
    HandshakeFinish(HandshakeFinishMessage),
    TransportFrame(TransportFrame),
    CryptoInvalidated,
}
fn to_cbor(f: &SdkFrame) -> Vec<u8> {
    let mut b = Vec::new();
    ciborium::into_writer(f, &mut b).unwrap();
    b
}
fn from_cbor(b: &[u8]) -> Result<SdkFrame, ()> {
    ciborium::from_reader(b).map_err(|_| ())
}

// ---- crates/bitwarden-ipc/src/rpc/{request_message,response_message,error}.rs
#[derive(Serialize)]
struct RpcRequestMessage<T> {
    request: T,
    request_id: String,
    request_type: String,
    response_topic: String,
}
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
enum RpcError {
    RequestDeserialization(String),
    RequestSerialization(String),
    ResponseDeserialization(String),
    ResponseSerialization(String),
    NoHandlerFound,
}
#[derive(Deserialize)]
#[serde(bound = "T: Deserialize<'de>")]
struct IncomingRpcResponseMessage<T> {
    result: Result<T, RpcError>,
    #[allow(dead_code)]
    request_id: String,
    #[allow(dead_code)]
    request_type: String,
}

// ---- crates/bitwarden-shared-unlock/src/wasm/biometrics.rs, discover/mod.rs
#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
enum BiometricsStatus {
    Available,
    UnlockNeeded,
    HardwareUnavailable,
    NotEnabled,
}
#[derive(Serialize)]
struct UserIdReq {
    user_id: String, // UserId: uuid, serde_json writes it hyphenated lowercase
}
#[derive(Debug, Deserialize)]
struct UnlockBiometricsResponse {
    user_key: Option<String>, // Option<SymmetricCryptoKey>, a string on the wire
}
#[derive(Serialize)]
struct AuthenticateBiometricsRequest; // unit struct: `null`
#[derive(Serialize)]
struct DiscoverRequest;
#[derive(Debug, Deserialize)]
struct DiscoverResponse {
    version: String,
}

/// bitwarden-encoding `B64::try_from(&str)`: trim '=', decode without
/// padding or trailing-bit checks; then `SymmetricCryptoKey::try_from` wants
/// 32, 64 or >64 (COSE) bytes.
fn sdk_symmetric_key_len(s: &str) -> Result<usize, &'static str> {
    let s = s.trim_end_matches('=');
    let mut bits = 0u32;
    let mut n = 0;
    let mut out = Vec::new();
    for c in s.bytes() {
        let v = match c {
            b'A'..=b'Z' => c - b'A',
            b'a'..=b'z' => c - b'a' + 26,
            b'0'..=b'9' => c - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return Err("not base64"),
        } as u32;
        bits = (bits << 6) | v;
        n += 6;
        if n >= 8 {
            n -= 8;
            out.push((bits >> n) as u8);
        }
    }
    if s.len() % 4 == 1 {
        return Err("not base64");
    }
    match out.len() {
        32 | 64 => Ok(out.len()),
        l if l > 64 => Err("COSE key expected"),
        _ => Err("InvalidKeyLen"),
    }
}

// ---- The extension: desktop-ipc.transport.ts + NoiseCryptoProvider as initiator
struct Extension {
    suite: CipherSuite,
    send_key: [u8; 32],
    recv_key: [u8; 32],
    send_nonce: u64,
    recv_nonce: u64,
    has_session: bool,
}

/// `DesktopIpcTransport.send`: `topic: message.topic` is `undefined` for
/// crypto frames, which `JSON.stringify` drops from the object.
fn post(destination: &str, frame: &SdkFrame, topic: Option<&str>) -> Vec<u8> {
    let mut msg = json!({"destination": destination, "payload": to_cbor(frame)});
    if let Some(t) = topic {
        msg["topic"] = json!(t);
    }
    serde_json::to_vec(&json!({"type": "bitwarden-ipc-message", "message": msg})).unwrap()
}

/// `port.onMessage` in `desktop-ipc.transport.ts` → `new IncomingMessage(...)`.
/// Returns (payload, source, topic). Panics where the wasm constructor would
/// throw (tsify `from_wasm_abi` on `destination: Endpoint`, `source: Source`).
fn on_message(bytes: &[u8]) -> Option<(Vec<u8>, Source, Option<String>)> {
    let v: Value = serde_json::from_slice(bytes).expect("Chrome only delivers valid JSON");
    let ipc = v["type"] == "bitwarden-ipc-message";
    let fwd = v["type"] == "forwarded-bitwarden-ipc-message";
    if !ipc && !fwd {
        return None;
    }
    let payload: Vec<u8> = serde_json::from_value(v["message"]["payload"].clone()).expect("payload: number[]");
    let _destination: Endpoint =
        serde_json::from_value(v["message"]["destination"].clone()).expect("IncomingMessage(destination: Endpoint) throws");
    let source: Source = if fwd {
        serde_json::from_value(v["originalSource"].clone()).expect("IncomingMessage(source: Source) throws")
    } else {
        Source::DesktopMain
    };
    let topic: Option<String> = match &v["message"]["topic"] {
        Value::Null => None,
        Value::String(s) => Some(s.clone()),
        other => panic!("topic {other:?} is not Option<String>"),
    };
    Some((payload, source, topic))
}

impl Extension {
    /// `perform_handshake` to `destination`, against `peer`.
    fn handshake(peer: &mut Peer, suite: CipherSuite, destination: &str, dest: Endpoint) -> Self {
        let mut hs = snow::Builder::new(suite.name().parse().unwrap()).build_initiator().unwrap();
        let mut buf = [0u8; 65535];
        let len = hs.write_message(&[], &mut buf).unwrap();
        let start = SdkFrame::HandshakeStart(HandshakeStartMessage { ciphersuite: suite, noise_frame: buf[..len].to_vec() });
        let Event::Send(reply) = peer.receive(&post(destination, &start, None)).unwrap() else { panic!("no finish") };
        let (payload, source, topic) = on_message(&reply).unwrap();
        // "For concurrent handshakes, ignore messages" not from the destination.
        assert_eq!(source.to_endpoint(), dest, "handshake loop would ignore this finish and time out after 2 s");
        assert_eq!(topic, None);
        let Ok(SdkFrame::HandshakeFinish(finish)) = from_cbor(&payload) else { panic!("not a HandshakeFinish") };
        hs.read_message(&finish.noise_frame, &mut buf).expect("read_response_message");
        let (i2r, r2i) = hs.dangerously_get_raw_split();
        Self { suite, send_key: i2r, recv_key: r2i, send_nonce: 0, recv_nonce: 0, has_session: true }
    }

    fn aead(&self, key: &[u8; 32]) -> Box<dyn snow::types::Cipher> {
        let mut c = DefaultResolver.resolve_cipher(&self.suite.cipher()).unwrap();
        c.set(key);
        c
    }

    fn seal(&mut self, plain: &[u8]) -> SdkFrame {
        self.send_nonce += 1;
        let mut buf = vec![0u8; 65535];
        let len = self.aead(&self.send_key).encrypt(self.send_nonce, &[], plain, &mut buf);
        buf.truncate(len);
        SdkFrame::TransportFrame(TransportFrame { payload: ByteBuf::from(buf), nonce: self.send_nonce })
    }

    /// `NoiseCryptoProvider::receive` for a message from `dest`.
    fn open(&mut self, payload: &[u8]) -> Result<Vec<u8>, &'static str> {
        match from_cbor(payload).map_err(|_| "malformed cbor")? {
            SdkFrame::TransportFrame(t) => {
                assert!(self.has_session, "would answer CryptoInvalidated");
                if t.nonce <= self.recv_nonce {
                    return Err("replay");
                }
                let mut buf = vec![0u8; 65535];
                let len = self.aead(&self.recv_key).decrypt(t.nonce, &[], &t.payload, &mut buf).map_err(|_| "decrypt")?;
                self.recv_nonce = t.nonce;
                Ok(buf[..len].to_vec())
            }
            SdkFrame::CryptoInvalidated => {
                self.has_session = false;
                Err("CryptoInvalidated")
            }
            _ => Err("ignored"),
        }
    }

    /// `IpcClientExt::request`: returns the decoded response.
    fn request<T: Serialize, R: for<'de> Deserialize<'de>>(
        &mut self,
        peer: &mut Peer,
        destination: &str,
        dest: Endpoint,
        request_type: &str,
        request: T,
        answer: impl FnOnce(&bwphone_ipc::rpc::Request) -> Response,
    ) -> Result<R, RpcError> {
        let id = "0b0c9a0e-5b1f-4d7e-9a77-1f6f2ad3c001".to_owned();
        let response_topic = format!("RpcResponseMessage:{id}");
        let body = RpcRequestMessage { request, request_id: id.clone(), request_type: request_type.into(), response_topic: response_topic.clone() };
        let frame = self.seal(&serde_json::to_vec(&body).unwrap());
        let Event::Call { to, id: call, request } = peer.receive(&post(destination, &frame, Some("RpcRequestMessage"))).unwrap() else {
            panic!("no call")
        };
        let out = peer.answer(to, &call, &answer(&request)).unwrap();
        let (payload, source, topic) = on_message(&out).unwrap();
        assert_eq!(topic.as_deref(), Some(response_topic.as_str()), "subscription is on the response topic");
        assert_eq!(source.to_endpoint(), dest, "response from another source is ignored");
        let plain = self.open(&payload).unwrap();
        let msg: IncomingRpcResponseMessage<R> = serde_json::from_slice(&plain).expect("ResponseDeserialization");
        msg.result
    }
}

const USER: &str = "6e5f3b2a-0c1d-4e8f-9a7b-112233445566";

fn key_b64() -> String {
    // 64 bytes, standard base64 with padding (as `bwphone_nm::b64` writes it).
    let bytes: Vec<u8> = (0u8..64).collect();
    const T: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut s = String::new();
    for c in bytes.chunks(3) {
        let n = (c[0] as u32) << 16 | (*c.get(1).unwrap_or(&0) as u32) << 8 | *c.get(2).unwrap_or(&0) as u32;
        for i in 0..4 {
            if i <= c.len() {
                s.push(T[(n >> (18 - 6 * i) & 63) as usize] as char);
            } else {
                s.push('=');
            }
        }
    }
    s
}

#[test]
fn sdk_initiator_runs_every_biometrics_rpc_in_every_suite() {
    for suite in [CipherSuite::Noise_NN_P256_AESGCM_SHA256, CipherSuite::Noise_NN_25519_AESGCM_SHA256, CipherSuite::Noise_NN_25519_ChaChaPoly_BLAKE2s] {
        let mut peer = Peer::new();
        let mut ext = Extension::handshake(&mut peer, suite, "DesktopRenderer", Endpoint::DesktopRenderer);

        let v: DiscoverResponse = ext
            .request(&mut peer, "DesktopRenderer", Endpoint::DesktopRenderer, "DiscoverRequest", DiscoverRequest, |_| Response::Discover {
                version: "bwphone 1".into(),
            })
            .unwrap();
        assert_eq!(v.version, "bwphone 1");

        for (ours, sdk) in [
            (Status::Available, BiometricsStatus::Available),
            (Status::UnlockNeeded, BiometricsStatus::UnlockNeeded),
            (Status::HardwareUnavailable, BiometricsStatus::HardwareUnavailable),
            (Status::NotEnabled, BiometricsStatus::NotEnabled),
        ] {
            let s: BiometricsStatus = ext
                .request(&mut peer, "DesktopRenderer", Endpoint::DesktopRenderer, "GetBiometricsStatus", UserIdReq { user_id: USER.into() }, |r| {
                    assert_eq!(*r, bwphone_ipc::rpc::Request::GetBiometricsStatus { user_id: USER.into() });
                    Response::Status(ours)
                })
                .unwrap();
            assert_eq!(s, sdk);
        }

        let r: UnlockBiometricsResponse = ext
            .request(&mut peer, "DesktopRenderer", Endpoint::DesktopRenderer, "UnlockBiometrics", UserIdReq { user_id: USER.into() }, |_| {
                Response::Unlock(Some(zeroize::Zeroizing::new(key_b64())))
            })
            .unwrap();
        assert_eq!(sdk_symmetric_key_len(r.user_key.as_deref().unwrap()), Ok(64), "Aes256CbcHmacKey");

        let r: UnlockBiometricsResponse = ext
            .request(&mut peer, "DesktopRenderer", Endpoint::DesktopRenderer, "UnlockBiometrics", UserIdReq { user_id: USER.into() }, |_| Response::Unlock(None))
            .unwrap();
        assert!(r.user_key.is_none());

        let b: bool = ext
            .request(&mut peer, "DesktopRenderer", Endpoint::DesktopRenderer, "AuthenticateBiometrics", AuthenticateBiometricsRequest, |r| {
                assert_eq!(*r, bwphone_ipc::rpc::Request::AuthenticateBiometrics);
                Response::Bool(false)
            })
            .unwrap();
        assert!(!b);

        let e = ext
            .request::<_, Value>(&mut peer, "DesktopRenderer", Endpoint::DesktopRenderer, "SomethingNew", json!({}), |_| Response::NoHandlerFound)
            .unwrap_err();
        assert_eq!(e, RpcError::NoHandlerFound);
    }
}

/// A plain `bitwarden-ipc-message` back is labelled `DesktopMain` by the
/// transport, so a DesktopMain session works too, independently.
#[test]
fn desktop_main_and_renderer_sessions_are_independent() {
    let mut peer = Peer::new();
    let mut main = Extension::handshake(&mut peer, CipherSuite::Noise_NN_P256_AESGCM_SHA256, "DesktopMain", Endpoint::DesktopMain);
    let mut rend = Extension::handshake(&mut peer, CipherSuite::Noise_NN_P256_AESGCM_SHA256, "DesktopRenderer", Endpoint::DesktopRenderer);
    let b: bool =
        main.request(&mut peer, "DesktopMain", Endpoint::DesktopMain, "AuthenticateBiometrics", AuthenticateBiometricsRequest, |_| Response::Bool(true)).unwrap();
    assert!(b);
    let b: bool = rend
        .request(&mut peer, "DesktopRenderer", Endpoint::DesktopRenderer, "AuthenticateBiometrics", AuthenticateBiometricsRequest, |_| Response::Bool(false))
        .unwrap();
    assert!(!b);
}

/// The extension re-handshakes every 300 s; an answer to a request made
/// under the old session goes out under the new one and still opens.
#[test]
fn answer_after_rehandshake_opens_under_the_new_session() {
    let mut peer = Peer::new();
    let mut old = Extension::handshake(&mut peer, CipherSuite::Noise_NN_P256_AESGCM_SHA256, "DesktopRenderer", Endpoint::DesktopRenderer);
    let body = RpcRequestMessage { request: UserIdReq { user_id: USER.into() }, request_id: "a".into(), request_type: "UnlockBiometrics".into(), response_topic: "RpcResponseMessage:a".into() };
    let f = old.seal(&serde_json::to_vec(&body).unwrap());
    let Event::Call { to, id, .. } = peer.receive(&post("DesktopRenderer", &f, Some("RpcRequestMessage"))).unwrap() else { panic!() };
    let mut new = Extension::handshake(&mut peer, CipherSuite::Noise_NN_P256_AESGCM_SHA256, "DesktopRenderer", Endpoint::DesktopRenderer);
    let out = peer.answer(to, &id, &Response::Unlock(None)).unwrap();
    let (payload, _, _) = on_message(&out).unwrap();
    assert!(new.open(&payload).is_ok());
    assert_eq!(to, Us::DesktopRenderer);
}

/// A transport frame with no session gets `CryptoInvalidated`, which the
/// SDK's receive loop accepts from that source and drops its session on.
#[test]
fn no_session_crypto_invalidated_is_what_the_sdk_expects() {
    let mut first = Peer::new();
    let mut ext = Extension::handshake(&mut first, CipherSuite::Noise_NN_P256_AESGCM_SHA256, "DesktopRenderer", Endpoint::DesktopRenderer);
    let mut fresh = Peer::new(); // e.g. the daemon restarted, the extension still holds its session
    let f = ext.seal(b"{}");
    let Event::Send(out) = fresh.receive(&post("DesktopRenderer", &f, Some("RpcRequestMessage"))).unwrap() else { panic!() };
    let (payload, source, topic) = on_message(&out).unwrap();
    assert_eq!((source, topic), (Source::DesktopRenderer, None));
    assert_eq!(ext.open(&payload), Err("CryptoInvalidated"));
    assert!(!ext.has_session);
}
