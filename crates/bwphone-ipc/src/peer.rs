//! One pipe's state: a Noise session per desktop endpoint the extension
//! addresses. Envelopes in, envelopes out; the daemon decides the answers.
//!
//! The SDK's responder rules, followed here:
//! - `HandshakeStart` replaces any session with a fresh one (the browser
//!   re-handshakes every 300 s, and whenever it lost its state); one that
//!   fails leaves the old session in place.
//! - A `TransportFrame` with no session is answered `CryptoInvalidated`, so
//!   the browser drops its session and handshakes again.
//! - `CryptoInvalidated` from the browser drops ours.
//! - Frames that do not decrypt, replays and malformed CBOR are dropped.
//!
//! Only RPC requests are decrypted. Every other topic, including Shared
//! Unlock's syncs (which carry the user key while the vault is unlocked)
//! and fragments, is dropped without being opened.

use crate::{
    IpcError,
    envelope::{self, Us},
    frame::Frame,
    noise::{self, Session},
    rpc::{self, CallId, Request, Response},
};

#[derive(Default)]
pub struct Peer {
    renderer: Option<Session>,
    main: Option<Session>,
}

#[derive(Debug)]
pub enum Event {
    /// Write this envelope now (a handshake finish, or `CryptoInvalidated`).
    Send(Vec<u8>),
    /// A request to answer with [`Peer::answer`], as `to`.
    Call { to: Us, id: CallId, request: Request },
    /// Nothing to do; the reason is for the log.
    Ignored(&'static str),
}

impl Peer {
    pub fn new() -> Self {
        Self::default()
    }

    fn session(&mut self, us: Us) -> &mut Option<Session> {
        match us {
            Us::DesktopRenderer => &mut self.renderer,
            Us::DesktopMain => &mut self.main,
        }
    }

    pub fn receive(&mut self, frame: &[u8]) -> Result<Event, IpcError> {
        let Some(received) = envelope::parse(frame)? else { return Ok(Event::Ignored("not addressed to the desktop")) };
        let us = received.to;
        let Ok(frame) = Frame::from_cbor(&received.payload) else { return Ok(Event::Ignored("malformed frame")) };
        match frame {
            Frame::HandshakeStart(start) => {
                // As the SDK: a start that fails leaves the working session alone.
                let (finish, session) = noise::respond(&start)?;
                *self.session(us) = Some(session);
                Ok(Event::Send(envelope::wrap(us, &Frame::HandshakeFinish(finish).to_cbor(), None)))
            }
            Frame::HandshakeFinish(_) => Ok(Event::Ignored("handshake finish, but we never initiate")),
            Frame::CryptoInvalidated => {
                *self.session(us) = None;
                Ok(Event::Ignored("session invalidated by the extension"))
            }
            Frame::TransportFrame(transport) => {
                let Some(session) = self.session(us) else {
                    return Ok(Event::Send(envelope::wrap(us, &Frame::CryptoInvalidated.to_cbor(), None)));
                };
                // The topic travels in clear: anything but a request is
                // dropped without decrypting it (Shared Unlock syncs carry
                // the user key). The nonce window only moves on a successful
                // open, so skipping one costs nothing.
                if received.topic.as_deref() != Some(rpc::REQUEST_TOPIC) {
                    return Ok(Event::Ignored("not an RPC request"));
                }
                let plain = session.open(&transport)?;
                let (id, request) = rpc::parse(&plain)?;
                Ok(Event::Call { to: us, id, request })
            }
        }
    }

    /// Seals the response under the endpoint's current session (which may
    /// be newer than the one the request came in on) and wraps it.
    pub fn answer(&mut self, to: Us, id: &CallId, response: &Response) -> Result<Vec<u8>, IpcError> {
        let body = rpc::encode(id, response);
        let session = self.session(to).as_mut().ok_or(IpcError::NoSession)?;
        let frame = Frame::TransportFrame(session.seal(&body)?);
        Ok(envelope::wrap(to, &frame.to_cbor(), Some(&id.response_topic)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        frame::{CipherSuite, TransportFrame},
        noise::initiator::Initiator,
        rpc::Status,
    };
    use serde_json::json;

    /// The extension's side: posts envelopes, reads ours.
    struct Browser {
        noise: Initiator,
    }

    fn envelope(to: &str, frame: &Frame, topic: Option<&str>) -> Vec<u8> {
        serde_json::to_vec(&json!({"type": "bitwarden-ipc-message", "message": {
            "destination": to, "payload": frame.to_cbor(), "topic": topic
        }}))
        .unwrap()
    }

    /// Returns (frame, topic, originalSource) of an envelope we sent.
    fn unwrap(bytes: &[u8]) -> (Frame, Option<String>, Option<String>) {
        let v: serde_json::Value = serde_json::from_slice(bytes).unwrap();
        let payload: Vec<u8> = serde_json::from_value(v["message"]["payload"].clone()).unwrap();
        (
            Frame::from_cbor(&payload).unwrap(),
            v["message"]["topic"].as_str().map(Into::into),
            v["originalSource"].as_str().map(Into::into),
        )
    }

    impl Browser {
        fn connect(peer: &mut Peer) -> Self {
            let (noise, start) = Initiator::start(CipherSuite::Noise_NN_P256_AESGCM_SHA256);
            let Event::Send(reply) = peer.receive(&envelope("DesktopRenderer", &Frame::HandshakeStart(start), None)).unwrap()
            else {
                panic!("no handshake reply")
            };
            let (frame, topic, source) = unwrap(&reply);
            assert_eq!((topic, source.as_deref()), (None, Some("DesktopRenderer")));
            let Frame::HandshakeFinish(finish) = frame else { panic!("{frame:?}") };
            let mut me = Self { noise };
            me.noise.finish(&finish);
            me
        }

        fn rpc(&mut self, request_type: &str, request: serde_json::Value) -> Vec<u8> {
            let body = serde_json::to_vec(&json!({
                "request": request, "request_id": "id-7", "request_type": request_type,
                "response_topic": "RpcResponseMessage:id-7"
            }))
            .unwrap();
            envelope("DesktopRenderer", &Frame::TransportFrame(self.noise.seal(&body)), Some(rpc::REQUEST_TOPIC))
        }

        fn read(&mut self, bytes: &[u8]) -> serde_json::Value {
            let (frame, topic, source) = unwrap(bytes);
            assert_eq!(topic.as_deref(), Some("RpcResponseMessage:id-7"));
            assert_eq!(source.as_deref(), Some("DesktopRenderer"));
            let Frame::TransportFrame(t) = frame else { panic!("{frame:?}") };
            serde_json::from_slice(&self.noise.open(&t)).unwrap()
        }
    }

    #[test]
    fn handshake_status_and_unlock() {
        let mut peer = Peer::new();
        let mut browser = Browser::connect(&mut peer);

        let user = "6e5f3b2a-0c1d-4e8f-9a7b-112233445566";
        let Event::Call { to, id, request } = peer.receive(&browser.rpc("GetBiometricsStatus", json!({"user_id": user}))).unwrap()
        else {
            panic!()
        };
        assert_eq!((to, &request), (Us::DesktopRenderer, &Request::GetBiometricsStatus { user_id: user.into() }));
        let out = peer.answer(to, &id, &Response::Status(Status::Available)).unwrap();
        assert_eq!(browser.read(&out)["result"], json!({"Ok": "Available"}));

        let Event::Call { to, id, .. } = peer.receive(&browser.rpc("UnlockBiometrics", json!({"user_id": user}))).unwrap() else {
            panic!()
        };
        let out = peer.answer(to, &id, &Response::Unlock(Some(zeroize::Zeroizing::new("S0VZ".into())))).unwrap();
        assert_eq!(browser.read(&out)["result"], json!({"Ok": {"user_key": "S0VZ"}}));
    }

    #[test]
    fn other_topics_are_dropped_unread() {
        let mut peer = Peer::new();
        let mut browser = Browser::connect(&mut peer);
        let sync = envelope(
            "DesktopRenderer",
            &Frame::TransportFrame(browser.noise.seal(br#"{"user_key":"secret"}"#)),
            Some("SharedUnlockSync"),
        );
        assert!(matches!(peer.receive(&sync).unwrap(), Event::Ignored("not an RPC request")));
        let fragment =
            envelope("DesktopRenderer", &Frame::TransportFrame(browser.noise.seal(b"x")), Some("IpcFragment/RpcRequestMessage"));
        assert!(matches!(peer.receive(&fragment).unwrap(), Event::Ignored(_)));
    }

    #[test]
    fn no_session_invalidation_and_rehandshake() {
        let mut peer = Peer::new();
        // Traffic with no session: tell the browser to start over.
        let mut stray = Browser::connect(&mut Peer::new());
        let Event::Send(reply) = peer.receive(&stray.rpc("DiscoverRequest", json!(null))).unwrap() else { panic!() };
        assert_eq!(unwrap(&reply).0, Frame::CryptoInvalidated);

        let mut browser = Browser::connect(&mut peer);
        let Event::Call { id, .. } = peer.receive(&browser.rpc("DiscoverRequest", json!(null))).unwrap() else { panic!() };

        // The browser invalidates; an answer for the old request has nowhere to go.
        let inv = envelope("DesktopRenderer", &Frame::CryptoInvalidated, None);
        assert!(matches!(peer.receive(&inv).unwrap(), Event::Ignored(_)));
        assert!(matches!(peer.answer(Us::DesktopRenderer, &id, &Response::Bool(false)), Err(IpcError::NoSession)));

        // A re-handshake mid-request: the answer goes out under the new session.
        let mut browser = Browser::connect(&mut peer);
        let Event::Call { id, .. } = peer.receive(&browser.rpc("AuthenticateBiometrics", json!(null))).unwrap() else { panic!() };
        let mut browser2 = Browser::connect(&mut peer);
        let out = peer.answer(Us::DesktopRenderer, &id, &Response::Bool(false)).unwrap();
        assert_eq!(browser2.read(&out)["result"], json!({"Ok": false}));
        let _ = &mut browser;
    }

    #[test]
    fn replays_and_bad_frames() {
        let mut peer = Peer::new();
        let mut browser = Browser::connect(&mut peer);
        let request = browser.rpc("DiscoverRequest", json!(null));
        assert!(matches!(peer.receive(&request).unwrap(), Event::Call { .. }));
        assert!(matches!(peer.receive(&request), Err(IpcError::Replay)));

        let garbage = envelope("DesktopRenderer", &Frame::TransportFrame(TransportFrame { payload: vec![1; 40].into(), nonce: 99 }), Some("RpcRequestMessage"));
        assert!(matches!(peer.receive(&garbage), Err(IpcError::Decrypt)));

        let raw = serde_json::to_vec(&json!({"type": "bitwarden-ipc-message", "message": {
            "destination": "DesktopRenderer", "payload": [1, 2, 3], "topic": null
        }}))
        .unwrap();
        assert!(matches!(peer.receive(&raw).unwrap(), Event::Ignored("malformed frame")));
        assert!(peer.receive(b"{}").is_err());
    }
}
