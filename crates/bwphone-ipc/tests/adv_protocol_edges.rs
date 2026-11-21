//! Adversarial: places where `Peer` reacts differently from the SDK's own
//! responder (`sdk-internal@5b7fbb41`, `crates/bitwarden-ipc/src/
//! crypto_provider/noise/crypto_provider.rs` and `ipc_client.rs`) to inputs
//! the current extension does not send but a peer speaking the protocol
//! may. Each test asserts the SDK's behaviour, so a failure is a deviation.
//!
//! `cargo test -p bwphone-ipc --features browser --test adv_protocol_edges`

use bwphone_ipc::{
    frame::{CipherSuite, Frame, HandshakeStart},
    noise::initiator::Initiator,
    peer::{Event, Peer},
};
use serde_json::json;

fn env(frame: &Frame, topic: Option<&str>) -> Vec<u8> {
    serde_json::to_vec(&json!({"type": "bitwarden-ipc-message", "message": {
        "destination": "DesktopRenderer", "payload": frame.to_cbor(), "topic": topic
    }}))
    .unwrap()
}

fn connect(peer: &mut Peer) -> Initiator {
    let (mut i, start) = Initiator::start(CipherSuite::Noise_NN_P256_AESGCM_SHA256);
    let Event::Send(out) = peer.receive(&env(&Frame::HandshakeStart(start), None)).unwrap() else { panic!() };
    let v: serde_json::Value = serde_json::from_slice(&out).unwrap();
    let payload: Vec<u8> = serde_json::from_value(v["message"]["payload"].clone()).unwrap();
    let Frame::HandshakeFinish(f) = Frame::from_cbor(&payload).unwrap() else { panic!() };
    i.finish(&f);
    i
}

fn request(i: &mut Initiator, request_type: &str, request: serde_json::Value) -> Vec<u8> {
    let body = json!({"request": request, "request_id": "r", "request_type": request_type, "response_topic": "RpcResponseMessage:r"});
    env(&Frame::TransportFrame(i.seal(&serde_json::to_vec(&body).unwrap())), Some("RpcRequestMessage"))
}

/// SDK: `responder.read_start_message(..).map_err(..)?` returns before
/// `sessions.save`, so a HandshakeStart that fails to read leaves the
/// existing session in place. bwphone (`peer.rs:58`) clears the session
/// *before* `noise::respond`, so the established channel is lost and the
/// next honest request is answered `CryptoInvalidated` instead.
#[test]
fn a_bad_handshake_start_keeps_the_established_session() {
    let mut peer = Peer::new();
    let mut browser = connect(&mut peer);
    let bad = HandshakeStart { ciphersuite: CipherSuite::Noise_NN_P256_AESGCM_SHA256, noise_frame: vec![4, 1, 2] };
    assert!(peer.receive(&env(&Frame::HandshakeStart(bad), None)).is_err());
    let after = peer.receive(&request(&mut browser, "AuthenticateBiometrics", json!(null))).unwrap();
    assert!(matches!(after, Event::Call { .. }), "SDK keeps the session; bwphone answered {after:?}");
}

/// SDK: a known request type whose `request` does not deserialise is
/// answered `{"Err":{"RequestDeserialization":"…"}}` (`handler.rs`
/// `deserialize_full()?`, sent by `handle_rpc_request`), so the requester
/// fails at once. bwphone (`rpc.rs:296-302`, `peer.rs:76`) returns
/// `Err(Rpc)` and sends nothing; the requester waits out its timeout.
#[test]
fn a_malformed_known_request_is_answered_not_dropped() {
    let mut peer = Peer::new();
    let mut browser = connect(&mut peer);
    let r = peer.receive(&request(&mut browser, "UnlockBiometrics", json!({"user_id": 5})));
    assert!(matches!(r, Ok(Event::Call { .. }) | Ok(Event::Send(_))), "SDK answers RequestDeserialization; bwphone gave {r:?}");
}
