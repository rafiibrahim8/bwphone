//! Adversarial, at the `serve_proxy` level: a hostile pipe peer mixing
//! protocols, garbage, wrong endpoints and replays must neither crash the
//! daemon nor get a key without the phone, and the honest session on the
//! same pipe must keep working.
//!
//! `cargo test -p bwphone --test adv_security_serve`

use std::{
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

use bwphone::{
    Ctx,
    accounts::{Account, Accounts},
    notify::{FakeNotifier, Notifier},
    phone::Phone,
    secrets::Secrets,
    serve::serve_proxy,
    unlock::{self, PhoneState, Queue},
};
use bwphone_fakephone::{Decision, Event, FakePhone, always, fixed_rsa_key};
use bwphone_ipc::{
    frame::{CipherSuite, Frame, TransportFrame},
    noise::initiator::Initiator,
};
use bwphone_nm::{
    b64,
    frame::{read_frame, write_frame},
};
use bwphone_transport::noise::StaticKeypair;
use bwphone_wrap::{UserKey, phone::Pin, rsa::RsaPublicKey, wrap};
use serde_json::{Value, json};
use tokio::io::DuplexStream;

const ACCOUNT: [u8; 16] = [1; 16];
const USER: &str = "6e5f3b2a-0c1d-4e8f-9a7b-112233445566";

async fn world(decision: Decision) -> (Arc<Ctx>, Arc<FakePhone>, UserKey) {
    let pc = StaticKeypair::generate().unwrap();
    let pairing_id = [7u8; 16];
    let phone = Arc::new(FakePhone::new(pc.public, pairing_id, always(decision)));
    let (phone_addr, task): (SocketAddr, _) = phone.clone().listen("127.0.0.1:0").await.unwrap();
    std::mem::forget(task);
    let private = fixed_rsa_key(0);
    let user_key = UserKey::from_slice(&std::array::from_fn::<u8, 64, _>(|i| i as u8)).unwrap();
    let blob = wrap(&RsaPublicKey::from(&private), &user_key).unwrap();
    phone.add_account(ACCOUNT, "Work", private, Some(Pin::of(blob.rsa_ct())));
    let mut accounts = Accounts::default();
    accounts.push(Account { id: ACCOUNT, user_id: USER.into(), label: "Work".into(), blob }).unwrap();
    let ctx = Arc::new(Ctx {
        accounts,
        phone: Phone { public: phone.public(), pairing_id, host: "test-PC".into() },
        state: Mutex::new(PhoneState { addr: Some(phone_addr), ..Default::default() }),
        secrets: Secrets::fixed(*pc.private),
        notifier: Notifier::Fake(Arc::new(FakeNotifier::default())),
        queue: Queue::default(),
        pairing: Mutex::new(None),
        pairing_path: None,
    });
    tokio::spawn(unlock::worker(ctx.clone()));
    (ctx, phone, user_key)
}

fn env(to: &str, frame: &Frame, topic: Option<&str>) -> Vec<u8> {
    serde_json::to_vec(&json!({"type": "bitwarden-ipc-message", "message": {
        "destination": to, "payload": frame.to_cbor(), "topic": topic
    }}))
    .unwrap()
}

async fn next_envelope(pipe: &mut DuplexStream) -> Value {
    let bytes = tokio::time::timeout(Duration::from_secs(10), read_frame(pipe)).await.expect("daemon went silent").unwrap().expect("daemon closed the pipe");
    serde_json::from_slice(&bytes).unwrap()
}

fn frame_of(v: &Value) -> Frame {
    let payload: Vec<u8> = serde_json::from_value(v["message"]["payload"].clone()).unwrap();
    Frame::from_cbor(&payload).unwrap()
}

async fn handshake(pipe: &mut DuplexStream, to: &str) -> Initiator {
    let (mut noise, start) = Initiator::start(CipherSuite::Noise_NN_P256_AESGCM_SHA256);
    write_frame(pipe, &env(to, &Frame::HandshakeStart(start), None)).await.unwrap();
    let v = next_envelope(pipe).await;
    let Frame::HandshakeFinish(f) = frame_of(&v) else { panic!("{v}") };
    noise.finish(&f);
    noise
}

fn rpc(noise: &mut Initiator, id: &str, request_type: &str, request: Value) -> TransportFrame {
    let body = json!({"request": request, "request_id": id, "request_type": request_type, "response_topic": format!("RpcResponseMessage:{id}")});
    noise.seal(&serde_json::to_vec(&body).unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn hostile_mixed_traffic_then_an_honest_unlock() {
    let (ctx, phone, user_key) = world(Decision::Approve).await;
    let (mut pipe, theirs) = tokio::io::duplex(1 << 20);
    let server = tokio::spawn(serve_proxy(theirs, ctx));
    assert_eq!(read_frame(&mut pipe).await.unwrap().unwrap(), br#"{"command":"connected"}"#);

    let mut honest = handshake(&mut pipe, "DesktopRenderer").await;
    // A second session on the other endpoint must not disturb the first.
    let mut main = handshake(&mut pipe, "DesktopMain").await;

    // Garbage of every shape, interleaved with legacy frames, on the same pipe.
    let garbage: Vec<Vec<u8>> = vec![
        b"".to_vec(),
        b"{".to_vec(),
        br#"{"type":"bitwarden-ipc-message"}"#.to_vec(),
        br#"{"type":"bitwarden-ipc-message","message":{"destination":"DesktopRenderer","payload":[256]}}"#.to_vec(),
        br#"{"type":"bitwarden-ipc-message","message":{"destination":"DesktopRenderer","payload":[],"topic":"RpcRequestMessage"}}"#.to_vec(),
        br#"{"type":"bitwarden-ipc-message","message":{"destination":{"BrowserBackground":{"id":"Own"}},"payload":[1]}}"#.to_vec(),
        br#"{"appId":"x","message":{"command":"setupEncryption","publicKey":"AAAA","userId":"u","messageId":1,"timestamp":0}}"#.to_vec(),
        br#"{"appId":"x","message":{"encryptedString":"2.AAAA|AAAA|AAAA","encryptionType":2}}"#.to_vec(),
        format!(r#"{{"type":"bitwarden-ipc-message","message":{{"destination":{}1{},"payload":[]}}}}"#, "[".repeat(5000), "]".repeat(5000)).into_bytes(),
        // A forged transport frame on the honest session, and one with a huge nonce.
        env("DesktopRenderer", &Frame::TransportFrame(TransportFrame { payload: vec![0; 64].into(), nonce: 2 }), Some("RpcRequestMessage")),
        env("DesktopRenderer", &Frame::TransportFrame(TransportFrame { payload: vec![0; 64].into(), nonce: u64::MAX }), Some("RpcRequestMessage")),
        env("DesktopRenderer", &Frame::HandshakeFinish(bwphone_ipc::frame::HandshakeFinish { noise_frame: vec![0; 48] }), None),
        // A 1 MiB-ish envelope of a payload number array.
        format!(r#"{{"type":"bitwarden-ipc-message","message":{{"destination":"DesktopRenderer","payload":[{}0]}}}}"#, "0,".repeat(500_000)).into_bytes(),
    ];
    for g in &garbage {
        write_frame(&mut pipe, g).await.unwrap();
    }

    // A request for DesktopMain's session sealed with the Renderer keys is not opened.
    let cross = rpc(&mut honest, "cross", "UnlockBiometrics", json!({"user_id": USER}));
    write_frame(&mut pipe, &env("DesktopMain", &Frame::TransportFrame(cross.clone()), Some("RpcRequestMessage"))).await.unwrap();

    // Honest status on Main, then unlock on Renderer.
    let s = rpc(&mut main, "s1", "GetBiometricsStatus", json!({"user_id": USER}));
    write_frame(&mut pipe, &env("DesktopMain", &Frame::TransportFrame(s), Some("RpcRequestMessage"))).await.unwrap();
    let u = rpc(&mut honest, "u1", "UnlockBiometrics", json!({"user_id": USER.to_uppercase()}));
    write_frame(&mut pipe, &env("DesktopRenderer", &Frame::TransportFrame(u.clone()), Some("RpcRequestMessage"))).await.unwrap();
    // Replays of the unlock are dropped, not re-run.
    for _ in 0..3 {
        write_frame(&mut pipe, &env("DesktopRenderer", &Frame::TransportFrame(u.clone()), Some("RpcRequestMessage"))).await.unwrap();
    }

    let mut got_status = false;
    let mut got_key = false;
    while !(got_status && got_key) {
        let v = next_envelope(&mut pipe).await;
        if v.get("command").is_some() || v.get("appId").is_some() {
            continue; // legacy noise answering legacy garbage
        }
        match frame_of(&v) {
            Frame::TransportFrame(t) if v["type"] == "bitwarden-ipc-message" => {
                let r: Value = serde_json::from_slice(&main.open(&t)).unwrap();
                assert_eq!(r["request_id"], "s1");
                assert_eq!(r["result"], json!({"Ok": "Available"}));
                got_status = true;
            }
            Frame::TransportFrame(t) => {
                assert_eq!(v["originalSource"], "DesktopRenderer");
                let r: Value = serde_json::from_slice(&honest.open(&t)).unwrap();
                assert_eq!(r["request_id"], "u1", "only the honest request is answered: {r}");
                assert_eq!(r["result"]["Ok"]["user_key"], b64(user_key.as_bytes()));
                got_key = true;
            }
            Frame::CryptoInvalidated => panic!("an established session was invalidated by garbage: {v}"),
            other => panic!("unexpected {other:?}"),
        }
    }
    // Exactly one prompt: neither replays nor the cross-session frame reached the phone.
    tokio::time::sleep(Duration::from_millis(300)).await;
    let prompts = phone.events().iter().filter(|e| matches!(e, Event::Prompted(_))).count();
    assert_eq!(prompts, 1);
    assert!(!server.is_finished(), "the pipe must survive hostile frames");
}
