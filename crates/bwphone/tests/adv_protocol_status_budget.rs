//! Adversarial timing check at the `serve_proxy` level: the extension's
//! 500 ms `BIOMETRICS_NO_INTERACTION_TIMEOUT` covers `IpcClientExt::request`,
//! which includes the Noise handshake when the session is missing or older
//! than 300 s (the usual case at a lock screen). Measured here from the
//! `HandshakeStart` write to the status answer, with a phone believed down
//! whose recovery ping hangs. Envelopes are shaped as `desktop-ipc.transport.ts`
//! posts them: no `topic` key on crypto frames (JSON.stringify drops undefined).
//!
//! `cargo test -p bwphone --test adv_protocol_status_budget`

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bwphone::{
    Ctx,
    accounts::{Account, Accounts},
    notify::{FakeNotifier, Notifier},
    pairing::Pairing,
    phone::Phone,
    secrets::Secrets,
    serve::serve_proxy,
    unlock::{self, PhoneState, Queue},
};
use bwphone_fakephone::{Decision, FakePhone, always, fixed_rsa_key};
use bwphone_ipc::{
    frame::{CipherSuite, Frame},
    noise::initiator::Initiator,
};
use bwphone_nm::frame::{read_frame, write_frame};
use bwphone_transport::noise::StaticKeypair;
use bwphone_wrap::{UserKey, phone::Pin, rsa::RsaPublicKey, wrap};
use serde_json::{Value, json};

const USER: &str = "6e5f3b2a-0c1d-4e8f-9a7b-112233445566";

async fn ctx() -> Arc<Ctx> {
    let pc = StaticKeypair::generate().unwrap();
    let pairing_id = [7u8; 16];
    let phone = Arc::new(FakePhone::new(pc.public, pairing_id, always(Decision::Approve)));
    let (phone_addr, task) = phone.clone().listen("127.0.0.1:0").await.unwrap();
    std::mem::forget(task);
    let private = fixed_rsa_key(0);
    let user_key = UserKey::from_slice(&[9u8; 64]).unwrap();
    let blob = wrap(&RsaPublicKey::from(&private), &user_key).unwrap();
    phone.add_account([1; 16], "Work", private, Some(Pin::of(blob.rsa_ct())));
    let mut accounts = Accounts::default();
    accounts.push(Account { id: [1; 16], user_id: USER.into(), label: "Work".into(), blob }).unwrap();
    let ctx = Arc::new(Ctx {
        accounts,
        phone: Phone { public: phone.public(), pairing_id, host: "test-PC".into() },
        state: Mutex::new(PhoneState { addr: Some(phone_addr), ..Default::default() }),
        secrets: Secrets::fixed(*pc.private),
        notifier: Notifier::Fake(Arc::new(FakeNotifier::default())),
        queue: Queue::default(),
        pairing: Mutex::new(Some(Pairing::new(&phone.public(), &pairing_id, "fake", phone_addr.port(), "today"))),
        pairing_path: None,
    });
    tokio::spawn(unlock::worker(ctx.clone()));
    ctx
}

fn post(frame: &Frame, topic: Option<&str>) -> Vec<u8> {
    let mut msg = json!({"destination": "DesktopRenderer", "payload": frame.to_cbor()});
    if let Some(t) = topic {
        msg["topic"] = json!(t);
    }
    serde_json::to_vec(&json!({"type": "bitwarden-ipc-message", "message": msg})).unwrap()
}

async fn next(pipe: &mut tokio::io::DuplexStream) -> (Frame, Value) {
    let v: Value = serde_json::from_slice(&read_frame(pipe).await.unwrap().unwrap()).unwrap();
    assert_eq!(v["originalSource"], "DesktopRenderer");
    let payload: Vec<u8> = serde_json::from_value(v["message"]["payload"].clone()).unwrap();
    (Frame::from_cbor(&payload).unwrap(), v)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_with_handshake_fits_the_extension_500ms_while_a_ping_hangs() {
    let ctx = ctx().await;
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    {
        let mut state = ctx.state.lock().unwrap();
        state.addr = Some(silent.local_addr().unwrap());
        state.note_reach(false);
        state.last_attempt = Some(Instant::now() - unlock::RETRY_AFTER);
    }
    let (mut pipe, theirs) = tokio::io::duplex(1 << 16);
    tokio::spawn(serve_proxy(theirs, ctx.clone()));
    assert_eq!(read_frame(&mut pipe).await.unwrap().unwrap(), br#"{"command":"connected"}"#);

    let t0 = Instant::now();
    let (mut noise, start) = Initiator::start(CipherSuite::Noise_NN_P256_AESGCM_SHA256);
    write_frame(&mut pipe, &post(&Frame::HandshakeStart(start), None)).await.unwrap();
    let (Frame::HandshakeFinish(finish), _) = next(&mut pipe).await else { panic!() };
    noise.finish(&finish);
    let handshake = t0.elapsed();
    let body = json!({"request": {"user_id": USER}, "request_id": "r1", "request_type": "GetBiometricsStatus",
                      "response_topic": "RpcResponseMessage:r1"});
    let frame = Frame::TransportFrame(noise.seal(&serde_json::to_vec(&body).unwrap()));
    write_frame(&mut pipe, &post(&frame, Some("RpcRequestMessage"))).await.unwrap();
    let (Frame::TransportFrame(t), v) = next(&mut pipe).await else { panic!() };
    let total = t0.elapsed();
    assert_eq!(v["message"]["topic"], "RpcResponseMessage:r1");
    let reply: Value = serde_json::from_slice(&noise.open(&t)).unwrap();
    assert_eq!(reply["result"], json!({"Ok": "HardwareUnavailable"}));
    eprintln!("handshake {handshake:?}, total {total:?}");
    assert!(total < Duration::from_millis(500), "handshake {handshake:?}, total {total:?}");
    drop(silent);
}
