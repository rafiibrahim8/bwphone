//! Adversarial concurrency tests for the SDK IPC path in `serve.rs` and the
//! shared `availability` changes. Harness copied from `tests/unlock.rs`.

use std::{
    net::SocketAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bwphone::{
    Ctx,
    accounts::{Account, Accounts},
    control::{self, ControlRequest},
    notify::{FakeNotifier, Notifier},
    pairing::Pairing,
    phone::Phone,
    secrets::Secrets,
    serve::serve_proxy,
    unlock::{self, PhoneState, Queue},
};
use bwphone_fakephone::{Decision, Event, FakePhone, Person, after, always, fixed_rsa_key};
use bwphone_ipc::{
    frame::{CipherSuite, Frame, TransportFrame},
    noise::initiator::Initiator,
};
use bwphone_nm::{
    b64,
    frame::{read_frame, write_frame},
    session::{EncString, SessionKey},
    unb64,
};
use bwphone_transport::noise::StaticKeypair;
use bwphone_wrap::{
    UserKey,
    phone::Pin,
    rsa::{Oaep, RsaPrivateKey, RsaPublicKey, pkcs8::EncodePublicKey as _},
    wrap,
};
use serde_json::{Value, json};
use tokio::io::DuplexStream;

const ACCOUNT: [u8; 16] = [1; 16];
const USER: &str = "user-1";

struct World {
    ctx: Arc<Ctx>,
    phone: Arc<FakePhone>,
    notifier: Arc<FakeNotifier>,
    user_key: UserKey,
    phone_addr: SocketAddr,
}

async fn world(person: Person) -> World {
    let pc = StaticKeypair::generate().unwrap();
    let pairing_id = [7u8; 16];
    let phone = Arc::new(FakePhone::new(pc.public, pairing_id, person));
    let (phone_addr, task) = phone.clone().listen("127.0.0.1:0").await.unwrap();
    let private = fixed_rsa_key(0);
    let public = RsaPublicKey::from(&private);
    let user_key = UserKey::from_slice(&std::array::from_fn::<u8, 64, _>(|i| i as u8)).unwrap();
    let blob = wrap(&public, &user_key).unwrap();
    phone.add_account(ACCOUNT, "Work", private, Some(Pin::of(blob.rsa_ct())));
    let mut accounts = Accounts::default();
    accounts.push(Account { id: ACCOUNT, user_id: USER.into(), label: "Work".into(), blob }).unwrap();
    let notifier = Arc::new(FakeNotifier::default());
    let pc_private = *pc.private;
    let ctx = Arc::new(Ctx {
        accounts,
        phone: Phone { public: phone.public(), pairing_id, host: "test-PC".into() },
        state: Mutex::new(PhoneState { addr: Some(phone_addr), ..Default::default() }),
        secrets: Secrets::fixed(pc_private),
        notifier: Notifier::Fake(notifier.clone()),
        queue: Queue::default(),
        pairing: Mutex::new(Some(Pairing::new(&phone.public(), &pairing_id, "fake", phone_addr.port(), "today"))),
        pairing_path: None,
    });
    tokio::spawn(unlock::worker(ctx.clone()));
    std::mem::forget(task);
    World { ctx, phone, notifier, user_key, phone_addr }
}

fn now_ms() -> i64 {
    bwphone_nm::peer::now_ms()
}

async fn wait_for(what: &str, mut cond: impl FnMut() -> bool) {
    let start = Instant::now();
    while !cond() {
        assert!(start.elapsed() < Duration::from_secs(10), "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn envelope(frame: &Frame, topic: Option<&str>) -> Vec<u8> {
    serde_json::to_vec(&json!({"type": "bitwarden-ipc-message", "message": {
        "destination": "DesktopRenderer", "payload": frame.to_cbor(), "topic": topic
    }}))
    .unwrap()
}

fn rpc_body(id: &str, request_type: &str, request: Value) -> Vec<u8> {
    serde_json::to_vec(&json!({"request": request, "request_id": id, "request_type": request_type,
                              "response_topic": format!("RpcResponseMessage:{id}")}))
    .unwrap()
}

/// One envelope from the daemon: (frame, topic).
async fn read_envelope(pipe: &mut DuplexStream) -> (Frame, Option<String>) {
    let v: Value = serde_json::from_slice(&read_frame(pipe).await.unwrap().unwrap()).unwrap();
    assert_eq!(v["type"], "forwarded-bitwarden-ipc-message", "{v}");
    let payload: Vec<u8> = serde_json::from_value(v["message"]["payload"].clone()).unwrap();
    (Frame::from_cbor(&payload).unwrap(), v["message"]["topic"].as_str().map(Into::into))
}

/// Opens with `noise` if it can, without disturbing it otherwise.
fn try_open(noise: &mut Initiator, t: &TransportFrame) -> Option<Vec<u8>> {
    thread_local!(static QUIET: std::cell::Cell<bool> = const { std::cell::Cell::new(false) });
    static HOOK: std::sync::Once = std::sync::Once::new();
    // One process-wide hook that stays quiet only inside this function, so
    // other tests' panic messages are never swallowed.
    HOOK.call_once(|| {
        let prev = std::panic::take_hook();
        std::panic::set_hook(Box::new(move |info| {
            if !QUIET.with(|q| q.get()) {
                prev(info)
            }
        }));
    });
    QUIET.with(|q| q.set(true));
    let r = catch_unwind(AssertUnwindSafe(|| noise.open(t))).ok();
    QUIET.with(|q| q.set(false));
    r
}

/// An IPC client on a raw pipe (so the pipe can be shared with legacy frames).
struct Ipc {
    noise: Initiator,
    next: u64,
}

impl Ipc {
    async fn handshake(pipe: &mut DuplexStream) -> Self {
        let (mut noise, start) = Initiator::start(CipherSuite::Noise_NN_P256_AESGCM_SHA256);
        write_frame(pipe, &envelope(&Frame::HandshakeStart(start), None)).await.unwrap();
        let (frame, _) = read_envelope(pipe).await;
        let Frame::HandshakeFinish(finish) = frame else { panic!("{frame:?}") };
        noise.finish(&finish);
        Self { noise, next: 0 }
    }

    fn request(&mut self, request_type: &str, request: Value) -> (String, Vec<u8>) {
        self.next += 1;
        let id = format!("req-{}", self.next);
        let frame = Frame::TransportFrame(self.noise.seal(&rpc_body(&id, request_type, request)));
        (id, envelope(&frame, Some("RpcRequestMessage")))
    }

    async fn send(&mut self, pipe: &mut DuplexStream, request_type: &str, request: Value) -> String {
        let (id, bytes) = self.request(request_type, request);
        write_frame(pipe, &bytes).await.unwrap();
        id
    }

    async fn read(&mut self, pipe: &mut DuplexStream) -> (String, Value) {
        let (frame, _) = read_envelope(pipe).await;
        let Frame::TransportFrame(t) = frame else { panic!("expected a transport frame, got {frame:?}") };
        let v: Value = serde_json::from_slice(&self.noise.open(&t)).unwrap();
        (v["request_id"].as_str().unwrap().to_owned(), v["result"].clone())
    }
}

async fn ipc_pipe(ctx: Arc<Ctx>, buf: usize) -> DuplexStream {
    let (mut pipe, theirs) = tokio::io::duplex(buf);
    tokio::spawn(serve_proxy(theirs, ctx));
    assert_eq!(read_frame(&mut pipe).await.unwrap().unwrap(), br#"{"command":"connected"}"#);
    pipe
}

/// Legacy native-messaging client on a raw pipe.
struct Legacy {
    app_id: String,
    key: SessionKey,
    next_id: i64,
}

impl Legacy {
    async fn setup(pipe: &mut DuplexStream, app_id: &str) -> Self {
        let private: RsaPrivateKey = fixed_rsa_key(1);
        let spki = b64(RsaPublicKey::from(&private).to_public_key_der().unwrap().as_bytes());
        let frame = json!({"appId": app_id, "message": {
            "command": "setupEncryption", "publicKey": spki, "userId": USER, "messageId": 0, "timestamp": now_ms()
        }});
        write_frame(pipe, &serde_json::to_vec(&frame).unwrap()).await.unwrap();
        let reply: Value = serde_json::from_slice(&read_frame(pipe).await.unwrap().unwrap()).unwrap();
        let ct = unb64(reply["sharedSecret"].as_str().unwrap()).unwrap();
        let raw = private.decrypt(Oaep::new::<sha1::Sha1>(), &ct).unwrap();
        Self { app_id: app_id.into(), key: SessionKey::from_slice(&raw).unwrap(), next_id: 1 }
    }

    async fn send(&mut self, pipe: &mut DuplexStream, command: &str) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        let inner = json!({"command": command, "messageId": id, "userId": USER, "timestamp": now_ms()});
        let enc = EncString::seal(&self.key, &serde_json::to_vec(&inner).unwrap());
        let frame = json!({"appId": self.app_id, "message": enc});
        write_frame(pipe, &serde_json::to_vec(&frame).unwrap()).await.unwrap();
        id
    }

    fn open(&self, outer: &Value) -> Value {
        let enc: EncString = serde_json::from_value(outer["message"].clone()).unwrap();
        serde_json::from_slice(&enc.open(&self.key).unwrap()).unwrap()
    }
}

// ---------------------------------------------------------------------------
// 1. Nonce/session ordering: a frame sealed under the session a
//    HandshakeStart just created must never reach the pipe before the
//    HandshakeFinish that gives the browser that session's keys.
//
//    `on_ipc_frame` drops the peer lock after `receive()` and only then
//    awaits `tx.send(finish)`. Any answer task that takes the lock in that
//    gap seals under the new session and enqueues first. On a current-thread
//    runtime the gap opens whenever the read loop's coop budget runs out at
//    that `send` (the semaphore acquire is a coop point); on the
//    multi-thread daemon runtime another worker can simply run in parallel.
//    The sweep over K moves the budget exhaustion point across the frames.

fn to_main(frame: &Frame) -> Vec<u8> {
    serde_json::to_vec(&json!({"type": "bitwarden-ipc-message", "message": {
        "destination": "DesktopMain", "payload": frame.to_cbor(), "topic": "RpcRequestMessage"
    }}))
    .unwrap()
}

/// Runs one burst: M shim frames (each costs the read loop one extra coop
/// unit: a transport frame to `DesktopMain`, which has no session, is
/// answered `CryptoInvalidated` through `tx.send`), K Discover requests on
/// session N, then a HandshakeStart. Returns how many replies went out,
/// before the HandshakeFinish, sealed under the session it establishes.
async fn burst(ctx: Arc<Ctx>, m: usize, k: usize) -> usize {
    let mut pipe = ipc_pipe(ctx, 1 << 22).await;
    let mut old = Ipc::handshake(&mut pipe).await;
    let mut frames = Vec::new();
    for _ in 0..m {
        frames.push(to_main(&Frame::TransportFrame(TransportFrame { payload: vec![0u8; 32].into(), nonce: 1 })));
    }
    for _ in 0..k {
        frames.push(old.request("DiscoverRequest", Value::Null).1);
    }
    let (mut new, start) = Initiator::start(CipherSuite::Noise_NN_P256_AESGCM_SHA256);
    frames.push(envelope(&Frame::HandshakeStart(start), None));
    // One write, so the read loop finds every frame already buffered.
    let mut bytes = Vec::new();
    for f in &frames {
        bytes.extend_from_slice(&(f.len() as u32).to_ne_bytes());
        bytes.extend_from_slice(f);
    }
    tokio::io::AsyncWriteExt::write_all(&mut pipe, &bytes).await.unwrap();

    let mut early_new = Vec::new();
    let mut violations = 0;
    let (mut seen_finish, mut answered, mut mains) = (false, 0, 0);
    while !(seen_finish && answered == k && mains == m) {
        let raw = tokio::time::timeout(Duration::from_secs(5), read_frame(&mut pipe)).await.expect("stalled").unwrap().unwrap();
        let v: Value = serde_json::from_slice(&raw).unwrap();
        let payload: Vec<u8> = serde_json::from_value(v["message"]["payload"].clone()).unwrap();
        let frame = Frame::from_cbor(&payload).unwrap();
        if v["type"] == "bitwarden-ipc-message" {
            assert_eq!(frame, Frame::CryptoInvalidated);
            mains += 1;
            continue;
        }
        match frame {
            Frame::HandshakeFinish(f) => {
                new.finish(&f);
                seen_finish = true;
                // Prove the early frames really were session N+1's.
                for t in early_new.drain(..) {
                    let _: Vec<u8> = new.open(&t);
                    violations += 1;
                }
            }
            Frame::TransportFrame(t) => {
                answered += 1;
                if seen_finish {
                    assert!(try_open(&mut new, &t).is_some(), "m={m} k={k}: a frame after the finish does not open");
                } else if try_open(&mut old.noise, &t).is_none() {
                    early_new.push(t);
                }
            }
            other => panic!("{other:?}"),
        }
    }
    violations
}

#[tokio::test]
async fn handshake_finish_precedes_frames_sealed_under_its_session() {
    let w = world(always(Decision::Approve)).await;
    let mut bad = Vec::new();
    for m in 0..4 {
        for k in 0..60 {
            let v = burst(w.ctx.clone(), m, k).await;
            if v > 0 {
                bad.push((m, k, v));
            }
        }
    }
    assert!(
        bad.is_empty(),
        "replies sealed under the new session went out before its HandshakeFinish, so the browser cannot open them; (M, K, how many): {bad:?}"
    );
}

/// The same race on the daemon's real runtime flavour, by brute force.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn handshake_finish_ordering_multi_thread() {
    let w = world(always(Decision::Approve)).await;
    let mut bad = Vec::new();
    for round in 0..300 {
        let v = burst(w.ctx.clone(), round % 4, 4 + round % 13).await;
        if v > 0 {
            bad.push((round, v));
        }
    }
    assert!(bad.is_empty(), "early new-session replies in rounds: {bad:?}");
}

// ---------------------------------------------------------------------------
// 2. A re-handshake while the prompt is up: the key must reach the browser
//    under the new session.

#[tokio::test]
async fn unlock_key_survives_a_rehandshake_mid_prompt() {
    let w = world(after(Duration::from_millis(800), Decision::Approve)).await;
    let mut pipe = ipc_pipe(w.ctx.clone(), 1 << 16).await;
    let mut a = Ipc::handshake(&mut pipe).await;
    let id = a.send(&mut pipe, "UnlockBiometrics", json!({"user_id": USER})).await;
    let n = w.notifier.clone();
    wait_for("the prompt", || n.shown().len() == 1).await;
    let mut b = Ipc::handshake(&mut pipe).await;
    let (got, result) = tokio::time::timeout(Duration::from_secs(5), b.read(&mut pipe)).await.expect("no answer");
    assert_eq!(got, id);
    assert_eq!(result["Ok"]["user_key"], b64(w.user_key.as_bytes()));
}

// ---------------------------------------------------------------------------
// 3. CryptoInvalidated while the prompt is up, and the browser handshakes
//    again only after the phone answered: the approved key is sealed under
//    no session, logged "ipc answer dropped", and never delivered. The
//    person scanned a finger for nothing.

#[tokio::test]
#[ignore = "accepted (SPECIFICATION.md §3): the SDK sends CryptoInvalidated only with no session for us, i.e. after losing its state (the pending request goes too) or after its own re-handshake timed out (2 s), which the daemon answers at once"]
async fn unlock_key_after_crypto_invalidated_is_not_lost() {
    let w = world(after(Duration::from_millis(500), Decision::Approve)).await;
    let mut pipe = ipc_pipe(w.ctx.clone(), 1 << 16).await;
    let mut a = Ipc::handshake(&mut pipe).await;
    let id = a.send(&mut pipe, "UnlockBiometrics", json!({"user_id": USER})).await;
    let n = w.notifier.clone();
    wait_for("the prompt", || n.shown().len() == 1).await;
    write_frame(&mut pipe, &envelope(&Frame::CryptoInvalidated, None)).await.unwrap();
    wait_for("the prompt to close", || !n.shown()[0].2).await;
    tokio::time::sleep(Duration::from_millis(200)).await;
    let mut b = Ipc::handshake(&mut pipe).await;
    let got = tokio::time::timeout(Duration::from_secs(3), b.read(&mut pipe)).await;
    match got {
        Ok((got, result)) => {
            assert_eq!(got, id);
            assert_eq!(result["Ok"]["user_key"], b64(w.user_key.as_bytes()));
        }
        Err(_) => panic!("the phone approved, but the key was dropped for want of a session and never delivered"),
    }
}

// ---------------------------------------------------------------------------
// 4. Lifecycle: an IPC pipe that closes takes its prompt down, as legacy.

#[tokio::test]
async fn ipc_pipe_close_takes_the_prompt_down() {
    let w = world(always(Decision::Ignore)).await;
    let mut pipe = ipc_pipe(w.ctx.clone(), 1 << 16).await;
    let mut a = Ipc::handshake(&mut pipe).await;
    a.send(&mut pipe, "UnlockBiometrics", json!({"user_id": USER})).await;
    let n = w.notifier.clone();
    wait_for("the prompt", || n.shown().len() == 1).await;
    let left = Instant::now();
    drop(pipe);
    wait_for("the prompt to close", || !n.shown()[0].2).await;
    assert!(left.elapsed() < Duration::from_secs(2));
    assert!(w.ctx.queue.is_empty());
}

// ---------------------------------------------------------------------------
// 5. Two IPC pipes, one account: one prompt, both keys, each under its own session.

#[tokio::test]
async fn two_ipc_pipes_share_one_prompt() {
    let w = world(after(Duration::from_millis(500), Decision::Approve)).await;
    let mut p1 = ipc_pipe(w.ctx.clone(), 1 << 16).await;
    let mut p2 = ipc_pipe(w.ctx.clone(), 1 << 16).await;
    let mut a = Ipc::handshake(&mut p1).await;
    let mut b = Ipc::handshake(&mut p2).await;
    let ia = a.send(&mut p1, "UnlockBiometrics", json!({"user_id": USER})).await;
    let ib = b.send(&mut p2, "UnlockBiometrics", json!({"user_id": USER.to_uppercase()})).await;
    let ((ga, ra), (gb, rb)) = tokio::join!(a.read(&mut p1), b.read(&mut p2));
    assert_eq!((ga, gb), (ia, ib));
    assert_eq!(ra["Ok"]["user_key"], b64(w.user_key.as_bytes()));
    assert_eq!(rb["Ok"]["user_key"], b64(w.user_key.as_bytes()));
    assert_eq!(w.phone.events().iter().filter(|e| matches!(e, Event::Prompted(_))).count(), 1);
}

// ---------------------------------------------------------------------------
// 6. Both protocols on ONE pipe, unlocking at once: both answered, one prompt.

#[tokio::test]
async fn legacy_and_ipc_on_one_pipe() {
    let w = world(after(Duration::from_millis(500), Decision::Approve)).await;
    let mut pipe = ipc_pipe(w.ctx.clone(), 1 << 16).await;
    let mut legacy = Legacy::setup(&mut pipe, "app-1").await;
    let mut ipc = Ipc::handshake(&mut pipe).await;
    let lid = legacy.send(&mut pipe, "unlockWithBiometricsForUser").await;
    let iid = ipc.send(&mut pipe, "UnlockBiometrics", json!({"user_id": USER})).await;
    let (mut got_legacy, mut got_ipc) = (false, false);
    for _ in 0..2 {
        let v: Value = serde_json::from_slice(&read_frame(&mut pipe).await.unwrap().unwrap()).unwrap();
        if v.get("appId").is_some() {
            let r = legacy.open(&v);
            assert_eq!(r["messageId"], lid);
            assert_eq!(r["userKeyB64"], b64(w.user_key.as_bytes()));
            got_legacy = true;
        } else {
            let payload: Vec<u8> = serde_json::from_value(v["message"]["payload"].clone()).unwrap();
            let Frame::TransportFrame(t) = Frame::from_cbor(&payload).unwrap() else { panic!() };
            let r: Value = serde_json::from_slice(&ipc.noise.open(&t)).unwrap();
            assert_eq!(r["request_id"], iid);
            assert_eq!(r["result"]["Ok"]["user_key"], b64(w.user_key.as_bytes()));
            got_ipc = true;
        }
    }
    assert!(got_legacy && got_ipc);
    assert_eq!(w.phone.events().iter().filter(|e| matches!(e, Event::Prompted(_))).count(), 1);
}

// ---------------------------------------------------------------------------
// 7. Legacy regression from the `pinging` flag: two status queries at once
//    while the phone is believed down but has come back. Before the change
//    both waited for a ping and both said available (0); now the second is
//    told unavailable (2) at once even though the first is about to say 0.

#[tokio::test]
async fn concurrent_legacy_status_during_recovery_ping() {
    let w = world(always(Decision::Approve)).await;
    {
        let mut state = w.ctx.state.lock().unwrap();
        state.note_reach(false);
        state.last_attempt = Some(Instant::now() - unlock::RETRY_AFTER);
    }
    let mut pipe = ipc_pipe(w.ctx.clone(), 1 << 16).await;
    let mut legacy = Legacy::setup(&mut pipe, "app-1").await;
    legacy.send(&mut pipe, "getBiometricsStatusForUser").await;
    legacy.send(&mut pipe, "getBiometricsStatus").await;
    let mut responses = Vec::new();
    for _ in 0..2 {
        let v: Value = serde_json::from_slice(&read_frame(&mut pipe).await.unwrap().unwrap()).unwrap();
        let r = legacy.open(&v);
        responses.push((r["command"].as_str().unwrap().to_owned(), r["response"].clone()));
    }
    assert!(
        responses.iter().all(|(_, r)| *r == 0),
        "the phone is up and one ping proves it, yet a concurrent query was told unavailable: {responses:?}"
    );
}

// ---------------------------------------------------------------------------
// 8. A recovery ping to the old address outlives a hello announcing the new
//    one and then overwrites the fresh state: the phone that just said
//    hello is believed down for RETRY_AFTER (30 s). The IPC status detaches
//    the ping from the request, so it also survives the pipe closing.

#[tokio::test]
async fn stale_ping_result_overrides_a_fresh_hello() {
    let w = world(always(Decision::Approve)).await;
    // A listener that never accepts: the ping connects, then waits out PING_BUDGET (2 s).
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    {
        let mut state = w.ctx.state.lock().unwrap();
        state.addr = Some(silent.local_addr().unwrap());
        state.note_reach(false);
        state.last_attempt = Some(Instant::now() - unlock::RETRY_AFTER);
    }
    let mut pipe = ipc_pipe(w.ctx.clone(), 1 << 16).await;
    let mut ipc = Ipc::handshake(&mut pipe).await;
    ipc.send(&mut pipe, "GetBiometricsStatus", json!({"user_id": USER})).await;
    assert_eq!(ipc.read(&mut pipe).await.1, json!({"Ok": "HardwareUnavailable"}));
    assert!(w.ctx.state.lock().unwrap().pinging());
    drop(pipe); // the browser goes away; the ping does not

    // The phone, on a new address, says hello.
    let ok = control::handle(&w.ctx, ControlRequest::Hello { ip: w.phone_addr.ip(), port: w.phone_addr.port(), seq: 1 }).await;
    assert_eq!(ok["ok"], true);
    let mut pipe = ipc_pipe(w.ctx.clone(), 1 << 16).await;
    let mut ipc = Ipc::handshake(&mut pipe).await;
    ipc.send(&mut pipe, "GetBiometricsStatus", json!({"user_id": USER})).await;
    assert_eq!(ipc.read(&mut pipe).await.1, json!({"Ok": "Available"}), "fresh hello");

    let ctx = w.ctx.clone();
    wait_for("the stale ping to end", || !ctx.state.lock().unwrap().pinging()).await;
    ipc.send(&mut pipe, "GetBiometricsStatus", json!({"user_id": USER})).await;
    assert_eq!(
        ipc.read(&mut pipe).await.1,
        json!({"Ok": "Available"}),
        "a ping to the address the phone left marked the phone that just said hello as down for 30 s"
    );
    drop(silent);
}

// ---------------------------------------------------------------------------
// 9. A legacy status query whose pipe closes mid-ping clears `pinging`
//    (the Drop guard) and a later query can ping again.

#[tokio::test]
async fn aborted_legacy_ping_clears_the_flag() {
    let w = world(always(Decision::Approve)).await;
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    {
        let mut state = w.ctx.state.lock().unwrap();
        state.addr = Some(silent.local_addr().unwrap());
        state.note_reach(false);
        state.last_attempt = Some(Instant::now() - unlock::RETRY_AFTER);
    }
    let mut pipe = ipc_pipe(w.ctx.clone(), 1 << 16).await;
    let mut legacy = Legacy::setup(&mut pipe, "app-1").await;
    legacy.send(&mut pipe, "getBiometricsStatusForUser").await;
    let ctx = w.ctx.clone();
    wait_for("the ping to start", || ctx.state.lock().unwrap().pinging()).await;
    drop(pipe);
    wait_for("the flag to clear", || !ctx.state.lock().unwrap().pinging()).await;
    assert!(w.ctx.state.lock().unwrap().believed_down());
    drop(silent);
}

// ---------------------------------------------------------------------------
// 10. Status latency on a pipe where an unlock is in flight and a burst of
//     other requests arrives: the status answer still leaves within 500 ms.

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn status_under_load_within_budget() {
    let w = world(after(Duration::from_millis(1500), Decision::Approve)).await;
    let mut pipe = ipc_pipe(w.ctx.clone(), 1 << 20).await;
    let mut ipc = Ipc::handshake(&mut pipe).await;
    ipc.send(&mut pipe, "UnlockBiometrics", json!({"user_id": USER})).await;
    for _ in 0..200 {
        ipc.send(&mut pipe, "DiscoverRequest", Value::Null).await;
    }
    let start = Instant::now();
    let sid = ipc.send(&mut pipe, "GetBiometricsStatus", json!({"user_id": USER})).await;
    loop {
        let (id, r) = ipc.read(&mut pipe).await;
        if id == sid {
            assert_eq!(r, json!({"Ok": "Available"}));
            break;
        }
    }
    assert!(start.elapsed() < Duration::from_millis(500), "took {:?}", start.elapsed());
}
