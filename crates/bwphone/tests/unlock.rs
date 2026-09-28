//! The whole PC path against the fake phone: a simulated browser
//! extension speaks native messaging to `serve_proxy`, the daemon speaks
//! Noise to the phone, and the user key comes back — or does not, fast.

use std::{
    collections::VecDeque,
    net::SocketAddr,
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
use tokio::{io::DuplexStream, net::TcpListener};

const ACCOUNT: [u8; 16] = [1; 16];
const USER: &str = "user-1";

struct World {
    ctx: Arc<Ctx>,
    phone: Arc<FakePhone>,
    notifier: Arc<FakeNotifier>,
    user_key: UserKey,
    phone_addr: SocketAddr,
    pc_private: [u8; 32],
}

async fn world(person: Person) -> World {
    let pc = StaticKeypair::generate().unwrap();
    let pairing_id = [7u8; 16];
    let phone = Arc::new(FakePhone::new(pc.public, pairing_id, person));
    let (phone_addr, _task) = phone.clone().listen("127.0.0.1:0").await.unwrap();

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
    std::mem::forget(_task);
    World { ctx, phone, notifier, user_key, phone_addr, pc_private }
}

/// A person who answers prompts from a script, in order.
fn scripted(decisions: Vec<Decision>) -> Person {
    let script = Arc::new(Mutex::new(VecDeque::from(decisions)));
    Arc::new(move |_| {
        let d = script.lock().unwrap().pop_front().unwrap_or(Decision::Ignore);
        Box::pin(async move { d })
    })
}

/// Enough of the extension to drive the daemon: one native-messaging pipe.
struct Browser {
    pipe: DuplexStream,
    app_id: String,
    private: RsaPrivateKey,
    key: Option<SessionKey>,
    next_id: i64,
}

impl Browser {
    async fn connect(ctx: Arc<Ctx>, app_id: &str) -> Self {
        let (mine, theirs) = tokio::io::duplex(1 << 16);
        tokio::spawn(serve_proxy(theirs, ctx));
        let mut b = Self { pipe: mine, app_id: app_id.into(), private: fixed_rsa_key(1), key: None, next_id: 0 };
        let hello = read_frame(&mut b.pipe).await.unwrap().unwrap();
        assert_eq!(hello, br#"{"command":"connected"}"#);
        b.setup().await;
        b
    }

    async fn setup(&mut self) {
        let spki = b64(RsaPublicKey::from(&self.private).to_public_key_der().unwrap().as_bytes());
        let id = self.next_id;
        self.next_id += 1;
        let frame = json!({"appId": self.app_id, "message": {
            "command": "setupEncryption", "publicKey": spki, "userId": USER, "messageId": id, "timestamp": now_ms()
        }});
        write_frame(&mut self.pipe, &serde_json::to_vec(&frame).unwrap()).await.unwrap();
        let reply: Value = serde_json::from_slice(&read_frame(&mut self.pipe).await.unwrap().unwrap()).unwrap();
        assert_eq!(reply["messageId"], -1);
        let ct = unb64(reply["sharedSecret"].as_str().unwrap()).unwrap();
        let raw = self.private.decrypt(Oaep::new::<sha1::Sha1>(), &ct).unwrap();
        self.key = Some(SessionKey::from_slice(&raw).unwrap());
    }

    async fn send(&mut self, command: &str, user_id: &str) -> i64 {
        let id = self.next_id;
        self.next_id += 1;
        let inner = json!({"command": command, "messageId": id, "userId": user_id, "timestamp": now_ms()});
        let enc = EncString::seal(self.key.as_ref().unwrap(), &serde_json::to_vec(&inner).unwrap());
        let frame = json!({"appId": self.app_id, "message": enc});
        write_frame(&mut self.pipe, &serde_json::to_vec(&frame).unwrap()).await.unwrap();
        id
    }

    /// The next decrypted inner reply, whichever request it answers.
    async fn read_reply(&mut self) -> Value {
        let outer: Value = serde_json::from_slice(&read_frame(&mut self.pipe).await.unwrap().unwrap()).unwrap();
        assert_eq!(outer["appId"], self.app_id);
        let enc: EncString = serde_json::from_value(outer["message"].clone()).unwrap();
        let plain = enc.open(self.key.as_ref().unwrap()).unwrap();
        let reply: Value = serde_json::from_slice(&plain).unwrap();
        assert_eq!(reply["messageId"], outer["messageId"]);
        assert!((reply["timestamp"].as_i64().unwrap() - now_ms()).abs() < 2_000, "stamped at send");
        reply
    }

    async fn call(&mut self, command: &str, user_id: &str) -> Value {
        let id = self.send(command, user_id).await;
        let reply = self.read_reply().await;
        assert_eq!(reply["messageId"], id);
        assert_eq!(reply["command"], command);
        reply
    }
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

#[tokio::test]
async fn unlock_end_to_end() {
    let w = world(always(Decision::Approve)).await;
    let mut browser = Browser::connect(w.ctx.clone(), "app-1").await;

    assert_eq!(browser.call("getBiometricsStatus", USER).await["response"], 0);
    assert_eq!(browser.call("getBiometricsStatusForUser", USER).await["response"], 0);

    let reply = browser.call("unlockWithBiometricsForUser", USER).await;
    assert_eq!(reply["response"], true);
    assert_eq!(reply["userKeyB64"], b64(w.user_key.as_bytes()));

    let events = w.phone.events();
    let Event::Prompted(prompt) = &events[0] else { panic!("{events:?}") };
    assert_eq!(prompt.label, "Work");
    assert_eq!(prompt.host, "test-PC");
    assert!(prompt.choices.contains(&prompt.emoji));
    assert!(matches!(events[1], Event::Answered { status: bwphone_transport::msg::Status::Ok, .. }));

    // The PC showed the same emoji the phone derived, and closed it after.
    assert_eq!(w.notifier.shown(), vec![("Work".to_string(), prompt.emoji.to_string(), false)]);
    assert!(w.notifier.warnings().is_empty());
}

#[tokio::test]
async fn denied_wrong_emoji_and_none_of_these_are_false() {
    let w = world(scripted(vec![Decision::Deny, Decision::WrongEmoji, Decision::NoneOfThese])).await;
    let mut browser = Browser::connect(w.ctx.clone(), "app-1").await;
    for _ in 0..3 {
        let reply = browser.call("unlockWithBiometricsForUser", USER).await;
        assert_eq!(reply["response"], false);
        assert!(reply.get("userKeyB64").is_none());
    }
    let warnings = w.notifier.warnings();
    assert_eq!(warnings.len(), 1, "only None of these raises the alarm: {warnings:?}");
    assert!(warnings[0].0.contains("Someone else asked your phone"));
    assert!(w.notifier.shown().iter().all(|(_, _, open)| !open));
}

#[tokio::test]
async fn unenrolled_user_is_refused_at_once() {
    let w = world(always(Decision::Approve)).await;
    let mut browser = Browser::connect(w.ctx.clone(), "app-1").await;
    assert_eq!(browser.call("getBiometricsStatusForUser", "user-2").await["response"], 8);
    let start = Instant::now();
    assert_eq!(browser.call("unlockWithBiometricsForUser", "user-2").await["response"], false);
    assert!(start.elapsed() < Duration::from_millis(500));
    assert!(w.phone.events().is_empty(), "the phone must not be asked");
    assert!(w.notifier.shown().is_empty());
}

#[tokio::test]
async fn unpinned_ciphertext_is_refused_without_a_prompt() {
    let w = world(always(Decision::Approve)).await;
    w.phone.set_pin(&ACCOUNT, Some(Pin::of(&[0u8; 256])));
    let mut browser = Browser::connect(w.ctx.clone(), "app-1").await;
    let start = Instant::now();
    assert_eq!(browser.call("unlockWithBiometricsForUser", USER).await["response"], false);
    assert!(start.elapsed() < Duration::from_secs(2));
    assert_eq!(
        w.phone.events(),
        vec![Event::Refused { account: Some(ACCOUNT), status: bwphone_transport::msg::Status::PinMismatch }]
    );
    assert!(w.notifier.shown().is_empty(), "no prompt, no notification");
}

#[tokio::test]
async fn phone_down_fails_fast_and_status_recovers_by_one_ping() {
    let w = world(always(Decision::Approve)).await;
    let dead = TcpListener::bind("127.0.0.1:0").await.unwrap().local_addr().unwrap();
    w.ctx.state.lock().unwrap().addr = Some(dead);

    let mut browser = Browser::connect(w.ctx.clone(), "app-1").await;
    let start = Instant::now();
    assert_eq!(browser.call("unlockWithBiometricsForUser", USER).await["response"], false);
    assert!(start.elapsed() < Duration::from_secs(5), "must fail inside the reach budget");
    assert_eq!(browser.call("getBiometricsStatusForUser", USER).await["response"], 2, "believed down");

    // The phone comes back; the next status query after the retry interval pings once.
    {
        let mut state = w.ctx.state.lock().unwrap();
        state.addr = Some(w.phone_addr);
        state.last_attempt = Some(Instant::now() - unlock::RETRY_AFTER);
    }
    assert_eq!(browser.call("getBiometricsStatusForUser", USER).await["response"], 0);
    assert_eq!(w.phone.events(), vec![Event::Pong]);
}

#[tokio::test]
async fn use_password_returns_false_at_once() {
    let w = world(always(Decision::Ignore)).await;
    let mut browser = Browser::connect(w.ctx.clone(), "app-1").await;
    let unlock = tokio::spawn(async move { browser.call("unlockWithBiometricsForUser", USER).await });
    let notifier = w.notifier.clone();
    wait_for("the prompt", || notifier.shown().len() == 1).await;
    let pressed = Instant::now();
    w.notifier.press_use_password(0);
    let reply = unlock.await.unwrap();
    assert_eq!(reply["response"], false);
    assert!(pressed.elapsed() < Duration::from_secs(1));
    assert!(!w.notifier.shown()[0].2, "notification closed");
}

/// The extension keeps polling status while the lock screen waits on the
/// phone; those must be answered right away on the same pipe, not after
/// the unlock (by which time they would be stale and dropped).
#[tokio::test]
async fn status_is_answered_while_an_unlock_waits_on_the_same_pipe() {
    let w = world(after(Duration::from_millis(800), Decision::Approve)).await;
    let mut browser = Browser::connect(w.ctx.clone(), "app-1").await;
    let unlock_id = browser.send("unlockWithBiometricsForUser", USER).await;
    let status_id = browser.send("getBiometricsStatusForUser", USER).await;
    let start = Instant::now();
    let first = browser.read_reply().await;
    assert_eq!(first["messageId"], status_id, "status must not queue behind the unlock");
    assert_eq!(first["response"], 0);
    assert!(start.elapsed() < Duration::from_millis(500));
    let second = browser.read_reply().await;
    assert_eq!(second["messageId"], unlock_id);
    assert_eq!(second["response"], true);
}

#[tokio::test]
async fn two_browsers_on_one_account_share_one_prompt() {
    let w = world(after(Duration::from_millis(300), Decision::Approve)).await;
    let mut a = Browser::connect(w.ctx.clone(), "app-a").await;
    let mut b = Browser::connect(w.ctx.clone(), "app-b").await;
    let (ra, rb) = tokio::join!(a.call("unlockWithBiometricsForUser", USER), b.call("unlockWithBiometricsForUser", USER));
    assert_eq!(ra["response"], true);
    assert_eq!(rb["response"], true);
    assert_eq!(ra["userKeyB64"], rb["userKeyB64"]);
    let prompts = w.phone.events().iter().filter(|e| matches!(e, Event::Prompted(_))).count();
    assert_eq!(prompts, 1, "one prompt, one fingerprint, two browsers");
    assert_eq!(w.notifier.shown().len(), 1);
}

#[tokio::test]
async fn a_busy_phone_is_an_alarm() {
    // The first prompt is someone else's, and they never answer it.
    let w = world(scripted(vec![Decision::Ignore])).await;
    let rsa_ct = w.ctx.accounts.by_id(&ACCOUNT).unwrap().blob.rsa_ct().to_vec();
    let intruder = w.ctx.phone.reach(&w.pc_private, w.phone_addr, &ACCOUNT, &rsa_ct, 30_000).await.unwrap();

    let mut browser = Browser::connect(w.ctx.clone(), "app-1").await;
    let start = Instant::now();
    assert_eq!(browser.call("unlockWithBiometricsForUser", USER).await["response"], false);
    assert!(start.elapsed() < Duration::from_secs(5));
    let warnings = w.notifier.warnings();
    assert_eq!(warnings.len(), 1);
    assert!(warnings[0].0.contains("Another unlock request is waiting"));
    assert!(w.notifier.shown().is_empty(), "our own prompt never got posted");
    assert!(matches!(w.phone.events()[1], Event::Refused { status: bwphone_transport::msg::Status::Busy, .. }));
    drop(intruder);
}

#[tokio::test]
async fn control_socket_hello_status_and_dry_run() {
    let w = world(always(Decision::Approve)).await;
    let ip = "10.9.8.7".parse().unwrap();
    // An ephemeral port, as the phone announces when its own is taken.
    let ok = control::handle(&w.ctx, ControlRequest::Hello { ip, port: 40123, seq: 5 }).await;
    assert_eq!(ok["ok"], true);
    assert_eq!(w.ctx.state.lock().unwrap().addr, Some(SocketAddr::new(ip, 40123)));
    let stale = control::handle(&w.ctx, ControlRequest::Hello { ip, port: 8731, seq: 5 }).await;
    assert_eq!(stale["ok"], false);
    {
        let pairing = w.ctx.pairing.lock().unwrap();
        let p = pairing.as_ref().unwrap();
        assert_eq!(p.last_hello_seq, 5);
        // What a restarted daemon or `bwphone enroll` will dial.
        assert_eq!(p.last_phone_addr(), Some(SocketAddr::new(ip, 40123)));
    }

    w.ctx.state.lock().unwrap().addr = Some(w.phone_addr);
    let status = control::handle(&w.ctx, ControlRequest::Status).await;
    assert_eq!(status["ok"], true);
    assert_eq!(status["wallet"], "unlocked");
    assert_eq!(status["accounts"][0]["label"], "Work");
    assert_eq!(status["accounts"][0]["available"], true);

    let unlocked = control::handle(&w.ctx, ControlRequest::Unlock { label: "Work".into() }).await;
    assert_eq!(unlocked["ok"], true);
    assert_eq!(unlocked["fingerprint"], w.user_key.fingerprint());
    assert!(unlocked.get("key").is_none());

    let missing = control::handle(&w.ctx, ControlRequest::Unlock { label: "Nope".into() }).await;
    assert_eq!(missing["ok"], false);
}

/// A request whose asker is already gone when its turn comes never reaches
/// the phone; the next real one still does.
#[tokio::test]
async fn an_unlock_nobody_waits_for_is_skipped() {
    // Denials, so a wrongly-run dead request cannot hand its answer on and hide.
    let w = world(always(Decision::Deny)).await;
    let (tx, rx) = tokio::sync::oneshot::channel();
    drop(rx);
    w.ctx.queue.push(unlock::Job { account_id: ACCOUNT, arrived: Instant::now(), reply: tx });

    let unlocked = control::handle(&w.ctx, ControlRequest::Unlock { label: "Work".into() }).await;
    assert_eq!(unlocked["reason"], "denied");
    let prompts = w.phone.events().iter().filter(|e| matches!(e, Event::Prompted(_))).count();
    assert_eq!(prompts, 1, "only the request someone waits for is shown: {:?}", w.phone.events());
}

/// The browser closes its pipe (its service worker idled out) while the
/// prompt is up: the prompt comes down at once instead of waiting out the
/// human phase for an answer nobody will read.
#[tokio::test]
async fn a_browser_that_leaves_takes_its_prompt_down() {
    let w = world(always(Decision::Ignore)).await;
    let mut browser = Browser::connect(w.ctx.clone(), "app-1").await;
    browser.send("unlockWithBiometricsForUser", USER).await;
    let notifier = w.notifier.clone();
    wait_for("the prompt", || notifier.shown().len() == 1).await;

    let left = Instant::now();
    drop(browser);
    wait_for("the prompt to close", || !notifier.shown()[0].2).await;
    assert!(left.elapsed() < Duration::from_secs(2));
    assert!(w.ctx.queue.is_empty());
}

/// Two browsers wait on one account and the first leaves: the prompt stays,
/// and the second still gets the key from that one fingerprint.
#[tokio::test]
async fn a_second_browser_keeps_the_prompt_when_the_first_leaves() {
    let w = world(after(Duration::from_millis(800), Decision::Approve)).await;
    let mut a = Browser::connect(w.ctx.clone(), "app-a").await;
    let mut b = Browser::connect(w.ctx.clone(), "app-b").await;
    a.send("unlockWithBiometricsForUser", USER).await;
    let notifier = w.notifier.clone();
    wait_for("the prompt", || notifier.shown().len() == 1).await;
    let id = b.send("unlockWithBiometricsForUser", USER).await;
    let ctx = w.ctx.clone();
    wait_for("the second request to queue", || ctx.queue.len() == 1).await;

    drop(a);
    let reply = b.read_reply().await;
    assert_eq!(reply["messageId"], id);
    assert_eq!(reply["response"], true);
    assert_eq!(reply["userKeyB64"], b64(w.user_key.as_bytes()));
    let prompts = w.phone.events().iter().filter(|e| matches!(e, Event::Prompted(_))).count();
    assert_eq!(prompts, 1);
}

/// The phone refuses `rate_limited` before any prompt, so nothing shows
/// there: the PC must say it, or the lockout is silent.
#[tokio::test]
async fn rate_limited_is_an_alarm() {
    let w = world(always(Decision::Approve)).await;
    w.phone.refuse_next_unwrap(bwphone_transport::msg::Status::RateLimited);
    let mut browser = Browser::connect(w.ctx.clone(), "app-1").await;
    let start = Instant::now();
    assert_eq!(browser.call("unlockWithBiometricsForUser", USER).await["response"], false);
    assert!(start.elapsed() < Duration::from_secs(2), "refused within the reach phase");
    let warnings = w.notifier.warnings();
    assert_eq!(warnings.len(), 1, "{warnings:?}");
    assert!(warnings[0].0.contains("too many unlock requests"));
    assert!(warnings[0].1.contains("someone else has been asking"));
    assert!(w.notifier.shown().is_empty(), "no prompt, so no emoji");

    // The next one goes through as usual.
    assert_eq!(browser.call("unlockWithBiometricsForUser", USER).await["response"], true);
}
