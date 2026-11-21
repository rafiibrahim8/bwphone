//! Whole-system adversarial checks: the seams between the unlock engine,
//! the hello path, the queue's sharing rule, the account store and the
//! daemon's local sockets. Each test states what the spec promises and
//! fails if the code does not deliver it.
//!
//! `cargo test -p bwphone --test adv_whole_daemon`

use std::{
    net::SocketAddr,
    panic::{AssertUnwindSafe, catch_unwind},
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bwphone::{
    Ctx,
    accounts::{Accounts, Account, id_hex, parse_id},
    control::{self, ControlRequest},
    hellosock::serve_hello_socket,
    notify::{FakeNotifier, Notifier},
    pairing::Pairing,
    phone::Phone,
    secrets::Secrets,
    serve::{availability, serve_proxy},
    unlock::{self, PhoneState, Queue},
};
use bwphone_fakephone::{Decision, FakePhone, Person, always, fixed_rsa_key};
use bwphone_nm::{
    b64,
    frame::{read_frame, write_frame},
    msg::BiometricsStatus,
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
use tokio::io::{AsyncWriteExt as _, DuplexStream};

const ACCOUNT: [u8; 16] = [1; 16];
const USER: &str = "user-1";

struct World {
    ctx: Arc<Ctx>,
    notifier: Arc<FakeNotifier>,
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
    let ctx = Arc::new(Ctx {
        accounts,
        phone: Phone { public: phone.public(), pairing_id, host: "test-PC".into() },
        state: Mutex::new(PhoneState { addr: Some(phone_addr), ..Default::default() }),
        secrets: Secrets::fixed(*pc.private),
        notifier: Notifier::Fake(notifier.clone()),
        queue: Queue::default(),
        pairing: Mutex::new(Some(Pairing::new(&phone.public(), &pairing_id, "fake", phone_addr.port(), "today"))),
        pairing_path: None,
    });
    tokio::spawn(unlock::worker(ctx.clone()));
    std::mem::forget(task);
    World { ctx, notifier, phone_addr }
}

async fn wait_for(what: &str, limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while !cond() {
        if start.elapsed() > limit {
            eprintln!("gave up waiting for {what} after {limit:?}");
            return false;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    true
}

/// A legacy native-messaging client on its own pipe.
struct Legacy {
    pipe: DuplexStream,
    key: SessionKey,
    next: i64,
}

impl Legacy {
    async fn connect(ctx: Arc<Ctx>, app_id: &str) -> Self {
        let (mut pipe, theirs) = tokio::io::duplex(1 << 16);
        tokio::spawn(serve_proxy(theirs, ctx));
        read_frame(&mut pipe).await.unwrap().unwrap();
        let private: RsaPrivateKey = fixed_rsa_key(1);
        let spki = b64(RsaPublicKey::from(&private).to_public_key_der().unwrap().as_bytes());
        let frame = json!({"appId": app_id, "message": {
            "command": "setupEncryption", "publicKey": spki, "userId": USER, "messageId": 0, "timestamp": bwphone_nm::peer::now_ms()
        }});
        write_frame(&mut pipe, &serde_json::to_vec(&frame).unwrap()).await.unwrap();
        let reply: Value = serde_json::from_slice(&read_frame(&mut pipe).await.unwrap().unwrap()).unwrap();
        let ct = unb64(reply["sharedSecret"].as_str().unwrap()).unwrap();
        let raw = private.decrypt(Oaep::new::<sha1::Sha1>(), &ct).unwrap();
        Self { pipe, key: SessionKey::from_slice(&raw).unwrap(), next: 1 }
    }

    async fn send(&mut self, app_id: &str, command: &str) {
        let inner = json!({"command": command, "messageId": self.next, "userId": USER, "timestamp": bwphone_nm::peer::now_ms()});
        self.next += 1;
        let enc = EncString::seal(&self.key, &serde_json::to_vec(&inner).unwrap());
        write_frame(&mut self.pipe, &serde_json::to_vec(&json!({"appId": app_id, "message": enc})).unwrap()).await.unwrap();
    }
}

/// unlock.rs `run`: a reach that fails is recorded with `note_reach(false)`
/// unconditionally. The recent change gave `PhoneState` a generation
/// counter precisely so that "a ping to an address the phone has left
/// cannot mark it down" (spec §3), but the unlock path itself was left out.
///
/// Realistic sequence: the phone is dozing, an unlock's reach hangs; the
/// person picks the phone up and unlocks its screen, which sends a fresh
/// hello (here: with its new address). The stale reach then times out and
/// marks the phone down, overriding the hello. For RETRY_AFTER (30 s) every
/// status query, legacy and SDK IPC alike, answers HardwareUnavailable,
/// although the phone is reachable at the address the daemon now holds.
#[tokio::test]
async fn a_stale_reach_failure_overrides_a_fresher_hello() {
    let w = world(always(Decision::Approve)).await;
    // The phone's old address: a TCP backlog that never answers, so the
    // reach runs out its 5 s budget.
    let silent = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    w.ctx.state.lock().unwrap().addr = Some(silent.local_addr().unwrap());

    let ctx = w.ctx.clone();
    let unlock = tokio::spawn(async move { control::handle(&ctx, ControlRequest::Unlock { label: "Work".into() }).await });

    // While that reach hangs, the phone announces where it really is.
    tokio::time::sleep(Duration::from_millis(1500)).await;
    let hello = control::handle(&w.ctx, ControlRequest::Hello { ip: w.phone_addr.ip(), port: w.phone_addr.port(), seq: 1 }).await;
    assert_eq!(hello["ok"], true);
    assert_eq!(w.ctx.state.lock().unwrap().addr, Some(w.phone_addr));

    let refused = unlock.await.unwrap();
    assert_eq!(refused["reason"], "unreachable", "{refused}");

    // The address the daemon now holds came from a hello newer than the
    // failed reach; nothing has failed there.
    let account = w.ctx.accounts.by_id(&ACCOUNT);
    let status = availability(&w.ctx, account).await;
    let state = w.ctx.state.lock().unwrap();
    assert_eq!(
        status,
        BiometricsStatus::Available,
        "a reach to the old address, started before the hello, marked the new address down \
         (last_reach_ok = {:?}); status stays unavailable for RETRY_AFTER",
        state.last_reach_ok
    );
    drop(silent);
}

/// Spec §3 Queueing: "if its prompt is up, the session is closed (which
/// takes the prompt down on the phone) unless another request for the
/// same account is queued behind it." unlock.rs `run` checks that only
/// once: after the first asker leaves with someone queued behind, the
/// `closed()` arm is disabled (`if !asker_gone`), so when that second
/// request also leaves, nobody notices. The prompt stays on the phone and
/// the PC for the whole human phase (up to 45 s), every other account's
/// unlock waits behind it, and a fingerprint given then releases the key
/// into nobody.
#[tokio::test]
async fn the_prompt_comes_down_when_every_asker_has_left() {
    let w = world(always(Decision::Ignore)).await;
    let mut a = Legacy::connect(w.ctx.clone(), "app-a").await;
    let mut b = Legacy::connect(w.ctx.clone(), "app-b").await;
    a.send("app-a", "unlockWithBiometricsForUser").await;
    let n = w.notifier.clone();
    assert!(wait_for("the prompt", Duration::from_secs(5), || n.shown().len() == 1).await);
    b.send("app-b", "unlockWithBiometricsForUser").await;
    let ctx = w.ctx.clone();
    assert!(wait_for("b to queue", Duration::from_secs(5), || ctx.queue.len() == 1).await);

    drop(a);
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(n.shown()[0].2, "b still waits, so the prompt stays (by design)");
    drop(b);

    let came_down = wait_for("the prompt to close after both left", Duration::from_secs(3), || !n.shown()[0].2).await;
    assert!(came_down, "both browsers are gone but the prompt is still up on the phone and the PC");
}

/// accounts.rs `parse_id`: `s.len() == 32` counts bytes, then slices at
/// byte offsets 2i..2i+2, which panics on a multi-byte character. Any
/// directory under `accounts/` whose name is 32 bytes of UTF-8 with a
/// 3-byte character makes `Accounts::load` panic, which with
/// `panic = "abort"` kills the daemon at every start (crash loop under
/// `Restart=on-failure`) and also `bwphone account list/remove`, the tools
/// that would fix it. The doc comment promises such a directory "is ignored".
#[test]
fn a_non_ascii_directory_name_does_not_panic_the_account_loader() {
    let name = format!("€{}", "a".repeat(29));
    assert_eq!(name.len(), 32);
    let parsed = catch_unwind(|| parse_id(&name));
    assert!(parsed.is_ok(), "parse_id panicked on a 32-byte non-ASCII name");

    let dir = std::env::temp_dir().join(format!("bwphone-adv-whole-ids-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join(&name)).unwrap();
    let loaded = catch_unwind(AssertUnwindSafe(|| Accounts::load(&dir).map(|a| a.is_empty())));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(matches!(loaded, Ok(Ok(true))), "Accounts::load panicked on a stray directory name");
}

/// The case-insensitive userId change reaches `Accounts::load` through
/// `check_free`: two account directories whose userIds differ only in case
/// (both loaded fine before the change) now fail the whole load. That stops
/// the daemon from starting, and `bwphone account remove` (main.rs, which
/// calls the same `Accounts::load` before deleting anything) cannot remove
/// either one, so the documented way out does not work.
#[test]
fn case_variant_user_ids_still_leave_account_remove_usable() {
    let dir = std::env::temp_dir().join(format!("bwphone-adv-whole-case-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let mut blob = vec![bwphone_wrap::VERSION];
    blob.resize(bwphone_wrap::BLOB_LEN, 0);
    for (id, user, label) in [([1u8; 16], "test-user", "One"), ([2u8; 16], "TEST-USER", "Two")] {
        let acc = dir.join(id_hex(&id));
        std::fs::create_dir_all(&acc).unwrap();
        std::fs::write(acc.join("account.json"), serde_json::to_vec(&json!({"user_id": user, "label": label})).unwrap()).unwrap();
        std::fs::write(acc.join("vault.blob"), &blob).unwrap();
    }
    let loaded = Accounts::load(&dir);
    let _ = std::fs::remove_dir_all(&dir);
    let err = loaded.err().map(|e| e.to_string());
    assert!(err.is_none(), "load failed ({err:?}): the daemon will not start and `account remove` cannot run either");
}

/// hellosock.rs `serve_hello_socket` (and control.rs `serve_control`) read
/// a line with an unbounded `read_line`. `bwphone-hello` is the component
/// the design treats as compromisable from the LAN ("Compromised, it can
/// misdirect the daemon to a wrong address ... and nothing more", unit file
/// and spec §2), and hello.sock is the one thing its sandbox reaches. It can
/// make the daemon, which holds the Noise key and every unlocked user key in
/// flight, buffer an arbitrarily long line until it is OOM-killed.
#[tokio::test]
async fn the_hello_socket_bounds_what_one_line_may_cost() {
    let w = world(always(Decision::Approve)).await;
    let (mut mine, theirs) = tokio::io::duplex(1 << 16);
    let server = tokio::spawn(serve_hello_socket(theirs, w.ctx.clone()));
    let chunk = vec![b'a'; 1 << 20];
    let mut sent = 0usize;
    let limit = 64 << 20;
    while sent < limit {
        match tokio::time::timeout(Duration::from_secs(5), mine.write_all(&chunk)).await {
            Ok(Ok(())) => sent += chunk.len(),
            _ => break,
        }
    }
    let still_reading = !server.is_finished();
    drop(mine);
    let _ = server.await;
    assert!(
        sent < limit,
        "the daemon buffered {} MiB of one hello.sock line without a newline (still reading: {still_reading})",
        sent >> 20
    );
}
