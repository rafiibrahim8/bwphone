//! The daemon's real D-Bus notifier (`DBusNotifier`) against a fake
//! notification server on a private `dbus-daemon` (never the session bus:
//! a minimal config with no service directories, so nothing is activated,
//! and the tray is off). The unlock runs end to end against the fake phone.
//!
//! `cargo test -p bwphone --test adv_whole_notify`
//! Skips (passes vacuously, with a note) when `dbus-daemon` is not installed.

// The tests share one private bus and serialise on a std mutex held for
// the whole test, awaits included: that is the point of it.
#![allow(clippy::await_holding_lock)]

use std::{
    collections::HashMap,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use bwphone::{
    Ctx,
    accounts::{Account, Accounts},
    config::Indicator,
    control::{self, ControlRequest},
    notify::{DBusNotifier, Notifier},
    pairing::Pairing,
    phone::Phone,
    secrets::Secrets,
    unlock::{self, PhoneState, Queue},
};
use bwphone_fakephone::{Decision, FakePhone, Person, after, fixed_rsa_key};
use bwphone_transport::noise::StaticKeypair;
use bwphone_wrap::{UserKey, phone::Pin, rsa::RsaPublicKey, wrap};
use zbus::{interface, zvariant::OwnedValue};

const ACCOUNT: [u8; 16] = [1; 16];

/// One test at a time: `DBusNotifier::connect` takes the bus from the environment.
static SERIAL: Mutex<()> = Mutex::new(());

struct Bus {
    child: Child,
    dir: std::path::PathBuf,
    address: String,
}

impl Drop for Bus {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

fn private_bus(tag: &str) -> Option<Bus> {
    let dir = std::env::temp_dir().join(format!("bwphone-adv-bus-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).ok()?;
    let socket = dir.join("bus");
    let config = dir.join("bus.conf");
    std::fs::write(
        &config,
        format!(
            r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:path={}</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>"#,
            socket.display()
        ),
    )
    .ok()?;
    let child = Command::new("dbus-daemon")
        .arg(format!("--config-file={}", config.display()))
        .arg("--nofork")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    let start = Instant::now();
    while !socket.exists() {
        if start.elapsed() > Duration::from_secs(5) {
            return None;
        }
        std::thread::sleep(Duration::from_millis(20));
    }
    Some(Bus { child, dir, address: format!("unix:path={}", socket.display()) })
}

/// A notification server: answers Notify with an id, or never answers it.
struct Server {
    next: AtomicU32,
    hang: bool,
    posted: Arc<AtomicU32>,
    closed_by_us: Arc<AtomicBool>,
}

#[interface(name = "org.freedesktop.Notifications")]
impl Server {
    #[allow(clippy::too_many_arguments)]
    async fn notify(
        &self,
        _app_name: String,
        _replaces_id: u32,
        _app_icon: String,
        _summary: String,
        _body: String,
        _actions: Vec<String>,
        _hints: HashMap<String, OwnedValue>,
        _expire_timeout: i32,
    ) -> u32 {
        if self.hang {
            // A notification server that is wedged (plasmashell frozen) but
            // still owns its name: the call is never answered.
            std::future::pending::<()>().await;
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        self.posted.store(id, Ordering::SeqCst);
        id
    }

    fn close_notification(&self, _id: u32) {
        self.closed_by_us.store(true, Ordering::SeqCst);
    }

    fn get_capabilities(&self) -> Vec<String> {
        vec!["actions".into(), "body".into()]
    }
}

struct World {
    ctx: Arc<Ctx>,
    server: zbus::Connection,
    posted: Arc<AtomicU32>,
    closed_by_us: Arc<AtomicBool>,
}

async fn world(bus: &Bus, person: Person, hang: bool) -> World {
    let posted = Arc::new(AtomicU32::new(0));
    let closed_by_us = Arc::new(AtomicBool::new(false));
    let server = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.Notifications")
        .unwrap()
        .serve_at(
            "/org/freedesktop/Notifications",
            Server { next: AtomicU32::new(0), hang, posted: posted.clone(), closed_by_us: closed_by_us.clone() },
        )
        .unwrap()
        .build()
        .await
        .unwrap();

    // SAFETY: tests in this file hold SERIAL; nothing else reads the environment meanwhile.
    unsafe { std::env::set_var("DBUS_SESSION_BUS_ADDRESS", &bus.address) };
    let notifier = DBusNotifier::connect(&Indicator { notification: true, tray: false, ..Default::default() }).await.unwrap();

    let pc = StaticKeypair::generate().unwrap();
    let pairing_id = [7u8; 16];
    let phone = Arc::new(FakePhone::new(pc.public, pairing_id, person));
    let (phone_addr, task) = phone.clone().listen("127.0.0.1:0").await.unwrap();
    let private = fixed_rsa_key(0);
    let public = RsaPublicKey::from(&private);
    let user_key = UserKey::from_slice(&[9u8; 64]).unwrap();
    let blob = wrap(&public, &user_key).unwrap();
    phone.add_account(ACCOUNT, "Work", private, Some(Pin::of(blob.rsa_ct())));
    let mut accounts = Accounts::default();
    accounts.push(Account { id: ACCOUNT, user_id: "user-1".into(), label: "Work".into(), blob }).unwrap();
    let ctx = Arc::new(Ctx {
        accounts,
        phone: Phone { public: phone.public(), pairing_id, host: "test-PC".into() },
        state: Mutex::new(PhoneState { addr: Some(phone_addr), ..Default::default() }),
        secrets: Secrets::fixed(*pc.private),
        notifier: Notifier::DBus(notifier),
        queue: Queue::default(),
        pairing: Mutex::new(Some(Pairing::new(&phone.public(), &pairing_id, "fake", phone_addr.port(), "today"))),
        pairing_path: None,
    });
    tokio::spawn(unlock::worker(ctx.clone()));
    std::mem::forget(task);
    World { ctx, server, posted, closed_by_us }
}

/// notify.rs `DBusNotifier::post`: the listener task `break`s, dropping
/// the oneshot sender, on NotificationClosed for our id and on *any*
/// ActionInvoked for our id; `Prompt::use_password` then resolves on the
/// sender being dropped (`let _ = rx.await`). So the person dismissing the
/// notification (or clicking its body, which GNOME/Plasma report as the
/// "default" action and then close it) ends the unlock exactly as Use
/// password does, although the spec makes only the Use password action do
/// that. Here the person dismisses the notification and then approves on
/// the phone 1.5 s later; the key never arrives.
#[tokio::test]
async fn dismissing_the_notification_is_not_use_password() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(bus) = private_bus("dismiss") else {
        eprintln!("dbus-daemon not available; skipped");
        return;
    };
    let w = world(&bus, after(Duration::from_millis(1500), Decision::Approve), false).await;

    let ctx = w.ctx.clone();
    let unlock = tokio::spawn(async move { control::handle(&ctx, ControlRequest::Unlock { label: "Work".into() }).await });
    let start = Instant::now();
    while w.posted.load(Ordering::SeqCst) == 0 {
        assert!(start.elapsed() < Duration::from_secs(10), "the notification was never posted");
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    let id = w.posted.load(Ordering::SeqCst);
    // The person swipes the notification away (reason 2: dismissed by the user).
    w.server
        .emit_signal(None::<()>, "/org/freedesktop/Notifications", "org.freedesktop.Notifications", "NotificationClosed", &(id, 2u32))
        .await
        .unwrap();

    let result = tokio::time::timeout(Duration::from_secs(20), unlock).await.expect("unlock hung").unwrap();
    assert_eq!(
        result["ok"], true,
        "dismissing the notification cancelled the unlock as if Use password were pressed: {result}"
    );
}

/// notify.rs / unlock.rs: the worker awaits `notifier.unlock_prompt` (a
/// D-Bus `Notify` call) with no timeout, after the prompt is already on the
/// phone and before it starts watching the phone, the Use password action
/// or the asker. zbus has no default method timeout, and dbus-broker (this
/// machine's session bus) has no reply timeout. A notification server that
/// is wedged but still owns its name (a frozen plasmashell) therefore
/// stalls the one unlock worker: the person approves on the phone, the key
/// is never read, and every later request, for any account, queues behind
/// it until the server recovers or the daemon restarts. The same applies to
/// `notifier.warn` (busy, rate_limited, None of these, tampered blob) and
/// to `prompt.close`.
#[tokio::test]
async fn a_wedged_notification_server_does_not_stall_unlocks() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(bus) = private_bus("hang") else {
        eprintln!("dbus-daemon not available; skipped");
        return;
    };
    let w = world(&bus, after(Duration::from_millis(300), Decision::Approve), true).await;

    let ctx = w.ctx.clone();
    let unlock = tokio::spawn(async move { control::handle(&ctx, ControlRequest::Unlock { label: "Work".into() }).await });
    // The phone approves 0.3 s after its prompt; allow generously for the rest.
    let result = tokio::time::timeout(Duration::from_secs(15), unlock).await;
    let _ = w.closed_by_us.load(Ordering::SeqCst);
    assert!(
        result.is_ok(),
        "the person approved on the phone, but the unlock is still waiting on a Notify call 15 s later (queued: {})",
        w.ctx.queue.len()
    );
}
