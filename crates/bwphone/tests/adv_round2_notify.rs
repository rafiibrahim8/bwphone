//! Round 2, fix 8 (`DBUS_TIMEOUT`): what the 2 s bound leaves behind.
//!
//! The real `DBusNotifier`, tray on, against a fake notification server on
//! a private `dbus-daemon` (never the session bus). The tray's state is read
//! back over D-Bus exactly as a panel would read it.
//!
//! `cargo test -p bwphone --test adv_round2_notify`
//! Skips (passes vacuously, with a note) when `dbus-daemon` is not installed.

// The tests share one private bus and serialise on a std mutex held for
// the whole test, awaits included: that is the point of it.
#![allow(clippy::await_holding_lock)]

use std::{
    collections::HashMap,
    process::{Child, Command, Stdio},
    sync::{
        Arc, Mutex,
        atomic::{AtomicU32, Ordering},
    },
    time::{Duration, Instant},
};

use bwphone::{
    Ctx,
    accounts::{Account, Accounts},
    config::{Indicator, TrayIdle},
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
    let dir = std::env::temp_dir().join(format!("bwphone-adv2-bus-{tag}-{}", std::process::id()));
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

#[derive(Clone, Copy, PartialEq)]
enum Mode {
    Normal,
    /// Notify is answered, but only after this long.
    SlowNotify(Duration),
    /// Notify is never answered (the server froze).
    HangNotify,
    /// Notify is answered; CloseNotification never is (the server froze later).
    HangClose,
}

struct Server {
    next: AtomicU32,
    mode: Mode,
    posted: Arc<AtomicU32>,
    closed: Arc<Mutex<Vec<u32>>>,
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
        match self.mode {
            Mode::HangNotify => std::future::pending::<()>().await,
            Mode::SlowNotify(d) => tokio::time::sleep(d).await,
            _ => {}
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        self.posted.store(id, Ordering::SeqCst);
        id
    }

    async fn close_notification(&self, id: u32) {
        if self.mode == Mode::HangClose {
            std::future::pending::<()>().await;
        }
        self.closed.lock().unwrap().push(id);
    }

    fn get_capabilities(&self) -> Vec<String> {
        vec!["actions".into(), "body".into()]
    }
}

struct World {
    ctx: Arc<Ctx>,
    _server: zbus::Connection,
    reader: zbus::Connection,
    posted: Arc<AtomicU32>,
    closed: Arc<Mutex<Vec<u32>>>,
}

async fn world(bus: &Bus, mode: Mode) -> World {
    world_with(bus, mode, after(Duration::from_millis(300), Decision::Approve)).await
}

async fn world_with(bus: &Bus, mode: Mode, person: Person) -> World {
    let posted = Arc::new(AtomicU32::new(0));
    let closed = Arc::new(Mutex::new(Vec::new()));
    let server = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.Notifications")
        .unwrap()
        .serve_at(
            "/org/freedesktop/Notifications",
            Server { next: AtomicU32::new(0), mode, posted: posted.clone(), closed: closed.clone() },
        )
        .unwrap()
        .build()
        .await
        .unwrap();
    let reader = zbus::connection::Builder::address(bus.address.as_str()).unwrap().build().await.unwrap();

    // SAFETY: tests in this file hold SERIAL; nothing else reads the environment meanwhile.
    unsafe { std::env::set_var("DBUS_SESSION_BUS_ADDRESS", &bus.address) };
    let notifier =
        DBusNotifier::connect(&Indicator { notification: true, tray: true, tray_idle: TrayIdle::Shown }).await.unwrap();

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
    World { ctx, _server: server, reader, posted, closed }
}

/// The tray's `Status` property, as the panel reads it.
async fn tray_status(conn: &zbus::Connection) -> String {
    let name = format!("org.kde.StatusNotifierItem-{}-1", std::process::id());
    let proxy = zbus::fdo::PropertiesProxy::builder(conn)
        .destination(name)
        .unwrap()
        .path("/StatusNotifierItem")
        .unwrap()
        .build()
        .await
        .unwrap();
    let v = proxy.get("org.kde.StatusNotifierItem".try_into().unwrap(), "Status").await.unwrap();
    String::try_from(v).unwrap()
}

async fn unlock_ok(w: &World) {
    let ctx = w.ctx.clone();
    let unlock = tokio::spawn(async move { control::handle(&ctx, ControlRequest::Unlock { label: "Work".into() }).await });
    let result = tokio::time::timeout(Duration::from_secs(20), unlock).await.expect("unlock hung").unwrap();
    assert_eq!(result["ok"], true, "{result}");
}

/// Sanity: a healthy server; the tray is back to idle when the unlock ends.
#[tokio::test]
async fn healthy_server_tray_returns_to_idle() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(bus) = private_bus("ok") else {
        eprintln!("dbus-daemon not available; skipped");
        return;
    };
    let w = world(&bus, Mode::Normal).await;
    assert_eq!(tray_status(&w.reader).await, "Active");
    unlock_ok(&w).await;
    assert_eq!(tray_status(&w.reader).await, "Active");
    assert_eq!(*w.closed.lock().unwrap(), vec![w.posted.load(Ordering::SeqCst)]);
}

/// notify.rs `Notifier::unlock_prompt` wraps the whole `DBusNotifier::prompt`
/// in `DBUS_TIMEOUT` and falls back to `Prompt::none()` (no closer).
/// `prompt` has already run `tray.show` (NeedsAttention, the emoji) before
/// it awaits `Notify`; the tray-clearing closer is only attached after
/// `post` returns. When Notify outlasts 2 s, the future is dropped between
/// the two, so nothing ever calls `tray.clear()`: the tray keeps asking for
/// attention with this request's emoji after the request has ended, until
/// the next unlock (which, with the server still frozen, leaves it stuck
/// again).
#[tokio::test]
async fn a_frozen_notify_leaves_the_tray_stuck_on_the_emoji() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(bus) = private_bus("hangnotify") else {
        eprintln!("dbus-daemon not available; skipped");
        return;
    };
    let w = world(&bus, Mode::HangNotify).await;
    unlock_ok(&w).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        tray_status(&w.reader).await,
        "Active",
        "the unlock ended, but the tray still shows its emoji and asks for attention"
    );
}

/// notify.rs `Prompt::close`: the combined closer runs `close_notification`
/// and then `tray.clear()`, all inside one `DBUS_TIMEOUT`. A server that
/// froze after posting (CloseNotification never answered) eats the 2 s and
/// the tray is never cleared.
#[tokio::test]
async fn a_frozen_close_leaves_the_tray_stuck_on_the_emoji() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(bus) = private_bus("hangclose") else {
        eprintln!("dbus-daemon not available; skipped");
        return;
    };
    let w = world(&bus, Mode::HangClose).await;
    unlock_ok(&w).await;
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert_eq!(
        tray_status(&w.reader).await,
        "Active",
        "the unlock ended, but the tray still shows its emoji and asks for attention"
    );
}

/// A merely slow server (Notify answered after 2.5 s, e.g. a loaded
/// plasmashell/gnome-shell): the daemon gave up at 2 s, but the server still
/// shows the notification (critical urgency, expire_timeout 0: it never
/// goes away by itself). Nobody holds its id, so it is never closed: a
/// stale "Unlock Work · <emoji>" stays on screen after the request ended,
/// and its Use password button does nothing.
#[tokio::test]
async fn a_late_notification_is_never_closed() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let Some(bus) = private_bus("slow") else {
        eprintln!("dbus-daemon not available; skipped");
        return;
    };
    let w = world(&bus, Mode::SlowNotify(Duration::from_millis(2500))).await;
    unlock_ok(&w).await;
    // Let the late Notify land (2.5 s after it was sent; the unlock itself no
    // longer waits for it) and anything that would close it run.
    tokio::time::sleep(Duration::from_secs(4)).await;
    let id = w.posted.load(Ordering::SeqCst);
    assert_ne!(id, 0, "the server did post the notification");
    assert!(
        w.closed.lock().unwrap().contains(&id),
        "notification {id} was posted late and is still on screen after the unlock ended"
    );
}

/// notify.rs `DBusNotifier::post`, listener task: since fix 8 the
/// `closed` branch means "not pressed" (it drops `tx`, and
/// `Prompt::use_password` now treats a dropped sender as nothing). But the
/// two signal streams are separate, and `tokio::select!` polls its ready
/// branches in random order. Notification servers close a notification
/// after one of its actions is invoked, so a press arrives as
/// ActionInvoked(id, "password") immediately followed by
/// NotificationClosed(id, 2); when both are queued by the time the task
/// runs, about half the time `closed` wins and the press is lost: the
/// request stays on the phone instead of ending at once. (Before fix 8 both
/// branches ended the request, so the order did not matter.)
#[tokio::test]
async fn use_password_followed_by_close_is_not_lost() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let mut lost = 0;
    let tries = 12;
    for i in 0..tries {
        // A fresh bus and phone each time: the fake phone stays busy with a cancelled prompt.
        let Some(bus) = private_bus(&format!("press{i}")) else {
            eprintln!("dbus-daemon not available; skipped");
            return;
        };
        let w = world_with(&bus, Mode::Normal, after(Duration::from_secs(4), Decision::Approve)).await;
        let before = w.posted.load(Ordering::SeqCst);
        let ctx = w.ctx.clone();
        let unlock = tokio::spawn(async move { control::handle(&ctx, ControlRequest::Unlock { label: "Work".into() }).await });
        let start = Instant::now();
        while w.posted.load(Ordering::SeqCst) == before {
            assert!(start.elapsed() < Duration::from_secs(10), "try {i}: the notification was never posted");
            tokio::time::sleep(Duration::from_millis(5)).await;
        }
        // Give the daemon a moment to subscribe and spawn its listener.
        tokio::time::sleep(Duration::from_millis(100)).await;
        let id = w.posted.load(Ordering::SeqCst);
        let path = "/org/freedesktop/Notifications";
        let iface = "org.freedesktop.Notifications";
        w._server.emit_signal(None::<()>, path, iface, "ActionInvoked", &(id, "password")).await.unwrap();
        w._server.emit_signal(None::<()>, path, iface, "NotificationClosed", &(id, 2u32)).await.unwrap();
        let pressed_at = Instant::now();
        let result = tokio::time::timeout(Duration::from_secs(20), unlock).await.expect("unlock hung").unwrap();
        if result["reason"] != "usepassword" || pressed_at.elapsed() > Duration::from_secs(2) {
            eprintln!("try {i}: Use password lost: {result} after {:?}", pressed_at.elapsed());
            lost += 1;
        }
    }
    assert_eq!(lost, 0, "{lost} of {tries} Use password presses were lost to the NotificationClosed that follows them");
}
