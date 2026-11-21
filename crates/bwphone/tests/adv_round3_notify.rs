//! Round 3: the redesigned `DBusNotifier::post` (notify.rs:202-277).
//!
//! `post` subscribes to ActionInvoked and NotificationClosed (match rules for
//! *every* notification of the server, not just ours) and then hands an
//! unbounded `Notify` to a task that only starts reading those streams once
//! `Notify` has returned. zbus 5 gives each match rule one shared broadcast
//! queue of 64 messages and, when it is full, stops reading the socket until
//! a receiver makes room (zbus `connection/mod.rs:122-126`, `add_match`).
//! So if the server emits 64+ such signals (other apps' notifications
//! closing, e.g. a backlog flushed by a server that froze and thawed)
//! between our AddMatch and its answer to our Notify, the reader blocks
//! with the Notify reply behind it, the task waits for that reply forever,
//! and nothing ever drains the queue: the notifier's connection is wedged
//! for the daemon's life. Each later prompt is still *shown* (the call goes
//! out) but its id is never read, so it is never closed and its Use password
//! does nothing.
//!
//! Before round 3 the whole `post` was bounded to 2 s, so the receivers were
//! dropped at the timeout and the reader recovered; `Notify` is now
//! deliberately unbounded, so it does not.
//!
//! The real `DBusNotifier` against a fake notification server on a private
//! `dbus-daemon` (never the session bus).
//!
//! Also: start-up is not bounded (`a_frozen_panel_at_start_up_...`).
//!
//! `cargo test -p bwphone --test adv_round3_notify`

// One private bus per test, serialised on a std mutex held across awaits.
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
    config::Indicator,
    notify::{DBusNotifier, Notifier},
};
use zbus::{interface, object_server::SignalEmitter, zvariant::OwnedValue};

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

fn private_bus(tag: &str) -> Bus {
    let dir = std::env::temp_dir().join(format!("bwphone-adv3-bus-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
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
    .unwrap();
    // No skip: dbus-daemon is required, so this test can never pass vacuously.
    let child = Command::new("dbus-daemon")
        .arg(format!("--config-file={}", config.display()))
        .arg("--nofork")
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("dbus-daemon must be installed for this test");
    let start = Instant::now();
    while !socket.exists() {
        assert!(start.elapsed() < Duration::from_secs(5), "dbus-daemon did not start");
        std::thread::sleep(Duration::from_millis(20));
    }
    Bus { child, dir, address: format!("unix:path={}", socket.display()) }
}

struct Server {
    next: AtomicU32,
    /// Before answering the next Notify, emit this many NotificationClosed
    /// signals for other applications' notifications (then reset to 0).
    flood_next: Arc<AtomicU32>,
    posted: Arc<Mutex<Vec<u32>>>,
    closed: Arc<Mutex<Vec<u32>>>,
}

#[interface(name = "org.freedesktop.Notifications")]
impl Server {
    #[allow(clippy::too_many_arguments)]
    async fn notify(
        &self,
        #[zbus(signal_emitter)] emitter: SignalEmitter<'_>,
        _app_name: String,
        _replaces_id: u32,
        _app_icon: String,
        _summary: String,
        _body: String,
        _actions: Vec<String>,
        _hints: HashMap<String, OwnedValue>,
        _expire_timeout: i32,
    ) -> u32 {
        let flood = self.flood_next.swap(0, Ordering::SeqCst);
        for i in 0..flood {
            // Another app's notification expiring (reason 1).
            Self::notification_closed(&emitter, 100_000 + i, 1).await.unwrap();
        }
        let id = self.next.fetch_add(1, Ordering::SeqCst) + 1;
        self.posted.lock().unwrap().push(id);
        id
    }

    async fn close_notification(&self, id: u32) {
        self.closed.lock().unwrap().push(id);
    }

    fn get_capabilities(&self) -> Vec<String> {
        vec!["actions".into(), "body".into()]
    }

    #[zbus(signal)]
    async fn notification_closed(emitter: &SignalEmitter<'_>, id: u32, reason: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    async fn action_invoked(emitter: &SignalEmitter<'_>, id: u32, action_key: &str) -> zbus::Result<()>;
}

struct World {
    notifier: Notifier,
    server: zbus::Connection,
    flood_next: Arc<AtomicU32>,
    posted: Arc<Mutex<Vec<u32>>>,
    closed: Arc<Mutex<Vec<u32>>>,
}

async fn world(bus: &Bus) -> World {
    let flood_next = Arc::new(AtomicU32::new(0));
    let posted = Arc::new(Mutex::new(Vec::new()));
    let closed = Arc::new(Mutex::new(Vec::new()));
    let server = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.freedesktop.Notifications")
        .unwrap()
        .serve_at(
            "/org/freedesktop/Notifications",
            Server { next: AtomicU32::new(0), flood_next: flood_next.clone(), posted: posted.clone(), closed: closed.clone() },
        )
        .unwrap()
        .build()
        .await
        .unwrap();
    // SAFETY: tests in this file hold SERIAL; nothing else reads the environment meanwhile.
    unsafe { std::env::set_var("DBUS_SESSION_BUS_ADDRESS", &bus.address) };
    let notifier = Notifier::DBus(
        DBusNotifier::connect(&Indicator { notification: true, tray: false, ..Default::default() }).await.unwrap(),
    );
    World { notifier, server, flood_next, posted, closed }
}

async fn wait_until(limit: Duration, mut f: impl FnMut() -> bool) -> bool {
    let start = Instant::now();
    while start.elapsed() < limit {
        if f() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    f()
}

/// What happened to the two prompts.
#[derive(Debug, PartialEq)]
struct Seen {
    first_closed: bool,
    second_posted: bool,
    second_pressed: bool,
    second_closed: bool,
}

const ALL_FINE: Seen = Seen { first_closed: true, second_posted: true, second_pressed: true, second_closed: true };

/// One prompt, posted while the server flushes `flood` other notifications'
/// NotificationClosed first; then a second, ordinary prompt on which the
/// person presses Use password.
async fn run(flood: u32, tag: &str) -> Seen {
    let bus = private_bus(tag);
    let w = world(&bus).await;

    w.flood_next.store(flood, Ordering::SeqCst);
    let first = w.notifier.unlock_prompt("Work", "🍩").await;
    assert!(wait_until(Duration::from_secs(3), || w.posted.lock().unwrap().len() == 1).await, "first Notify never reached the server");
    let id1 = w.posted.lock().unwrap()[0];
    tokio::time::sleep(Duration::from_millis(300)).await;
    first.close().await;
    let first_closed = wait_until(Duration::from_secs(4), || w.closed.lock().unwrap().contains(&id1)).await;

    // An ordinary unlock afterwards: no flood this time.
    let mut second = w.notifier.unlock_prompt("Work", "🤠").await;
    let second_posted = wait_until(Duration::from_secs(3), || w.posted.lock().unwrap().len() == 2).await;
    let (mut second_pressed, mut second_closed) = (false, false);
    if second_posted {
        let id2 = w.posted.lock().unwrap()[1];
        tokio::time::sleep(Duration::from_millis(300)).await;
        w.server
            .emit_signal(None::<()>, "/org/freedesktop/Notifications", "org.freedesktop.Notifications", "ActionInvoked", &(id2, "password"))
            .await
            .unwrap();
        second_pressed = tokio::time::timeout(Duration::from_secs(3), second.use_password()).await.is_ok();
        second.close().await;
        second_closed = wait_until(Duration::from_secs(4), || w.closed.lock().unwrap().contains(&id2)).await;
    } else {
        second.close().await;
    }
    Seen { first_closed, second_posted, second_pressed, second_closed }
}

/// Control: a handful of other notifications closing while ours is posted
/// is fine (the queue absorbs them). This also shows the harness works.
#[tokio::test]
async fn a_few_signals_before_notify_answers_are_harmless() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    assert_eq!(run(10, "few").await, ALL_FINE);
}

/// 70 NotificationClosed for other notifications between our AddMatch and
/// the Notify reply (more than zbus's 64-message queue) wedge the notifier
/// connection for good: the first prompt is never closed, and no later
/// prompt is even posted (its subscription now waits on the wedged reader,
/// so `post` times out and the unlock gets `Prompt::none()`: no emoji
/// notification, no Use password, for the daemon's whole life).
#[tokio::test]
async fn a_burst_of_other_notifications_closing_does_not_wedge_the_notifier() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let seen = run(70, "flood").await;
    assert_eq!(seen, ALL_FINE, "the notifier's connection is wedged");
}

/// A panel (`org.kde.StatusNotifierWatcher`, i.e. plasmashell) that owns its
/// name but never answers: frozen, or still starting up at login.
struct FrozenWatcher;

#[interface(name = "org.kde.StatusNotifierWatcher")]
impl FrozenWatcher {
    async fn register_status_notifier_item(&self, _service: String) {
        std::future::pending::<()>().await;
    }
}

/// SPECIFICATION.md §7: "Every other notification and tray call is bounded
/// to 2 s". Not at start-up: `DBusNotifier::connect` (main.rs:359, before
/// any socket is bound) awaits `Tray::connect`, which awaits `register`
/// (tray.rs:221, 274-276), an unbounded RegisterStatusNotifierItem call to
/// the panel. With the panel frozen, the daemon never gets as far as
/// listening: no unlock, status or hello is served until the panel recovers.
#[tokio::test]
async fn a_frozen_panel_at_start_up_does_not_stop_the_daemon_starting() {
    let _serial = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let bus = private_bus("watcher");
    let _watcher = zbus::connection::Builder::address(bus.address.as_str())
        .unwrap()
        .name("org.kde.StatusNotifierWatcher")
        .unwrap()
        .serve_at("/StatusNotifierWatcher", FrozenWatcher)
        .unwrap()
        .build()
        .await
        .unwrap();
    // SAFETY: tests in this file hold SERIAL; nothing else reads the environment meanwhile.
    unsafe { std::env::set_var("DBUS_SESSION_BUS_ADDRESS", &bus.address) };
    let indicator = Indicator { notification: true, tray: true, ..Default::default() };
    let connected = tokio::time::timeout(Duration::from_secs(10), DBusNotifier::connect(&indicator)).await;
    assert!(connected.is_ok(), "DBusNotifier::connect still waiting on the panel after 10 s: the daemon never starts listening");
}
