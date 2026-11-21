//! The desktop side of an unlock: one critical-urgency notification carrying
//! the session's emoji and a Use password action, and/or the tray icon
//! showing that emoji (as `config.toml` says), both taken down when the
//! request ends; and plain warnings, always as notifications.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::sync::oneshot;

use crate::{config::Indicator, tray::Tray};
use tokio_stream::StreamExt as _;
use zbus::zvariant::Value;

const URGENCY_CRITICAL: u8 = 2;

/// The most any notification or tray call may take. The unlock worker
/// awaits them while the phone is already asking, and neither zbus nor
/// dbus-broker times a method call out: a notification server that is
/// frozen but still owns its name would otherwise stall every unlock.
pub const DBUS_TIMEOUT: Duration = Duration::from_secs(2);

type Closer = Box<dyn FnOnce() -> Pin<Box<dyn Future<Output = ()> + Send>> + Send>;

/// An unlock notification on screen.
pub struct Prompt {
    use_password: Option<oneshot::Receiver<()>>,
    closer: Option<Closer>,
}

impl Prompt {
    /// Nothing on screen to press Use password on.
    fn none() -> Self {
        Self { use_password: None, closer: None }
    }

    /// Resolves when the person presses Use password; never, if there is no
    /// notification to press it on. Dismissing the notification, another
    /// action on it, or the server closing it is not a refusal: the request
    /// carries on, answered on the phone.
    pub async fn use_password(&mut self) {
        if let Some(rx) = &mut self.use_password {
            let pressed = rx.await.is_ok();
            // A completed receiver must not be polled again: callers re-arm this in a loop.
            self.use_password = None;
            if pressed {
                return;
            }
        }
        std::future::pending().await
    }

    /// Takes the notification and the tray emoji down. Each D-Bus call in a
    /// closer is bounded on its own, so the tray is cleared whatever the
    /// notification server does.
    pub async fn close(mut self) {
        if let Some(close) = self.closer.take() {
            close().await;
        }
    }
}

pub enum Notifier {
    DBus(DBusNotifier),
    Fake(Arc<FakeNotifier>),
    /// No session bus: unlocks still work, but nothing shows the emoji.
    Silent,
}

impl Notifier {
    pub async fn unlock_prompt(&self, label: &str, emoji: &str) -> Prompt {
        match self {
            // Bounded inside, call by call, so the tray's closer always survives.
            Self::DBus(d) => d.prompt(label, emoji).await,
            Self::Fake(f) => f.prompt(label, emoji),
            Self::Silent => Prompt { use_password: None, closer: None },
        }
    }

    pub async fn warn(&self, summary: &str, body: &str) {
        tracing::warn!("{summary}: {body}");
        match self {
            Self::DBus(d) => match tokio::time::timeout(DBUS_TIMEOUT, d.warn(summary, body)).await {
                Ok(Ok(())) => {}
                Ok(Err(e)) => tracing::warn!("notification failed: {e}"),
                Err(_) => tracing::warn!("notification timed out"),
            },
            Self::Fake(f) => f.warnings.lock().unwrap().push((summary.into(), body.into())),
            Self::Silent => {}
        }
    }
}

#[zbus::proxy(
    interface = "org.freedesktop.Notifications",
    default_service = "org.freedesktop.Notifications",
    default_path = "/org/freedesktop/Notifications",
    gen_blocking = false
)]
trait Notifications {
    #[allow(clippy::too_many_arguments)]
    fn notify(
        &self,
        app_name: &str,
        replaces_id: u32,
        app_icon: &str,
        summary: &str,
        body: &str,
        actions: &[&str],
        hints: HashMap<&str, Value<'_>>,
        expire_timeout: i32,
    ) -> zbus::Result<u32>;

    fn close_notification(&self, id: u32) -> zbus::Result<()>;

    #[zbus(signal)]
    fn action_invoked(&self, id: u32, action_key: &str) -> zbus::Result<()>;

    #[zbus(signal)]
    fn notification_closed(&self, id: u32, reason: u32) -> zbus::Result<()>;
}

pub struct DBusNotifier {
    proxy: NotificationsProxy<'static>,
    /// Post the unlock notification (`indicator.notification`).
    notify_prompts: bool,
    /// The tray icon (`indicator.tray`), if a session bus took it.
    tray: Option<Tray>,
}

impl DBusNotifier {
    pub async fn connect(indicator: &Indicator) -> zbus::Result<Self> {
        let conn = zbus::Connection::session().await?;
        let tray = if indicator.tray {
            match Tray::connect(indicator.tray_idle).await {
                Ok(t) => Some(t),
                Err(e) => {
                    tracing::warn!("no tray icon: {e}");
                    None
                }
            }
        } else {
            None
        };
        Ok(Self { proxy: NotificationsProxy::new(&conn).await?, notify_prompts: indicator.notification, tray })
    }

    /// The tray icon and/or the notification for one request. Closing the
    /// prompt takes both down; a failed or late notification still leaves
    /// the tray, and the tray is cleared whatever happens to the
    /// notification. Returns at once: the notification is posted by its own
    /// task, so the unlock never waits on the notification server.
    async fn prompt(&self, label: &str, emoji: &str) -> Prompt {
        if let Some(t) = &self.tray
            && tokio::time::timeout(DBUS_TIMEOUT, t.show(label, emoji)).await.is_err()
        {
            tracing::warn!("tray icon update timed out");
        }
        let mut prompt = if self.notify_prompts {
            match tokio::time::timeout(DBUS_TIMEOUT, self.post(label, emoji)).await {
                Ok(Ok(p)) => p,
                Ok(Err(e)) => {
                    tracing::warn!("notification failed: {e}");
                    Prompt::none()
                }
                Err(_) => {
                    tracing::warn!("notification timed out; answer on the phone");
                    Prompt::none()
                }
            }
        } else {
            Prompt::none()
        };
        if let Some(t) = self.tray.clone() {
            let close_notification = prompt.closer.take();
            prompt.closer = Some(Box::new(move || {
                Box::pin(async move {
                    if let Some(close) = close_notification {
                        close().await;
                    }
                    if tokio::time::timeout(DBUS_TIMEOUT, t.clear()).await.is_err() {
                        tracing::warn!("clearing the tray icon timed out");
                    }
                })
            }));
        }
        prompt
    }

    /// Subscribes, then hands `Notify` to a task of its own, and returns.
    ///
    /// The task owns the notification for its whole life: if the prompt has
    /// already ended when the server finally returns the id (a server that
    /// was slow or frozen), it closes the notification itself; otherwise it
    /// records the id for the closer and listens until the notification
    /// goes away or the prompt ends. Only the Use password action sends.
    async fn post(&self, label: &str, emoji: &str) -> zbus::Result<Prompt> {
        // Subscribe before posting, so the action cannot slip past.
        let mut actions = self.proxy.receive_action_invoked().await?;
        let mut closed = self.proxy.receive_notification_closed().await?;
        let shared = Arc::new(Mutex::new(Posted::default()));
        let (ended_tx, mut ended_rx) = tokio::sync::watch::channel(false);
        let (tx, rx) = oneshot::channel();
        let (proxy, task_shared) = (self.proxy.clone(), shared.clone());
        let summary = format!("Unlock {label} · {emoji}");
        tokio::spawn(async move {
            let hints = HashMap::from([("urgency", Value::U8(URGENCY_CRITICAL))]);
            let body = "Pick this emoji on your phone, then your fingerprint.";
            // Not bounded: a frozen server answers when it thaws, and the
            // notification it then shows must still be taken down.
            let notify = proxy.notify("bwphone", 0, "phone", &summary, body, &["password", "Use password"], hints, 0);
            tokio::pin!(notify);
            // Both subscriptions see every notification's signals, and zbus
            // stops reading the socket once a match rule's queue (64) is full:
            // left unread while Notify is pending, a burst of other
            // notifications' signals would hold our reply behind them for
            // good. So read and discard them meanwhile. None can be ours: the
            // server's reply reaches us before any signal about its id.
            let id = loop {
                tokio::select! {
                    biased;
                    reply = &mut notify => match reply {
                        Ok(id) => break id,
                        Err(e) => {
                            tracing::warn!("notification failed: {e}");
                            return;
                        }
                    },
                    Some(_) = actions.next() => {}
                    Some(_) = closed.next() => {}
                }
            };
            // One decision, under the lock: either the closer will find the id
            // and close it, or the prompt already ended and this task does.
            let already_ended = {
                let mut posted = task_shared.lock().unwrap();
                if !posted.ended {
                    posted.id = Some(id);
                }
                posted.ended
            };
            if already_ended {
                close_bounded(&proxy, id).await;
                return;
            }
            loop {
                tokio::select! {
                    // Actions first: a server sends ActionInvoked before the
                    // NotificationClosed that follows a press, and both are
                    // usually queued by the time this wakes. Taking the close
                    // first would lose the press.
                    biased;
                    Some(sig) = actions.next() => {
                        let Ok(a) = sig.args() else { continue };
                        if *a.id() == id && *a.action_key() == "password" {
                            let _ = tx.send(());
                            break;
                        }
                    }
                    Some(sig) = closed.next() => {
                        if sig.args().is_ok_and(|a| *a.id() == id) {
                            break;
                        }
                    }
                    // The prompt ended (or was dropped): stop listening.
                    _ = ended_rx.changed() => break,
                    else => break,
                }
            }
        });
        let proxy = self.proxy.clone();
        let closer: Closer = Box::new(move || {
            Box::pin(async move {
                let id = {
                    let mut posted = shared.lock().unwrap();
                    posted.ended = true;
                    posted.id.take()
                };
                let _ = ended_tx.send(true);
                // No id yet: the posting task closes it when one comes.
                if let Some(id) = id {
                    close_bounded(&proxy, id).await;
                }
            })
        });
        Ok(Prompt { use_password: Some(rx), closer: Some(closer) })
    }

    async fn warn(&self, summary: &str, body: &str) -> zbus::Result<()> {
        let hints = HashMap::from([("urgency", Value::U8(URGENCY_CRITICAL))]);
        self.proxy.notify("bwphone", 0, "dialog-warning", summary, body, &[], hints, -1).await?;
        Ok(())
    }
}

/// What the closer and the posting task share: whether the prompt has
/// ended, and the notification's id once the server has given it.
#[derive(Default)]
struct Posted {
    ended: bool,
    id: Option<u32>,
}

async fn close_bounded(proxy: &NotificationsProxy<'static>, id: u32) {
    match tokio::time::timeout(DBUS_TIMEOUT, proxy.close_notification(id)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => tracing::warn!("closing the unlock notification failed: {e}"),
        Err(_) => tracing::warn!("closing the unlock notification timed out"),
    }
}

/// Records what would have been shown; tests press Use password on it, or
/// dismiss it.
#[derive(Default)]
pub struct FakeNotifier {
    pub prompts: Mutex<Vec<FakePrompt>>,
    pub warnings: Mutex<Vec<(String, String)>>,
}

pub struct FakePrompt {
    pub label: String,
    pub emoji: String,
    pub open: bool,
    use_password: Option<oneshot::Sender<()>>,
}

impl FakeNotifier {
    fn prompt(self: &Arc<Self>, label: &str, emoji: &str) -> Prompt {
        let (tx, rx) = oneshot::channel();
        let index = {
            let mut prompts = self.prompts.lock().unwrap();
            prompts.push(FakePrompt { label: label.into(), emoji: emoji.into(), open: true, use_password: Some(tx) });
            prompts.len() - 1
        };
        let me = self.clone();
        let closer: Closer = Box::new(move || {
            Box::pin(async move {
                me.prompts.lock().unwrap()[index].open = false;
            })
        });
        Prompt { use_password: Some(rx), closer: Some(closer) }
    }

    pub fn press_use_password(&self, index: usize) {
        if let Some(tx) = self.prompts.lock().unwrap()[index].use_password.take() {
            let _ = tx.send(());
        }
    }

    /// The person closes the notification without pressing anything.
    pub fn dismiss(&self, index: usize) {
        drop(self.prompts.lock().unwrap()[index].use_password.take());
    }

    pub fn shown(&self) -> Vec<(String, String, bool)> {
        self.prompts.lock().unwrap().iter().map(|p| (p.label.clone(), p.emoji.clone(), p.open)).collect()
    }

    pub fn warnings(&self) -> Vec<(String, String)> {
        self.warnings.lock().unwrap().clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Against the live session bus: `cargo test -p bwphone live_bus -- --ignored`.
    /// Posts a prompt, leaves it up for a second, closes it.
    #[tokio::test]
    #[ignore]
    async fn live_bus_smoke() {
        let n = DBusNotifier::connect(&Indicator { notification: true, tray: false, ..Default::default() }).await.expect("session bus");
        let mut prompt = n.post("Smoke", "🍩").await.expect("notify");
        let pressed = tokio::time::timeout(std::time::Duration::from_secs(1), prompt.use_password()).await.is_ok();
        prompt.close().await;
        n.warn("bwphone smoke test", "This warning came from the test suite.").await.expect("warn");
        assert!(!pressed, "nobody should have pressed Use password within a second");
    }
}
