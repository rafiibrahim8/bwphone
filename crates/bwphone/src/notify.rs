//! The desktop side of an unlock: one critical-urgency notification carrying
//! the session's emoji and a Use password action, and/or the tray icon
//! showing that emoji (as `config.toml` says), both taken down when the
//! request ends; and plain warnings, always as notifications.

use std::{
    collections::HashMap,
    future::Future,
    pin::Pin,
    sync::{Arc, Mutex},
};

use tokio::sync::oneshot;

use crate::{config::Indicator, tray::Tray};
use tokio_stream::StreamExt as _;
use zbus::zvariant::Value;

const URGENCY_CRITICAL: u8 = 2;

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
    /// notification to press it on.
    pub async fn use_password(&mut self) {
        match &mut self.use_password {
            Some(rx) => {
                let _ = rx.await;
            }
            None => std::future::pending().await,
        }
    }

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
            Self::DBus(d) => d.prompt(label, emoji).await,
            Self::Fake(f) => f.prompt(label, emoji),
            Self::Silent => Prompt { use_password: None, closer: None },
        }
    }

    pub async fn warn(&self, summary: &str, body: &str) {
        tracing::warn!("{summary}: {body}");
        match self {
            Self::DBus(d) => {
                if let Err(e) = d.warn(summary, body).await {
                    tracing::warn!("notification failed: {e}");
                }
            }
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
    /// prompt takes both down; a failed notification still leaves the tray.
    async fn prompt(&self, label: &str, emoji: &str) -> Prompt {
        if let Some(t) = &self.tray {
            t.show(label, emoji).await;
        }
        let mut prompt = if self.notify_prompts {
            self.post(label, emoji).await.unwrap_or_else(|e| {
                tracing::warn!("notification failed: {e}");
                Prompt::none()
            })
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
                    t.clear().await;
                })
            }));
        }
        prompt
    }

    async fn post(&self, label: &str, emoji: &str) -> zbus::Result<Prompt> {
        // Subscribe before posting, so the action cannot slip past.
        let mut actions = self.proxy.receive_action_invoked().await?;
        let mut closed = self.proxy.receive_notification_closed().await?;
        let hints = HashMap::from([("urgency", Value::U8(URGENCY_CRITICAL))]);
        let id = self
            .proxy
            .notify(
                "bwphone",
                0,
                "phone",
                &format!("Unlock {label} · {emoji}"),
                "Pick this emoji on your phone, then your fingerprint.",
                &["password", "Use password"],
                hints,
                0,
            )
            .await?;
        let (tx, rx) = oneshot::channel();
        tokio::spawn(async move {
            loop {
                tokio::select! {
                    Some(sig) = actions.next() => {
                        let Ok(a) = sig.args() else { continue };
                        if *a.id() == id {
                            if *a.action_key() == "password" {
                                let _ = tx.send(());
                            }
                            break;
                        }
                    }
                    Some(sig) = closed.next() => {
                        if sig.args().is_ok_and(|a| *a.id() == id) {
                            break;
                        }
                    }
                    else => break,
                }
            }
        });
        let proxy = self.proxy.clone();
        let closer: Closer = Box::new(move || {
            Box::pin(async move {
                let _ = proxy.close_notification(id).await;
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

/// Records what would have been shown; tests press Use password on it.
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
