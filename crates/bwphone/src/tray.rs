//! The system-tray indicator: a StatusNotifierItem (the D-Bus protocol
//! behind the icons next to Wi-Fi and battery in Plasma's panel, and in
//! GNOME with the AppIndicator extension). Between unlocks it shows a keyhole,
//! `Active` (in the panel) or `Passive` (in the overflow) as `tray_idle` says;
//! while a request is on the phone it turns `NeedsAttention`, shows that
//! request's emoji as its icon, and says in its tooltip which account and
//! which emoji to pick.
//!
//! The icons are bitmaps compiled in: the 32 emojis of the pick, rendered
//! from Noto Color Emoji (SIL OFL, see assets/emoji/LICENSE), and the idle
//! keyhole. Nothing here can answer or cancel a request; the Use password
//! action stays on the notification.

use std::sync::OnceLock;

use tokio_stream::StreamExt as _;
use zbus::{interface, object_server::SignalEmitter, zvariant::OwnedObjectPath};

use crate::config::TrayIdle;

const PATH: &str = "/StatusNotifierItem";
const WATCHER: &str = "org.kde.StatusNotifierWatcher";

/// `a(iiay)`: width, height, ARGB32 in network byte order.
type Pixmaps = Vec<(i32, i32, Vec<u8>)>;

const EMOJI_PNG: [&[u8]; 32] = [
    include_bytes!("../assets/emoji/00.png"),
    include_bytes!("../assets/emoji/01.png"),
    include_bytes!("../assets/emoji/02.png"),
    include_bytes!("../assets/emoji/03.png"),
    include_bytes!("../assets/emoji/04.png"),
    include_bytes!("../assets/emoji/05.png"),
    include_bytes!("../assets/emoji/06.png"),
    include_bytes!("../assets/emoji/07.png"),
    include_bytes!("../assets/emoji/08.png"),
    include_bytes!("../assets/emoji/09.png"),
    include_bytes!("../assets/emoji/10.png"),
    include_bytes!("../assets/emoji/11.png"),
    include_bytes!("../assets/emoji/12.png"),
    include_bytes!("../assets/emoji/13.png"),
    include_bytes!("../assets/emoji/14.png"),
    include_bytes!("../assets/emoji/15.png"),
    include_bytes!("../assets/emoji/16.png"),
    include_bytes!("../assets/emoji/17.png"),
    include_bytes!("../assets/emoji/18.png"),
    include_bytes!("../assets/emoji/19.png"),
    include_bytes!("../assets/emoji/20.png"),
    include_bytes!("../assets/emoji/21.png"),
    include_bytes!("../assets/emoji/22.png"),
    include_bytes!("../assets/emoji/23.png"),
    include_bytes!("../assets/emoji/24.png"),
    include_bytes!("../assets/emoji/25.png"),
    include_bytes!("../assets/emoji/26.png"),
    include_bytes!("../assets/emoji/27.png"),
    include_bytes!("../assets/emoji/28.png"),
    include_bytes!("../assets/emoji/29.png"),
    include_bytes!("../assets/emoji/30.png"),
    include_bytes!("../assets/emoji/31.png"),
];
const IDLE_PNG: &[u8] = include_bytes!("../assets/tray-idle.png");

fn argb(png_bytes: &[u8]) -> Pixmaps {
    let decoder = png::Decoder::new(std::io::Cursor::new(png_bytes));
    let Ok(mut reader) = decoder.read_info() else { return vec![] };
    let Some(size) = reader.output_buffer_size() else { return vec![] };
    let mut buf = vec![0; size];
    let Ok(info) = reader.next_frame(&mut buf) else { return vec![] };
    if info.color_type != png::ColorType::Rgba || info.bit_depth != png::BitDepth::Eight {
        return vec![];
    }
    let mut out = Vec::with_capacity(info.width as usize * info.height as usize * 4);
    for [r, g, b, a] in buf[..info.buffer_size()].as_chunks::<4>().0 {
        out.extend_from_slice(&[*a, *r, *g, *b]);
    }
    vec![(info.width as i32, info.height as i32, out)]
}

fn idle_icon() -> &'static Pixmaps {
    static ICON: OnceLock<Pixmaps> = OnceLock::new();
    ICON.get_or_init(|| argb(IDLE_PNG))
}

/// The pixmap for one of the pick's emojis; the idle icon for anything else.
fn emoji_icon(emoji: &str) -> Pixmaps {
    match bwphone_transport::emoji::EMOJI.iter().position(|e| *e == emoji) {
        Some(i) => argb(EMOJI_PNG[i]),
        None => idle_icon().clone(),
    }
}

struct Item {
    status: &'static str,
    title: String,
    icon: Pixmaps,
    tip_title: String,
    tip_text: String,
}

impl Item {
    fn idle(idle: TrayIdle) -> Self {
        Self {
            status: match idle {
                TrayIdle::Shown => "Active",
                TrayIdle::Hidden => "Passive",
            },
            title: "bwphone".into(),
            icon: idle_icon().clone(),
            tip_title: "bwphone".into(),
            tip_text: "No unlock in progress".into(),
        }
    }
}

#[interface(name = "org.kde.StatusNotifierItem")]
impl Item {
    #[zbus(property)]
    fn category(&self) -> &str {
        "ApplicationStatus"
    }
    #[zbus(property)]
    fn id(&self) -> &str {
        "bwphone"
    }
    #[zbus(property)]
    fn title(&self) -> String {
        self.title.clone()
    }
    #[zbus(property)]
    fn status(&self) -> &str {
        self.status
    }
    #[zbus(property)]
    fn window_id(&self) -> i32 {
        0
    }
    #[zbus(property)]
    fn icon_name(&self) -> &str {
        ""
    }
    #[zbus(property)]
    fn icon_pixmap(&self) -> Pixmaps {
        self.icon.clone()
    }
    #[zbus(property)]
    fn overlay_icon_name(&self) -> &str {
        ""
    }
    #[zbus(property)]
    fn overlay_icon_pixmap(&self) -> Pixmaps {
        vec![]
    }
    #[zbus(property)]
    fn attention_icon_name(&self) -> &str {
        ""
    }
    #[zbus(property)]
    fn attention_icon_pixmap(&self) -> Pixmaps {
        self.icon.clone()
    }
    #[zbus(property)]
    fn attention_movie_name(&self) -> &str {
        ""
    }
    #[zbus(property)]
    fn tool_tip(&self) -> (String, Pixmaps, String, String) {
        (String::new(), self.icon.clone(), self.tip_title.clone(), self.tip_text.clone())
    }
    #[zbus(property)]
    fn item_is_menu(&self) -> bool {
        false
    }
    #[zbus(property)]
    fn menu(&self) -> OwnedObjectPath {
        OwnedObjectPath::try_from("/NO_DBUSMENU").expect("valid path")
    }

    fn activate(&self, _x: i32, _y: i32) {}
    fn secondary_activate(&self, _x: i32, _y: i32) {}
    fn context_menu(&self, _x: i32, _y: i32) {}
    fn scroll(&self, _delta: i32, _orientation: &str) {}

    #[zbus(signal)]
    async fn new_title(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn new_icon(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn new_attention_icon(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn new_tool_tip(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
    #[zbus(signal)]
    async fn new_status(emitter: &SignalEmitter<'_>, status: &str) -> zbus::Result<()>;
}

#[zbus::proxy(
    interface = "org.kde.StatusNotifierWatcher",
    default_service = "org.kde.StatusNotifierWatcher",
    default_path = "/StatusNotifierWatcher",
    gen_blocking = false
)]
trait Watcher {
    fn register_status_notifier_item(&self, service: &str) -> zbus::Result<()>;
}

/// The tray icon, registered with the panel for the daemon's lifetime.
#[derive(Clone)]
pub struct Tray {
    conn: zbus::Connection,
    idle: TrayIdle,
}

impl Tray {
    /// Puts the (passive) icon on the bus and registers it with the panel's
    /// watcher, now and again whenever the watcher restarts (plasmashell
    /// restarting, or a panel that starts after the daemon).
    pub async fn connect(idle: TrayIdle) -> zbus::Result<Self> {
        let name = format!("org.kde.StatusNotifierItem-{}-1", std::process::id());
        let conn = zbus::connection::Builder::session()?.name(name.clone())?.serve_at(PATH, Item::idle(idle))?.build().await?;
        let tray = Self { conn: conn.clone(), idle };
        let dbus = zbus::fdo::DBusProxy::new(&conn).await?;
        let mut owners = dbus.receive_name_owner_changed_with_args(&[(0, WATCHER)]).await?;
        register(&conn, &name).await;
        tokio::spawn(async move {
            while let Some(changed) = owners.next().await {
                if changed.args().is_ok_and(|a| a.new_owner().is_some()) {
                    register(&conn, &name).await;
                }
            }
        });
        Ok(tray)
    }

    /// A request is on the phone: its emoji in the panel, the details in the tooltip.
    pub async fn show(&self, label: &str, emoji: &str) {
        let icon = emoji_icon(emoji);
        self.set(|item| {
            item.status = "NeedsAttention";
            item.title = format!("Unlock {label} · {emoji}");
            item.icon = icon;
            item.tip_title = format!("Unlock {label}");
            item.tip_text = format!("Pick {emoji} on your phone, then your fingerprint.");
        })
        .await;
    }

    /// The request ended: back to the keyhole.
    pub async fn clear(&self) {
        let idle = self.idle;
        self.set(move |item| *item = Item::idle(idle)).await;
    }

    async fn set(&self, change: impl FnOnce(&mut Item)) {
        if let Err(e) = self.try_set(change).await {
            tracing::warn!("tray icon update failed: {e}");
        }
    }

    async fn try_set(&self, change: impl FnOnce(&mut Item)) -> zbus::Result<()> {
        let iface = self.conn.object_server().interface::<_, Item>(PATH).await?;
        let status = {
            let mut item = iface.get_mut().await;
            change(&mut item);
            item.status
        };
        let emitter = iface.signal_emitter();
        Item::new_icon(emitter).await?;
        Item::new_attention_icon(emitter).await?;
        Item::new_title(emitter).await?;
        Item::new_tool_tip(emitter).await?;
        Item::new_status(emitter, status).await?;
        Ok(())
    }
}

async fn register(conn: &zbus::Connection, name: &str) {
    let result = async { WatcherProxy::new(conn).await?.register_status_notifier_item(name).await }.await;
    match result {
        Ok(()) => tracing::info!("tray icon registered"),
        // No panel with a tray (yet): the watcher appearing later re-registers.
        Err(e) => tracing::info!("no tray to show the icon in yet: {e}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_emoji_has_its_icon() {
        for e in bwphone_transport::emoji::EMOJI {
            let p = emoji_icon(e);
            assert_eq!(p.len(), 1, "{e}");
            let (w, h, data) = &p[0];
            assert_eq!((*w, *h), (64, 64), "{e}");
            assert_eq!(data.len(), 64 * 64 * 4);
            assert!(data.as_chunks::<4>().0.iter().any(|px| px[0] == 255), "{e} is not blank");
            assert_ne!(&p, idle_icon(), "{e} fell back to the idle icon");
        }
        assert_eq!(idle_icon().len(), 1);
    }

    #[test]
    fn an_unknown_emoji_shows_the_idle_icon() {
        assert_eq!(&emoji_icon("🦀"), idle_icon());
    }

    /// Against the live session bus: `cargo test -p bwphone live_tray -- --ignored`.
    /// A second tray icon cycles through a few emojis, three seconds each, for
    /// `BWPHONE_TRAY_SECS` seconds (default 3), then goes back to idle.
    #[tokio::test]
    #[ignore]
    async fn live_tray_smoke() {
        let secs: u64 = std::env::var("BWPHONE_TRAY_SECS").ok().and_then(|s| s.parse().ok()).unwrap_or(3);
        let t = Tray::connect(TrayIdle::Shown).await.expect("session bus");
        for emoji in ["🍩", "🤠", "🥑", "😎", "🥳"].iter().cycle().take(secs.div_ceil(3) as usize) {
            t.show("Smoke", emoji).await;
            tokio::time::sleep(std::time::Duration::from_secs(3)).await;
        }
        t.clear().await;
    }
}
