//! The daemon's settings: `~/.config/bwphone/config.toml`, read once at
//! start (`systemctl --user restart bwphone` after a change). Every key is
//! optional; a missing file means the defaults, and a file that doesn't
//! parse is reported and ignored rather than stopping the daemon.
//!
//! ```toml
//! [indicator]
//! # The desktop notification with the emoji and a Use password action.
//! notification = true
//! # A status icon in the system tray that shows the emoji while a request
//! # is on the phone, with the account and the emoji in its tooltip.
//! tray = true
//! # Between unlocks: "shown" keeps the keyhole in the panel, "hidden" puts
//! # it in the tray's overflow until a request comes.
//! tray_idle = "shown"
//! ```

use std::path::Path;

use serde::Deserialize;

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub indicator: Indicator,
}

/// How the PC shows an unlock's emoji. Warnings (someone else asked,
/// a manifest was overwritten) are always notifications.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Indicator {
    pub notification: bool,
    pub tray: bool,
    pub tray_idle: TrayIdle,
}

/// The tray icon between unlocks. During one it always asks for attention.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TrayIdle {
    /// `Active`: panels show it.
    #[default]
    Shown,
    /// `Passive`: panels keep it in their overflow.
    Hidden,
}

impl Default for Indicator {
    fn default() -> Self {
        Self { notification: true, tray: true, tray_idle: TrayIdle::Shown }
    }
}

impl Config {
    /// The settings at `path`, or the defaults with a reason why not.
    pub fn load(path: &Path) -> (Self, Option<String>) {
        match std::fs::read_to_string(path) {
            Ok(text) => match toml::from_str(&text) {
                Ok(c) => (c, None),
                Err(e) => (Self::default(), Some(format!("{}: {e}; using the defaults", path.display()))),
            },
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => (Self::default(), None),
            Err(e) => (Self::default(), Some(format!("{}: {e}; using the defaults", path.display()))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(s: &str) -> Result<Config, toml::de::Error> {
        toml::from_str(s)
    }

    #[test]
    fn defaults_show_both() {
        assert_eq!(parse("").unwrap(), Config { indicator: Indicator { notification: true, tray: true, tray_idle: TrayIdle::Shown } });
        assert_eq!(
            parse("[indicator]\ntray = false\n").unwrap().indicator,
            Indicator { notification: true, tray: false, tray_idle: TrayIdle::Shown }
        );
        assert_eq!(parse("[indicator]\ntray_idle = \"hidden\"\n").unwrap().indicator.tray_idle, TrayIdle::Hidden);
    }

    #[test]
    fn a_typo_is_an_error_not_a_silent_default() {
        assert!(parse("[indicator]\ntrya = false\n").is_err());
        assert!(parse("[indicatr]\n").is_err());
        assert!(parse("[indicator]\ntray = \"no\"\n").is_err());
        assert!(parse("[indicator]\ntray_idle = \"sometimes\"\n").is_err());
    }

    #[test]
    fn load_reports_a_bad_file_and_falls_back() {
        let dir = std::env::temp_dir().join(format!("bwphone-config-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("config.toml");
        assert_eq!(Config::load(&p), (Config::default(), None), "missing file: defaults, no complaint");
        std::fs::write(&p, "[indicator]\nnotification = false\n").unwrap();
        assert!(!Config::load(&p).0.indicator.notification);
        std::fs::write(&p, "not toml [").unwrap();
        let (c, why) = Config::load(&p);
        assert_eq!(c, Config::default());
        assert!(why.unwrap().contains("using the defaults"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
