//! The native messaging manifests, `com.8bit.bitwarden.json`, one per
//! browser, each pointing at `bwphone-proxy`. Installing the real Bitwarden
//! desktop app overwrites them under the same name, so the daemon checks
//! them at startup.

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde_json::{Value, json};

pub const HOST_NAME: &str = "com.8bit.bitwarden";
/// The Bitwarden extension's IDs, as Bitwarden's own desktop app allows them
/// (`apps/desktop/src/main/native-messaging.main.ts`, `loadChromeIds`). The
/// browsers below are the ones it writes a manifest for on Linux
/// (`getLinuxNMHS`), and no others.
const CHROME_ORIGINS: [&str; 4] = [
    // Chrome Web Store: Chrome, Chromium, Brave, Vivaldi
    "chrome-extension://nngceckbapebfimnlniiiahkandclblb/",
    // Chrome Web Store, beta channel
    "chrome-extension://hccnnhgbibccigepcmlgppchkpfdophk/",
    // Microsoft Edge Add-ons
    "chrome-extension://jbkfoedolllekgbhcbcoahefnbanhhlh/",
    // Opera add-ons
    "chrome-extension://ccnckbpmaceehanjmeomladnmlffdjgn/",
];
const FIREFOX_EXTENSION: &str = "{446900e4-71c2-419f-a6a7-df9c091e268b}";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Chromium,
    Firefox,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Browser {
    pub name: &'static str,
    pub kind: Kind,
    /// The browser's config directory; the manifest goes under it. Only
    /// browsers whose directory exists get a manifest.
    pub config_dir: PathBuf,
    pub manifest: PathBuf,
}

pub fn browsers(home: &Path) -> Vec<Browser> {
    let chromium = |name, sub: &str| {
        let config_dir = home.join(".config").join(sub);
        Browser { name, kind: Kind::Chromium, manifest: config_dir.join("NativeMessagingHosts").join(format!("{HOST_NAME}.json")), config_dir }
    };
    let firefox_dir = home.join(".mozilla");
    vec![
        chromium("Chrome", "google-chrome"),
        chromium("Chromium", "chromium"),
        chromium("Brave", "BraveSoftware/Brave-Browser"),
        chromium("Edge", "microsoft-edge"),
        chromium("Vivaldi", "vivaldi"),
        Browser {
            name: "Firefox",
            kind: Kind::Firefox,
            manifest: firefox_dir.join("native-messaging-hosts").join(format!("{HOST_NAME}.json")),
            config_dir: firefox_dir,
        },
    ]
}

pub fn manifest(kind: Kind, proxy: &Path) -> Value {
    let mut m = json!({
        "name": HOST_NAME,
        "description": "Bitwarden desktop <-> browser bridge (bwphone)",
        "path": proxy,
        "type": "stdio",
    });
    match kind {
        Kind::Chromium => m["allowed_origins"] = json!(CHROME_ORIGINS),
        Kind::Firefox => m["allowed_extensions"] = json!([FIREFOX_EXTENSION]),
    }
    m
}

pub fn write_all(home: &Path, proxy: &Path) -> std::io::Result<Vec<Browser>> {
    let mut written = Vec::new();
    for b in browsers(home) {
        if !b.config_dir.is_dir() {
            continue;
        }
        if let Some(dir) = b.manifest.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(&b.manifest, serde_json::to_vec_pretty(&manifest(b.kind, proxy))?)?;
        written.push(b);
    }
    Ok(written)
}

/// Manifests that exist but do not point at our proxy: someone else's, most
/// likely the real desktop app's.
pub fn check_all(home: &Path, proxy: &Path) -> Vec<(Browser, String)> {
    let mut problems = Vec::new();
    for b in browsers(home) {
        let Ok(bytes) = fs::read(&b.manifest) else { continue };
        let path = serde_json::from_slice::<Value>(&bytes).ok().and_then(|v| v["path"].as_str().map(str::to_owned));
        match path {
            Some(p) if Path::new(&p) == proxy => {}
            Some(p) => problems.push((b, format!("points at {p}"))),
            None => problems.push((b, "unreadable".into())),
        }
    }
    problems
}

/// Where the proxy is expected. It is not a command, so it lives in the
/// package's lib directory beside the installed `bwphone`: `<prefix>/lib/bwphone/`
/// for `<prefix>/bin/bwphone`, i.e. `/usr/lib/bwphone/` or `~/.local/lib/bwphone/`.
/// A sibling of this binary wins (a source checkout's target directory).
pub fn default_proxy_path(home: &Path) -> PathBuf {
    let mut candidates = Vec::new();
    if let Ok(me) = std::env::current_exe()
        && let Some(bin) = me.parent()
    {
        candidates.push(bin.join("bwphone-proxy"));
        if let Some(prefix) = bin.parent() {
            candidates.push(prefix.join("lib/bwphone/bwphone-proxy"));
        }
    }
    candidates.push(home.join(".local/lib/bwphone/bwphone-proxy"));
    candidates.push(PathBuf::from("/usr/lib/bwphone/bwphone-proxy"));
    candidates.iter().find(|p| p.is_file()).cloned().unwrap_or_else(|| home.join(".local/lib/bwphone/bwphone-proxy"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn writes_only_installed_browsers_and_detects_tampering() {
        let home = std::env::temp_dir().join(format!("bwphone-manifests-{}", std::process::id()));
        let _ = fs::remove_dir_all(&home);
        fs::create_dir_all(home.join(".config/chromium")).unwrap();
        fs::create_dir_all(home.join(".mozilla")).unwrap();
        let proxy = home.join(".local/bin/bwphone-proxy");

        let written = write_all(&home, &proxy).unwrap();
        assert_eq!(written.iter().map(|b| b.name).collect::<Vec<_>>(), ["Chromium", "Firefox"]);
        let chromium: Value = serde_json::from_slice(&fs::read(&written[0].manifest).unwrap()).unwrap();
        assert_eq!(chromium["name"], HOST_NAME);
        assert_eq!(chromium["allowed_origins"][0], CHROME_ORIGINS[0]);
        assert!(chromium.get("allowed_extensions").is_none());
        let firefox: Value = serde_json::from_slice(&fs::read(&written[1].manifest).unwrap()).unwrap();
        assert_eq!(firefox["allowed_extensions"][0], FIREFOX_EXTENSION);
        assert!(check_all(&home, &proxy).is_empty());

        // The real desktop app overwrites Chromium's.
        fs::write(&written[0].manifest, r#"{"name":"com.8bit.bitwarden","path":"/opt/Bitwarden/bitwarden-desktop-proxy"}"#).unwrap();
        let problems = check_all(&home, &proxy);
        assert_eq!(problems.len(), 1);
        assert_eq!(problems[0].0.name, "Chromium");
        assert!(problems[0].1.contains("/opt/Bitwarden"));
        fs::remove_dir_all(&home).unwrap();
    }
}
