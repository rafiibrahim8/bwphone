//! Where the daemon keeps things, by the XDG base directories.
//!
//! - config `~/.config/bwphone/`: `config.toml` (the daemon's settings)
//! - data `~/.local/share/bwphone/`: `pairing.json`, `accounts/<id>/`
//! - state `~/.local/state/bwphone/`: `log`
//! - runtime `$XDG_RUNTIME_DIR/bwphone/`: `sock` (proxies), `ctl` (CLI),
//!   `daemon.lock` (one daemon per user)
//! - `$XDG_RUNTIME_DIR/bwphone-hello/`: `hello.sock`, and `hello.lock` (one
//!   `bwphone-hello` per user); the one directory the hello process's sandbox
//!   can reach, everything under `bwphone/` is hidden from it

use std::{
    io,
    path::{Path, PathBuf},
};

#[derive(Debug, Clone)]
pub struct Paths {
    pub config: PathBuf,
    pub data: PathBuf,
    pub state: PathBuf,
    pub runtime: PathBuf,
    pub hello_runtime: PathBuf,
}

impl Paths {
    pub fn from_env() -> io::Result<Self> {
        let home = std::env::var_os("HOME")
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "HOME is not set"))?;
        let xdg = |var: &str, fallback: &str| {
            std::env::var_os(var).map(PathBuf::from).unwrap_or_else(|| home.join(fallback)).join("bwphone")
        };
        let run = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "XDG_RUNTIME_DIR is not set"))?;
        Ok(Self {
            config: xdg("XDG_CONFIG_HOME", ".config"),
            data: xdg("XDG_DATA_HOME", ".local/share"),
            state: xdg("XDG_STATE_HOME", ".local/state"),
            runtime: run.join("bwphone"),
            hello_runtime: run.join("bwphone-hello"),
        })
    }

    pub fn under(root: &Path) -> Self {
        Self { config: root.join("config"), data: root.join("data"), state: root.join("state"), runtime: root.join("run"), hello_runtime: root.join("run-hello") }
    }

    pub fn config_file(&self) -> PathBuf {
        self.config.join("config.toml")
    }

    pub fn pairing(&self) -> PathBuf {
        self.data.join("pairing.json")
    }

    pub fn accounts(&self) -> PathBuf {
        self.data.join("accounts")
    }

    pub fn log(&self) -> PathBuf {
        self.state.join("log")
    }

    /// Browsers' proxies connect here: raw native-messaging frames.
    pub fn proxy_socket(&self) -> PathBuf {
        self.runtime.join("sock")
    }

    /// The CLI connects here: one JSON line each way.
    pub fn control_socket(&self) -> PathBuf {
        self.runtime.join("ctl")
    }

    /// Held by the running daemon; a second one refuses to start.
    pub fn daemon_lock(&self) -> PathBuf {
        self.runtime.join("daemon.lock")
    }

    /// `bwphone-hello` connects here: plain text lines, key and hellos only.
    pub fn hello_socket(&self) -> PathBuf {
        self.hello_runtime.join("hello.sock")
    }
}
