//! The daemon. One process holds the Noise key, owns every `vault.blob`,
//! serves the browsers' proxies, and talks to the phone one session at a
//! time.

pub mod accounts;
pub mod bwcli;
pub mod config;
pub mod control;
pub mod enroll;
pub mod hellosock;
pub mod manifests;
pub mod notify;
pub mod pair;
pub mod pairing;
pub mod paths;
pub mod phone;
pub mod secrets;
pub mod serve;
pub mod socket;
pub mod tray;
pub mod unlock;

use std::{path::PathBuf, sync::Mutex};

use accounts::Accounts;
use notify::Notifier;
use pairing::Pairing;
use phone::Phone;
use secrets::Secrets;
use unlock::{PhoneState, Queue};

/// Everything the connection handlers and the unlock worker share.
pub struct Ctx {
    pub accounts: Accounts,
    pub phone: Phone,
    pub state: Mutex<PhoneState>,
    pub secrets: Secrets,
    pub notifier: Notifier,
    pub queue: Queue,
    pub pairing: Mutex<Option<Pairing>>,
    pub pairing_path: Option<PathBuf>,
}

/// `PR_SET_DUMPABLE = 0` and `RLIMIT_CORE = 0`, before any secret is
/// loaded: systemd-coredump would otherwise write a crash dump holding the
/// key to disk, and a dumpable process's `/proc/<pid>/mem` is readable by
/// other processes of the same uid. Every subcommand calls this, not only
/// the daemon: `pair` holds the Noise key and `enroll` holds the plaintext
/// user key.
pub fn no_core_dumps() -> bool {
    let limit = libc::rlimit { rlim_cur: 0, rlim_max: 0 };
    // SAFETY: both calls only change this process's own attributes, and
    // `limit` outlives the call that reads it.
    unsafe { libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0 && libc::setrlimit(libc::RLIMIT_CORE, &limit) == 0 }
}

/// For the phone's prompt: "Unlock Work on ibra-PC".
pub fn hostname() -> String {
    std::fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_owned())
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "PC".into())
}
