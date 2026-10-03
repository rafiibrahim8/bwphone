//! The daemon's Unix sockets: directory 0700 and socket 0600, both set
//! explicitly, and `SO_PEERCRED` checked before a byte is read. That is the
//! only local authentication there is; the protocol has none.
//!
//! Also the one-daemon-per-user lock, taken before any socket is touched.

use std::{
    fs, io,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
};

use tokio::net::{UnixListener, UnixStream};

/// Exit status of a daemon that found another holding the lock. The unit
/// lists it in `RestartPreventExitStatus=`, so systemd does not retry.
pub const ALREADY_RUNNING: i32 = 3;

fn private_dir(path: &Path) -> io::Result<()> {
    let dir = path.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "path has no directory"))?;
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))
}

/// An exclusive `flock` on `path`, or `None` if another process holds it.
/// The lock lasts as long as the returned file is open, and the kernel drops
/// it however the process ends, so a crash never leaves it stale. `flock`
/// locks the file, not the path: the sandboxed unit and a daemon started by
/// hand see the same one.
pub fn lock_single_instance(path: &Path) -> io::Result<Option<fs::File>> {
    private_dir(path)?;
    let file = fs::OpenOptions::new().create(true).write(true).truncate(false).mode(0o600).open(path)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(fs::TryLockError::WouldBlock) => Ok(None),
        Err(fs::TryLockError::Error(e)) => Err(e),
    }
}

/// Replaces a socket file left by an earlier daemon. Safe only because the
/// caller holds the single-instance lock: no live daemon is listening there.
pub async fn bind_private(path: &Path) -> io::Result<UnixListener> {
    private_dir(path)?;
    match fs::remove_file(path) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => {}
        Err(e) => return Err(e),
    }
    let listener = UnixListener::bind(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(listener)
}

pub fn same_uid(stream: &UnixStream) -> bool {
    // SAFETY: getuid takes no arguments and cannot fail.
    let ours = unsafe { libc::getuid() };
    stream.peer_cred().map(|c| c.uid() == ours).unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn modes_are_explicit_and_peer_is_us() {
        let dir = std::env::temp_dir().join(format!("bwphone-sock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("run").join("sock");
        let listener = bind_private(&path).await.unwrap();
        assert_eq!(fs::metadata(dir.join("run")).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);

        let client = UnixStream::connect(&path).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        assert!(same_uid(&server));
        drop(client);

        // Rebinding over a stale socket file works.
        drop(listener);
        bind_private(&path).await.unwrap();
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn second_instance_is_refused_until_the_first_is_gone() {
        let dir = std::env::temp_dir().join(format!("bwphone-lock-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("run").join("daemon.lock");

        let first = lock_single_instance(&path).unwrap().expect("nobody holds it yet");
        assert_eq!(fs::metadata(dir.join("run")).unwrap().permissions().mode() & 0o777, 0o700);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o600);
        // A separate open of the same file is refused, as another process would be.
        assert!(lock_single_instance(&path).unwrap().is_none());

        drop(first);
        assert!(lock_single_instance(&path).unwrap().is_some());
        fs::remove_dir_all(&dir).unwrap();
    }
}
