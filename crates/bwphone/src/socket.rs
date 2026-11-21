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

use tokio::{
    io::{AsyncBufRead, AsyncBufReadExt as _, AsyncReadExt as _},
    net::{UnixListener, UnixStream},
};

/// The longest line the control and hello sockets accept, newline included.
/// Their requests are a few dozen bytes.
pub const MAX_LINE: usize = 4096;
/// How long a peer may take to send a line once connected (or after the
/// previous one). The CLI and `bwphone-hello` write theirs at once.
pub const LINE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);

/// One line of at most [`MAX_LINE`] bytes into `line` (cleared first),
/// within [`LINE_TIMEOUT`]. `Ok(false)` at a clean end of stream. A longer
/// line or a slow peer is an error, which ends the connection: a peer
/// (such as a compromised `bwphone-hello`) cannot make the daemon buffer
/// without bound or hold a connection open forever.
pub async fn read_line_bounded<R: AsyncBufRead + Unpin>(r: &mut R, line: &mut String) -> io::Result<bool> {
    line.clear();
    let mut limited = r.take(MAX_LINE as u64);
    let n = tokio::time::timeout(LINE_TIMEOUT, limited.read_line(line))
        .await.map_err(|_| io::Error::new(io::ErrorKind::TimedOut, "no line in time"))??;
    if n == MAX_LINE && !line.ends_with('\n') {
        return Err(io::Error::new(io::ErrorKind::InvalidData, "line too long"));
    }
    Ok(n > 0)
}

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

#[cfg(test)]
mod line_tests {
    use super::*;
    use tokio::io::{AsyncWriteExt as _, BufReader};

    #[tokio::test]
    async fn lines_are_bounded_in_size() {
        let (mut a, b) = tokio::io::duplex(1 << 16);
        let mut r = BufReader::new(b);
        let mut line = String::new();
        a.write_all(b"key\n").await.unwrap();
        assert!(read_line_bounded(&mut r, &mut line).await.unwrap());
        assert_eq!(line, "key\n");

        let exact = format!("{}\n", "a".repeat(MAX_LINE - 1));
        a.write_all(exact.as_bytes()).await.unwrap();
        assert!(read_line_bounded(&mut r, &mut line).await.unwrap(), "a line of exactly MAX_LINE is fine");

        a.write_all(&vec![b'a'; MAX_LINE + 10]).await.unwrap();
        assert_eq!(read_line_bounded(&mut r, &mut line).await.unwrap_err().kind(), io::ErrorKind::InvalidData);

        drop(a);
        let (a, b) = tokio::io::duplex(64);
        drop(a);
        assert!(!read_line_bounded(&mut BufReader::new(b), &mut line).await.unwrap(), "clean end of stream");
    }

    #[tokio::test(start_paused = true)]
    async fn a_silent_peer_times_out() {
        let (_a, b) = tokio::io::duplex(64);
        let mut line = String::new();
        let err = read_line_bounded(&mut BufReader::new(b), &mut line).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
    }
}
