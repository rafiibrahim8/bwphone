//! The daemon's Unix sockets: directory 0700 and socket 0600, both set
//! explicitly, and `SO_PEERCRED` checked before a byte is read. That is the
//! only local authentication there is; the protocol has none.

use std::{
    fs, io,
    os::unix::fs::PermissionsExt as _,
    path::Path,
};

use tokio::net::{UnixListener, UnixStream};

pub async fn bind_private(path: &Path) -> io::Result<UnixListener> {
    let dir = path.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket path has no directory"))?;
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
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
}
