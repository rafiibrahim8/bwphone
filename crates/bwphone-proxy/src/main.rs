//! The browser spawns one of these per extension connection and kills it
//! when the service worker idles out. It forwards stdin to the daemon's
//! socket and the socket to stdout, unchanged: the native-messaging
//! frames stay intact and the daemon does the rest. Every byte it carries
//! after the handshake is ciphertext, so it holds nothing worth protecting.
//!
//! Its own stdout is the message pipe. At startup that fd is duplicated for
//! the relay and fd 1 is pointed at `/dev/null`, so a stray print from a
//! dependency cannot corrupt the stream.

use std::os::fd::FromRawFd as _;

use tokio::{
    io::{AsyncWriteExt as _, copy},
    net::UnixStream,
};

fn socket_path() -> Option<std::path::PathBuf> {
    Some(std::path::PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?).join("bwphone").join("sock"))
}

/// The real stdout as a file, with fd 1 sent to `/dev/null`.
fn take_stdout() -> std::io::Result<std::fs::File> {
    // SAFETY: plain fd arithmetic on fds this process owns, before any
    // other thread exists.
    unsafe {
        let out = libc::dup(1);
        if out < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let null = libc::open(c"/dev/null".as_ptr(), libc::O_WRONLY);
        if null < 0 || libc::dup2(null, 1) < 0 {
            return Err(std::io::Error::last_os_error());
        }
        libc::close(null);
        Ok(std::fs::File::from_raw_fd(out))
    }
}

#[tokio::main(flavor = "current_thread")]
async fn main() {
    let stdout = match take_stdout() {
        Ok(f) => f,
        Err(e) => {
            eprintln!("bwphone-proxy: cannot take over stdout: {e}");
            std::process::exit(1);
        }
    };
    let Some(path) = socket_path() else {
        eprintln!("bwphone-proxy: XDG_RUNTIME_DIR is not set");
        std::process::exit(1);
    };
    let daemon = match UnixStream::connect(&path).await {
        Ok(s) => s,
        Err(e) => {
            // The extension retries every 10 s; the daemon may just not be up yet.
            eprintln!("bwphone-proxy: daemon not reachable at {}: {e}", path.display());
            std::process::exit(1);
        }
    };
    let (mut from_daemon, mut to_daemon) = daemon.into_split();
    let mut stdin = tokio::io::stdin();
    let mut stdout = tokio::fs::File::from_std(stdout);

    let inbound = async {
        let _ = copy(&mut stdin, &mut to_daemon).await;
        let _ = to_daemon.shutdown().await;
    };
    let outbound = async {
        let _ = copy(&mut from_daemon, &mut stdout).await;
        let _ = stdout.flush().await;
    };
    // Whichever side closes first ends the relay; the other has nothing left to say.
    tokio::select! {
        _ = inbound => {}
        _ = outbound => {}
    }
}
