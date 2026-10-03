//! `bwphone-hello`: the PC's ear for the phone, in a process that holds
//! only `hello_key` — never the Noise key, never a blob, never the wallet.
//!
//! - UDP on the hello port: opens the phone's encrypted address announcement
//!   and hands the address to the daemon.
//! - mDNS on 5353: answers queries for the rotating names (yesterday's,
//!   today's, tomorrow's) with this PC's address. Answers only, never
//!   announces; unicast when the phone asks with the QU bit.
//!
//! It talks to the daemon over `$XDG_RUNTIME_DIR/bwphone-hello/hello.sock`
//! in plain text lines (`key` → `key <hex> <port>`; `hello <ip> <port>
//! <seq>` → `ok`), which is the only path its unit lets it reach: no session
//! bus, no `$HOME`, none of the daemon's other sockets. Compromised, it can
//! misdirect the daemon to a wrong address (a failed handshake, then the
//! password box) and nothing more.
//!
//! IPv4 only for now: the phone queries over Wi-Fi IPv4. `ff02::fb` is a
//! second socket and an AAAA record when it is needed.
//!
//! One per user: `hello.lock` beside the socket, under `flock`, held for the
//! life of the process. A second one exits with [`ALREADY_RUNNING`].

mod dns;

use std::{
    net::{Ipv4Addr, SocketAddr, SocketAddrV4},
    path::{Path, PathBuf},
    time::Duration,
};

use bwphone_transport::{hello, mdns};
use tokio::{
    io::{AsyncBufReadExt as _, AsyncWriteExt as _, BufReader},
    net::{UdpSocket, UnixStream},
};
use zeroize::Zeroizing;

const MDNS_GROUP: Ipv4Addr = Ipv4Addr::new(224, 0, 0, 251);
const MDNS_PORT: u16 = 5353;
const RECORD_TTL: u32 = 10;
const RETRY: Duration = Duration::from_secs(5);
/// Exit status when another `bwphone-hello` holds the lock; the unit lists it
/// in `RestartPreventExitStatus=`, so systemd does not retry.
const ALREADY_RUNNING: i32 = 3;

fn log(msg: impl std::fmt::Display) {
    eprintln!("bwphone-hello: {msg}");
}

fn socket_path() -> Option<PathBuf> {
    Some(PathBuf::from(std::env::var_os("XDG_RUNTIME_DIR")?).join("bwphone-hello").join("hello.sock"))
}

/// An exclusive `flock` on `path`, or `None` if another process holds it.
/// The kernel drops it however we exit. `flock` locks the file, not the path,
/// so this unit's bind-mounted view and an unsandboxed copy share one lock.
fn lock_single_instance(path: &Path) -> std::io::Result<Option<std::fs::File>> {
    use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};
    // The daemon's unit normally creates the directory; this is for a copy
    // started by hand before the daemon ever ran.
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new().recursive(true).mode(0o700).create(dir)?;
    }
    let file = std::fs::OpenOptions::new().create(true).write(true).truncate(false).mode(0o600).open(path)?;
    match file.try_lock() {
        Ok(()) => Ok(Some(file)),
        Err(std::fs::TryLockError::WouldBlock) => Ok(None),
        Err(std::fs::TryLockError::Error(e)) => Err(e),
    }
}

#[tokio::main]
async fn main() {
    let Some(sock) = socket_path() else {
        log("XDG_RUNTIME_DIR is not set");
        std::process::exit(1);
    };
    let lock_path = sock.with_file_name("hello.lock");
    let _lock = match lock_single_instance(&lock_path) {
        Ok(Some(lock)) => lock,
        Ok(None) => {
            log(format!("already running for this user ({} is locked)", lock_path.display()));
            std::process::exit(ALREADY_RUNNING);
        }
        Err(e) => {
            log(format!("cannot take {}: {e}", lock_path.display()));
            std::process::exit(1);
        }
    };
    // The key comes from the daemon, which reads the wallet; wait for both.
    let (key, port) = loop {
        match fetch_key(&sock).await {
            Ok(x) => break x,
            Err(e) => {
                log(format!("no key yet ({e}); retrying in {}s", RETRY.as_secs()));
                tokio::time::sleep(RETRY).await;
            }
        }
    };
    let key = std::sync::Arc::new(key);
    let receiver = receive_hellos(key.clone(), port, sock);
    let responder = answer_mdns(key);
    tokio::select! {
        r = receiver => if let Err(e) = r { log(format!("hello receiver: {e}")); std::process::exit(1) },
        r = responder => if let Err(e) = r { log(format!("mDNS responder: {e}")); std::process::exit(1) },
        _ = tokio::signal::ctrl_c() => {}
    }
}

async fn ask(sock: &Path, line: &str) -> std::io::Result<String> {
    let mut stream = BufReader::new(UnixStream::connect(sock).await?);
    stream.get_mut().write_all(format!("{line}\n").as_bytes()).await?;
    let mut reply = String::new();
    stream.read_line(&mut reply).await?;
    Ok(reply.trim().to_owned())
}

/// `key` → `key <64 hex> <hello port>`.
async fn fetch_key(sock: &Path) -> std::io::Result<(Zeroizing<[u8; 32]>, u16)> {
    let reply = Zeroizing::new(ask(sock, "key").await?);
    let mut words = reply.split_whitespace();
    match (words.next(), words.next(), words.next()) {
        (Some("key"), Some(hex), Some(port)) => {
            let key = parse_hex32(hex).ok_or_else(|| std::io::Error::other("daemon sent a malformed key"))?;
            let port = port.parse().map_err(|_| std::io::Error::other("daemon sent a malformed port"))?;
            Ok((key, port))
        }
        (Some(other), ..) => Err(std::io::Error::other(format!("daemon says {other}"))),
        _ => Err(std::io::Error::other("empty reply")),
    }
}

fn parse_hex32(s: &str) -> Option<Zeroizing<[u8; 32]>> {
    if s.len() != 64 {
        return None;
    }
    let mut out = Zeroizing::new([0u8; 32]);
    for (i, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(out)
}

/// One packet, one decrypt, one line to the daemon. A packet that does not
/// authenticate is dropped without a word.
async fn receive_hellos(key: std::sync::Arc<Zeroizing<[u8; 32]>>, port: u16, sock: PathBuf) -> std::io::Result<()> {
    let socket = UdpSocket::bind(SocketAddr::from((Ipv4Addr::UNSPECIFIED, port))).await?;
    log(format!("listening for hellos on udp/{port}"));
    let mut buf = [0u8; 512];
    loop {
        let (n, from) = socket.recv_from(&mut buf).await?;
        let Ok(h) = hello::open(&key, &buf[..n]) else { continue };
        if h.ip.parse::<std::net::IpAddr>().is_err() {
            continue;
        }
        match ask(&sock, &format!("hello {} {} {}", h.ip, h.port, h.seq)).await {
            Ok(reply) => log(format!("hello from {from}: {}:{} seq {} → {reply}", h.ip, h.port, h.seq)),
            Err(e) => log(format!("could not reach the daemon: {e}")),
        }
    }
}

/// The mDNS socket: 5353 shared with whatever else listens there
/// (`SO_REUSEADDR` + `SO_REUSEPORT`), joined to the group on every interface.
fn mdns_socket() -> std::io::Result<UdpSocket> {
    use socket2::{Domain, Protocol, Socket, Type};
    let s = Socket::new(Domain::IPV4, Type::DGRAM, Some(Protocol::UDP))?;
    s.set_reuse_address(true)?;
    s.set_reuse_port(true)?;
    s.set_nonblocking(true)?;
    s.bind(&SocketAddr::from((Ipv4Addr::UNSPECIFIED, MDNS_PORT)).into())?;
    s.join_multicast_v4(&MDNS_GROUP, &Ipv4Addr::UNSPECIFIED)?;
    s.set_multicast_loop_v4(false)?;
    UdpSocket::from_std(s.into())
}

/// Our address as the querier sees it: the interface that routes to them.
fn address_towards(peer: Ipv4Addr) -> Option<Ipv4Addr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0").ok()?;
    probe.connect(SocketAddrV4::new(peer, 9)).ok()?;
    match probe.local_addr().ok()?.ip() {
        std::net::IpAddr::V4(ip) => Some(ip),
        _ => None,
    }
}

async fn answer_mdns(key: std::sync::Arc<Zeroizing<[u8; 32]>>) -> std::io::Result<()> {
    let socket = mdns_socket()?;
    log("answering mDNS for the rotating name");
    let mut buf = [0u8; 1500];
    loop {
        let (n, from) = socket.recv_from(&mut buf).await?;
        let SocketAddr::V4(from) = from else { continue };
        let Some(query) = dns::parse_query(&buf[..n]) else { continue };
        let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
        let ours: Vec<String> = mdns::labels_around(&key, now).iter().map(|l| format!("{l}.local")).collect();
        for q in &query.questions {
            if !(q.qtype == dns::TYPE_A || q.qtype == dns::TYPE_ANY) || !ours.contains(&q.name) {
                continue;
            }
            let Some(ip) = address_towards(*from.ip()) else { continue };
            let answer = dns::build_a_answer(query.id, &q.name, ip, RECORD_TTL);
            let to = if q.unicast { SocketAddr::V4(from) } else { SocketAddr::from((MDNS_GROUP, MDNS_PORT)) };
            match socket.send_to(&answer, to).await {
                Ok(_) => log(format!("answered {} for {from} with {ip} ({})", q.name, if q.unicast { "unicast" } else { "multicast" })),
                Err(e) => log(format!("mDNS answer failed: {e}")),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_three_names_match() {
        let key = [3u8; 32];
        let now = 1_790_500_000;
        let ours: Vec<String> = mdns::labels_around(&key, now).iter().map(|l| format!("{l}.local")).collect();
        assert_eq!(ours.len(), 3);
        assert!(ours.contains(&mdns::name_now(&key, now)));
        assert!(ours.contains(&mdns::name_now(&key, now - 86_400)));
        assert!(!ours.contains(&mdns::name_now(&key, now + 2 * 86_400)));
        assert!(!ours.contains(&mdns::name_now(&[4u8; 32], now)));
    }

    #[test]
    fn second_instance_is_refused_until_the_first_is_gone() {
        let dir = std::env::temp_dir().join(format!("bwphone-hello-lock-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let path = dir.join("hello.lock");
        let first = lock_single_instance(&path).unwrap().expect("nobody holds it yet");
        assert!(lock_single_instance(&path).unwrap().is_none());
        drop(first);
        assert!(lock_single_instance(&path).unwrap().is_some());
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn hex_parsing() {
        assert_eq!(*parse_hex32(&"ab".repeat(32)).unwrap(), [0xAB; 32]);
        assert!(parse_hex32(&"ab".repeat(31)).is_none());
        assert!(parse_hex32(&"zz".repeat(32)).is_none());
    }

    /// A stand-in daemon on a Unix socket: answers `key` and echoes hellos.
    async fn fake_daemon(sock: PathBuf, key_reply: &'static str) -> tokio::task::JoinHandle<Vec<String>> {
        let listener = tokio::net::UnixListener::bind(&sock).unwrap();
        tokio::spawn(async move {
            let mut seen = Vec::new();
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let mut stream = BufReader::new(stream);
                let mut line = String::new();
                stream.read_line(&mut line).await.unwrap();
                let line = line.trim().to_owned();
                let reply = if line == "key" { key_reply.to_owned() } else { "ok".to_owned() };
                stream.get_mut().write_all(format!("{reply}\n").as_bytes()).await.unwrap();
                seen.push(line);
            }
            seen
        })
    }

    #[tokio::test]
    async fn fetches_the_key_and_forwards_a_hello_as_text() {
        let dir = std::env::temp_dir().join(format!("bwphone-hello-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("hello.sock");
        let daemon = fake_daemon(sock.clone(), "key abababababababababababababababababababababababababababababababab 8732").await;

        let (key, port) = fetch_key(&sock).await.unwrap();
        assert_eq!(*key, [0xAB; 32]);
        assert_eq!(port, 8732);
        assert_eq!(ask(&sock, "hello 10.0.0.7 8731 9").await.unwrap(), "ok");
        assert_eq!(daemon.await.unwrap(), vec!["key", "hello 10.0.0.7 8731 9"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[tokio::test]
    async fn a_locked_wallet_is_an_error_to_retry() {
        let dir = std::env::temp_dir().join(format!("bwphone-hello-locked-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let sock = dir.join("hello.sock");
        let _daemon = fake_daemon(sock.clone(), "locked").await;
        let err = fetch_key(&sock).await.unwrap_err();
        assert!(err.to_string().contains("locked"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
