//! `bwphone pair`: one QR code, one `Noise_NKpsk0` handshake with the QR
//! token as the PSK, six words on both screens, and nothing committed until
//! both sides have sent and received `true`.
//!
//! Order on the wire, after the handshake: the phone sends `PairHello`; each
//! side shows the words, asks its person, sends its `PairConfirm`, then reads
//! the other's. Both send before reading, so neither waits on the other.
//!
//! The QR is a bearer credential while it is on screen, and X11 lets any
//! client capture the screen: keep the window short, and if pairing fails
//! unexpectedly, restart it rather than retrying.

use std::{
    net::{Ipv4Addr, SocketAddr},
    time::Duration,
};

use bwphone_transport::{
    DEFAULT_HELLO_PORT, PROTOCOL_VERSION, mdns,
    msg::{PairConfirm, PairHello},
    noise::{self, StaticKeypair},
    pairing::{self, QrPayload},
    unb64,
};
use rand::RngCore as _;
use tokio::{net::TcpListener, time::timeout};

use crate::{
    pairing::Pairing,
    paths::Paths,
    secrets::{self, Key32},
};

/// How long the QR stays valid: the phone must connect within this.
pub const PAIR_WINDOW: Duration = Duration::from_secs(120);
/// From accept to the phone's `PairHello`.
pub const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
/// For the two people to compare the words.
pub const CONFIRM_TIMEOUT: Duration = Duration::from_secs(180);

#[derive(Debug, thiserror::Error)]
pub enum PairError {
    #[error("already paired with {0}; pass --replace after revoking on the phone")]
    AlreadyPaired(String),
    #[error("no phone connected within {}s", PAIR_WINDOW.as_secs())]
    NoPhone,
    #[error("the phone did not finish the handshake in time")]
    HandshakeTimeout,
    #[error("channel: {0}")]
    Channel(#[from] noise::ChannelError),
    #[error("the phone's hello is malformed: {0}")]
    Hello(&'static str),
    #[error("not confirmed on {0}; nothing was stored")]
    NotConfirmed(&'static str),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Pairing(#[from] crate::pairing::PairingError),
    #[error("{0}")]
    Secrets(#[from] secrets::SecretsError),
}

/// The terminal, or a test.
pub trait Ui {
    fn show(&mut self, text: &str);
    fn confirm(&mut self, question: &str) -> bool;
}

/// What a successful pairing yields; the caller commits it.
pub struct PairOutcome {
    pub pairing: Pairing,
    pub noise_private: Key32,
    pub hello_key: Key32,
}

impl std::fmt::Debug for PairOutcome {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "PairOutcome({}, keys redacted)", self.pairing.device_label)
    }
}

pub fn qr_text(pc_pub: &[u8; 32], token: &[u8; 32], ip: Ipv4Addr, pair_port: u16, hello_port: u16) -> String {
    QrPayload { pc_pub: *pc_pub, token: *token, ip, pair_port, hello_port }.encode()
}

/// The QR as Unicode half-blocks for a terminal.
pub fn render_qr(text: &str) -> String {
    let code = qrcode::QrCode::new(text.as_bytes()).expect("73 bytes of base64url fit a QR code");
    code.render::<qrcode::render::unicode::Dense1x2>().dark_color(qrcode::render::unicode::Dense1x2::Light).light_color(qrcode::render::unicode::Dense1x2::Dark).build()
}

/// The address the phone can reach us at: the interface that would route
/// to the internet. No packet is sent.
pub fn lan_ip() -> std::io::Result<Ipv4Addr> {
    let probe = std::net::UdpSocket::bind("0.0.0.0:0")?;
    probe.connect("192.0.2.1:9")?;
    match probe.local_addr()?.ip() {
        std::net::IpAddr::V4(ip) => Ok(ip),
        std::net::IpAddr::V6(_) => Err(std::io::Error::other("no IPv4 route")),
    }
}

/// One pairing session on an already-bound listener, with a PC key and
/// token already shown to the phone. Returns only if both sides confirmed.
pub async fn pair_session(
    listener: TcpListener,
    pc: &StaticKeypair,
    token: &[u8; 32],
    ui: &mut dyn Ui,
) -> Result<PairOutcome, PairError> {
    let (stream, peer) = timeout(PAIR_WINDOW, listener.accept()).await.map_err(|_| PairError::NoPhone)??;
    let _ = stream.set_nodelay(true);
    let (mut channel, hello_bytes) = timeout(HANDSHAKE_TIMEOUT, async {
        let mut channel = noise::pair_respond(stream, &pc.private, token).await?;
        let hello_bytes = channel.recv().await?;
        Ok::<_, noise::ChannelError>((channel, hello_bytes))
    })
    .await
    .map_err(|_| PairError::HandshakeTimeout)??;

    let hello: PairHello = serde_json::from_slice(&hello_bytes).map_err(|_| PairError::Hello("not a PairHello"))?;
    if hello.v != PROTOCOL_VERSION {
        return Err(PairError::Hello("wrong protocol version"));
    }
    let phone_pub: [u8; 32] =
        unb64(&hello.x25519_pub).ok().and_then(|v| v.try_into().ok()).ok_or(PairError::Hello("x25519_pub is not 32 bytes"))?;

    // The words cover the phone's key: the transcript folds the PairHello in.
    let transcript = pairing::transcript(channel.handshake_hash(), &hello_bytes);
    let words = pairing::words(&transcript);
    ui.show(&format!("\nPhone: {} ({})\n\n    {}\n", hello.device_label, peer.ip(), words.join("  ")));
    let confirmed = ui.confirm("Do these six words match the phone's screen?");

    channel.send_json(&PairConfirm { v: PROTOCOL_VERSION, confirmed }).await?;
    let theirs: PairConfirm =
        timeout(CONFIRM_TIMEOUT, channel.recv_json()).await.map_err(|_| PairError::NotConfirmed("the phone (no answer)"))??;
    if !confirmed {
        return Err(PairError::NotConfirmed("this PC"));
    }
    if !theirs.confirmed {
        return Err(PairError::NotConfirmed("the phone"));
    }

    let now = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).map(|d| d.as_secs() as i64).unwrap_or(0);
    let mut pairing = Pairing::new(&phone_pub, &pairing::pairing_id(&transcript), &hello.device_label, hello.listen_port, &mdns::utc_date(now));
    pairing.last_address = Some(peer.ip());
    Ok(PairOutcome { pairing, noise_private: Key32::new(*pc.private), hello_key: Key32::new(*pairing::hello_key(&transcript)) })
}

pub struct PairOptions {
    pub ip: Option<Ipv4Addr>,
    pub pair_port: u16,
    pub hello_port: u16,
    pub replace: bool,
}

impl Default for PairOptions {
    fn default() -> Self {
        Self { ip: None, pair_port: 0, hello_port: DEFAULT_HELLO_PORT, replace: false }
    }
}

/// The whole command: refuse a second pairing, show the QR, run the
/// session, then write the two wallet items and `pairing.json`.
pub async fn run(paths: &Paths, opts: PairOptions, ui: &mut dyn Ui) -> Result<Pairing, PairError> {
    if let Some(existing) = Pairing::load(&paths.pairing())?
        && !opts.replace
    {
        return Err(PairError::AlreadyPaired(existing.device_label));
    }
    let ip = match opts.ip {
        Some(ip) => ip,
        None => lan_ip()?,
    };
    let listener = TcpListener::bind(SocketAddr::from((ip, opts.pair_port))).await?;
    let pair_port = listener.local_addr()?.port();

    let pc = StaticKeypair::generate()?;
    let mut token = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut token);

    let text = qr_text(&pc.public, &token, ip, pair_port, opts.hello_port);
    ui.show(&format!(
        "Scan this on the phone within {}s. Listening on {ip}:{pair_port}; hellos will arrive on port {}.\n\n{}\n\n{text}\n",
        PAIR_WINDOW.as_secs(),
        opts.hello_port,
        render_qr(&text)
    ));

    let mut outcome = pair_session(listener, &pc, &token, ui).await?;
    outcome.pairing.hello_port = opts.hello_port;

    // The Noise key goes straight into the wallet; it never touches a file.
    secrets::write_item(secrets::NOISE_STATIC, "bwphone noise static key", outcome.noise_private.as_bytes()).await?;
    secrets::write_item(secrets::HELLO, "bwphone hello key", outcome.hello_key.as_bytes()).await?;
    outcome.pairing.save(&paths.pairing())?;
    // Every existing blob was wrapped to keys the old pairing's phone held;
    // none opens under this one. Remove them so the daemon serves nothing
    // until a fresh enrollment has round-tripped against the new phone.
    let retired = match std::fs::remove_dir_all(paths.accounts()) {
        Ok(()) => true,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => false,
        Err(e) => return Err(e.into()),
    };
    ui.show(&format!(
        "Paired with {}.{} Next: enrol an account.",
        outcome.pairing.device_label,
        if retired { " Previously enrolled accounts were removed; enrol them again." } else { "" }
    ));
    Ok(outcome.pairing)
}

#[cfg(test)]
mod tests {
    use super::*;
    use bwphone_transport::b64;

    struct Script {
        answer: bool,
        shown: Vec<String>,
    }

    impl Ui for Script {
        fn show(&mut self, text: &str) {
            self.shown.push(text.to_owned());
        }
        fn confirm(&mut self, _: &str) -> bool {
            self.answer
        }
    }

    /// The phone's side of pairing, over a real TCP connection.
    async fn phone(addr: SocketAddr, pc_pub: [u8; 32], token: [u8; 32], confirm: bool) -> (StaticKeypair, [u8; 32], bool) {
        let phone = StaticKeypair::generate().unwrap();
        let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
        let mut ch = noise::pair_initiate(stream, &pc_pub, &token).await.unwrap();
        let hello = PairHello { v: PROTOCOL_VERSION, x25519_pub: b64(&phone.public), listen_port: 8731, device_label: "Pixel".into() };
        let hello_bytes = serde_json::to_vec(&hello).unwrap();
        ch.send(&hello_bytes).await.unwrap();
        let transcript = pairing::transcript(ch.handshake_hash(), &hello_bytes);
        ch.send_json(&PairConfirm { v: PROTOCOL_VERSION, confirmed: confirm }).await.unwrap();
        let theirs: PairConfirm = ch.recv_json().await.unwrap();
        (phone, transcript, theirs.confirmed)
    }

    #[tokio::test]
    async fn both_confirm_and_derive_the_same_secrets() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pc = StaticKeypair::generate().unwrap();
        let token = [3u8; 32];
        let phone_task = tokio::spawn(phone(addr, pc.public, token, true));
        let mut ui = Script { answer: true, shown: vec![] };
        let outcome = pair_session(listener, &pc, &token, &mut ui).await.unwrap();
        let (phone, transcript, pc_said) = phone_task.await.unwrap();
        assert!(pc_said);
        assert_eq!(outcome.pairing.phone_pub().unwrap(), phone.public);
        assert_eq!(outcome.pairing.pairing_id().unwrap(), pairing::pairing_id(&transcript));
        assert_eq!(outcome.hello_key.as_bytes(), &*pairing::hello_key(&transcript));
        assert_eq!(outcome.noise_private.as_bytes(), &*pc.private);
        assert_eq!(outcome.pairing.device_label, "Pixel");
        assert_eq!(outcome.pairing.phone_port, 8731);
        assert_eq!(outcome.pairing.last_address, Some(addr.ip()));
        let words = pairing::words(&transcript).join("  ");
        assert!(ui.shown.iter().any(|s| s.contains(&words)), "the words were shown");
    }

    #[tokio::test]
    async fn a_no_on_either_side_commits_nothing() {
        for (pc_says, phone_says, who) in [(false, true, "this PC"), (true, false, "the phone")] {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let addr = listener.local_addr().unwrap();
            let pc = StaticKeypair::generate().unwrap();
            let token = [4u8; 32];
            let phone_task = tokio::spawn(phone(addr, pc.public, token, phone_says));
            let mut ui = Script { answer: pc_says, shown: vec![] };
            let err = pair_session(listener, &pc, &token, &mut ui).await.unwrap_err();
            assert!(matches!(err, PairError::NotConfirmed(w) if w == who), "{err}");
            let (_, _, pc_said) = phone_task.await.unwrap();
            assert_eq!(pc_said, pc_says, "the phone learns the PC's answer either way");
        }
    }

    #[tokio::test]
    async fn wrong_token_never_reaches_the_words() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let pc = StaticKeypair::generate().unwrap();
        let pc_pub = pc.public;
        let attacker = tokio::spawn(async move {
            let stream = tokio::net::TcpStream::connect(addr).await.unwrap();
            noise::pair_initiate(stream, &pc_pub, &[9u8; 32]).await.is_err()
        });
        let mut ui = Script { answer: true, shown: vec![] };
        let err = pair_session(listener, &pc, &[3u8; 32], &mut ui).await.unwrap_err();
        assert!(matches!(err, PairError::Channel(_)), "{err}");
        assert!(ui.shown.is_empty());
        assert!(attacker.await.unwrap());
    }

    #[test]
    fn qr_renders_and_round_trips() {
        let text = qr_text(&[1; 32], &[2; 32], Ipv4Addr::new(192, 168, 1, 20), 40000, 8732);
        let q = QrPayload::decode(&text).unwrap();
        assert_eq!((q.pair_port, q.hello_port), (40000, 8732));
        let art = render_qr(&text);
        assert!(art.lines().count() > 20);
    }
}
