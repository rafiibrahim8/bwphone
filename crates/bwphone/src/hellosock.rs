//! `$XDG_RUNTIME_DIR/bwphone-hello/hello.sock`: what `bwphone-hello` talks
//! to, and the only thing its sandbox lets it reach. Plain ASCII lines, so
//! the hello process needs no JSON, no D-Bus and no wallet — it gets its one
//! key from here.
//!
//! ```text
//! → key                          ← key <64 hex> <hello port>   |  locked  |  missing
//! → hello <ip> <port> <seq>      ← ok  |  stale  |  unpaired  |  error <why>
//! ```
//!
//! A compromised hello process can therefore do exactly one thing to the
//! daemon: tell it a wrong address for the phone, which makes the next Noise
//! handshake fail closed.

use std::sync::Arc;

use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncWrite, AsyncWriteExt as _, BufReader};
use zeroize::Zeroizing;

use crate::{
    Ctx,
    control::{self, ControlRequest},
    secrets::SecretsError,
};

pub async fn serve_hello_socket<S: AsyncRead + AsyncWrite + Unpin>(stream: S, ctx: Arc<Ctx>) -> std::io::Result<()> {
    let mut stream = BufReader::new(stream);
    let mut line = String::new();
    loop {
        line.clear();
        if stream.read_line(&mut line).await? == 0 {
            return Ok(());
        }
        // The `key` reply carries the hello key in hex; the buffer is wiped after the write.
        let mut reply = Zeroizing::new(handle_line(&ctx, line.trim()).await);
        reply.push('\n');
        stream.get_mut().write_all(reply.as_bytes()).await?;
    }
}

pub async fn handle_line(ctx: &Ctx, line: &str) -> String {
    // Callers that keep the returned string wrap it in `Zeroizing`; see `serve_hello_socket`.
    let mut words = line.split_whitespace();
    match (words.next(), words.next(), words.next(), words.next(), words.next()) {
        (Some("key"), None, ..) => match ctx.secrets.hello_key().await {
            Ok(k) => {
                let port = ctx.pairing.lock().unwrap().as_ref().map(|p| p.hello_port).unwrap_or(bwphone_transport::DEFAULT_HELLO_PORT);
                format!("key {} {port}", hex(k.as_bytes()))
            }
            Err(SecretsError::Locked) => "locked".into(),
            Err(SecretsError::Missing(_)) => "missing".into(),
            Err(e) => format!("error {e}"),
        },
        (Some("hello"), Some(ip), Some(port), Some(seq), None) => {
            let (Ok(ip), Ok(port), Ok(seq)) = (ip.parse(), port.parse(), seq.parse()) else {
                return "error bad hello".into();
            };
            let reply = control::handle(ctx, ControlRequest::Hello { ip, port, seq }).await;
            if reply["ok"] == true {
                "ok".into()
            } else if reply["error"] == "stale hello" {
                "stale".into()
            } else if reply["error"] == "not paired" {
                "unpaired".into()
            } else {
                format!("error {}", reply["error"].as_str().unwrap_or("?"))
            }
        }
        _ => "error unknown command".into(),
    }
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        accounts::Accounts,
        notify::Notifier,
        pairing::Pairing,
        phone::Phone,
        secrets::Secrets,
        unlock::{PhoneState, Queue},
    };
    use std::sync::Mutex;

    fn ctx(hello: Option<[u8; 32]>, paired: bool) -> Arc<Ctx> {
        let secrets = match hello {
            Some(h) => Secrets::fixed_with_hello([1; 32], h),
            None => Secrets::fixed([1; 32]),
        };
        Arc::new(Ctx {
            accounts: Accounts::default(),
            phone: Phone { public: [0; 32], pairing_id: [0; 16], host: "t".into() },
            state: Mutex::new(PhoneState::default()),
            secrets,
            notifier: Notifier::Silent,
            queue: Queue::default(),
            pairing: Mutex::new(paired.then(|| Pairing::new(&[2; 32], &[3; 16], "Pixel", 8731, "today"))),
            pairing_path: None,
        })
    }

    #[tokio::test]
    async fn key_hello_and_errors_over_one_connection() {
        let ctx = ctx(Some([0xAB; 32]), true);
        let (mine, theirs) = tokio::io::duplex(1024);
        tokio::spawn(serve_hello_socket(theirs, ctx.clone()));
        let mut mine = BufReader::new(mine);
        let mut ask = async |line: &str| {
            mine.get_mut().write_all(format!("{line}\n").as_bytes()).await.unwrap();
            let mut reply = String::new();
            mine.read_line(&mut reply).await.unwrap();
            reply.trim().to_owned()
        };
        assert_eq!(ask("key").await, format!("key {} 8732", "ab".repeat(32)));
        assert_eq!(ask("hello 10.0.0.7 8731 5").await, "ok");
        assert_eq!(ctx.state.lock().unwrap().addr, Some("10.0.0.7:8731".parse().unwrap()));
        assert_eq!(ask("hello 10.0.0.7 8731 5").await, "stale");
        assert_eq!(ask("hello 10.0.0.7 nope 6").await, "error bad hello");
        assert_eq!(ask("unlock Work").await, "error unknown command", "nothing but key and hello");
        assert_eq!(ask("key extra").await, "error unknown command");
    }

    #[tokio::test]
    async fn no_key_and_no_pairing() {
        assert_eq!(handle_line(&ctx(None, false), "key").await, "missing");
        assert_eq!(handle_line(&ctx(Some([1; 32]), false), "hello 10.0.0.7 8731 1").await, "unpaired");
    }
}
