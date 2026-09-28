//! The control socket: one JSON line in, one JSON line out, from the CLI
//! (status, a dry-run unlock that prints a fingerprint and never a key, and
//! `bwphone hello`). `bwphone-hello` does not come here: it has its own
//! socket and plain-text protocol (`hellosock`), which reuses [`handle`] for
//! the address it hands in.

use std::{net::IpAddr, sync::Arc};

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt as _, AsyncRead, AsyncWrite, AsyncWriteExt as _, BufReader};

use crate::{
    Ctx,
    accounts::id_hex,
    secrets::SecretsError,
    serve::availability,
    unlock::{self, Outcome},
};

#[derive(Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "cmd", rename_all = "snake_case")]
pub enum ControlRequest {
    /// From `bwphone-hello`, already decrypted and authenticated.
    Hello { ip: IpAddr, port: u16, seq: u64 },
    Status,
    /// Runs a real unlock, emoji pick and fingerprint included, and
    /// answers with the user key's SHA-256. The key itself never leaves
    /// the daemon this way.
    Unlock { label: String },
    /// Forget the last hello `seq`. Whoever holds `hello_key` can send a
    /// hello with the largest possible `seq` and lock every real one out as
    /// stale; this is the way back, from the CLI only.
    ResetHello,
}

pub async fn serve_control<S: AsyncRead + AsyncWrite + Unpin>(stream: S, ctx: Arc<Ctx>) -> std::io::Result<()> {
    let mut stream = BufReader::new(stream);
    let mut line = String::new();
    if stream.read_line(&mut line).await? == 0 {
        return Ok(());
    }
    let reply = match serde_json::from_str::<ControlRequest>(&line) {
        Ok(request) => handle(&ctx, request).await,
        Err(e) => json!({"ok": false, "error": format!("bad request: {e}")}),
    };
    let mut out = serde_json::to_vec(&reply)?;
    out.push(b'\n');
    stream.get_mut().write_all(&out).await?;
    stream.get_mut().shutdown().await
}

pub async fn handle(ctx: &Ctx, request: ControlRequest) -> Value {
    match request {
        ControlRequest::Hello { ip, port, seq } => {
            let addr = (ip, port).into();
            {
                let mut pairing = ctx.pairing.lock().unwrap();
                let Some(p) = pairing.as_mut() else { return json!({"ok": false, "error": "not paired"}) };
                if seq <= p.last_hello_seq {
                    return json!({"ok": false, "error": "stale hello", "last_seq": p.last_hello_seq});
                }
                p.last_hello_seq = seq;
                p.last_address = Some(ip);
                p.last_port = Some(port);
                if let Some(path) = &ctx.pairing_path
                    && let Err(e) = p.save(path)
                {
                    tracing::warn!("could not save pairing.json: {e}");
                }
            }
            ctx.state.lock().unwrap().note_hello(addr);
            tracing::info!(%addr, seq, "phone hello");
            json!({"ok": true})
        }
        ControlRequest::Status => {
            let wallet = match ctx.secrets.noise_static().await {
                Ok(_) => "unlocked",
                Err(SecretsError::Locked) => "locked",
                Err(SecretsError::Missing(_)) => "missing",
                Err(_) => "error",
            };
            let (addr, reach) = {
                let s = ctx.state.lock().unwrap();
                (s.addr, s.last_reach_ok)
            };
            let mut accounts = Vec::new();
            for a in ctx.accounts.iter() {
                let status = availability(ctx, Some(a)).await;
                accounts.push(json!({
                    "label": a.label, "user_id": a.user_id, "id": id_hex(&a.id),
                    "available": status == bwphone_nm::msg::BiometricsStatus::Available,
                }));
            }
            json!({
                "ok": true,
                "paired": ctx.pairing.lock().unwrap().is_some(),
                "wallet": wallet,
                "phone": {"addr": addr.map(|a| a.to_string()), "last_reach_ok": reach},
                "queued": ctx.queue.len(),
                "accounts": accounts,
            })
        }
        ControlRequest::ResetHello => {
            let mut pairing = ctx.pairing.lock().unwrap();
            let Some(p) = pairing.as_mut() else { return json!({"ok": false, "error": "not paired"}) };
            p.last_hello_seq = 0;
            if let Some(path) = &ctx.pairing_path
                && let Err(e) = p.save(path)
            {
                tracing::warn!("could not save pairing.json: {e}");
            }
            json!({"ok": true})
        }
        ControlRequest::Unlock { label } => {
            let Some(account) = ctx.accounts.by_label(&label) else {
                return json!({"ok": false, "error": format!("no account labelled {label}")});
            };
            match unlock::request(ctx, account.id).await {
                Outcome::Key(key) => json!({"ok": true, "fingerprint": key.fingerprint()}),
                Outcome::Refused(reason) => json!({"ok": false, "reason": reason.as_str()}),
            }
        }
    }
}
