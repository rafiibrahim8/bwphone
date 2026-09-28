//! One browser's pipe, relayed by its proxy: the native-messaging
//! conversation, routed by userId.

use std::sync::Arc;

use bwphone_nm::{
    NmError, b64,
    frame::{read_frame, write_frame},
    msg::{BiometricsStatus, Command, Reply, Request},
    peer::{Event, Peer, now_ms},
};
use tokio::io::{AsyncRead, AsyncWrite};
use zeroize::Zeroizing;

use crate::{
    Ctx,
    accounts::Account,
    unlock::{self, Outcome, RETRY_AFTER},
};

/// What the extension is told when the phone path cannot work right now.
pub const UNAVAILABLE: BiometricsStatus = BiometricsStatus::HardwareUnavailable;
pub const NOT_ENROLLED: BiometricsStatus = BiometricsStatus::NotEnabledInConnectedDesktopApp;

/// Requests on one pipe are handled concurrently: an unlock can sit on
/// the phone for most of a minute, and the extension keeps asking for
/// status meanwhile. Replies go out through one writer, in completion order.
pub async fn serve_proxy<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(stream: S, ctx: Arc<Ctx>) -> std::io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = tokio::sync::mpsc::channel::<Zeroizing<Vec<u8>>>(32);
    let writer_task = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if write_frame(&mut writer, &bytes).await.is_err() {
                break;
            }
        }
    });
    let peer = Arc::new(tokio::sync::Mutex::new(Peer::new()));
    tx.send(Zeroizing::new(Peer::connected())).await.ok();

    while let Some(frame) = read_frame(&mut reader).await? {
        let event = peer.lock().await.receive(&frame, now_ms());
        match event {
            Ok(Event::Setup { reply, .. }) => {
                tx.send(Zeroizing::new(reply)).await.ok();
            }
            Ok(Event::Request(request)) => {
                let (ctx, peer, tx) = (ctx.clone(), peer.clone(), tx.clone());
                tokio::spawn(async move {
                    let reply = handle(&ctx, &request).await;
                    match peer.lock().await.reply(reply, now_ms()) {
                        Ok(bytes) => {
                            tx.send(bytes).await.ok();
                        }
                        Err(e) => tracing::warn!("could not seal reply: {e}"),
                    }
                });
            }
            Ok(Event::Stale(request)) => tracing::info!(?request.command, "stale request ignored"),
            Ok(Event::Unknown(command)) => tracing::info!(command, "unknown plaintext command ignored"),
            Ok(Event::NoChannel) | Err(NmError::Mac) => {
                if let Some(bytes) = peer.lock().await.invalidate(None) {
                    tx.send(Zeroizing::new(bytes)).await.ok();
                }
            }
            Err(e) => tracing::warn!("bad frame from browser: {e}"),
        }
    }
    drop(tx);
    let _ = writer_task.await;
    Ok(())
}

async fn handle(ctx: &Ctx, request: &Request) -> Reply {
    let account = request.user_id.as_deref().and_then(|u| ctx.accounts.by_user_id(u));
    match request.command {
        Command::GetBiometricsStatus => {
            let any = ctx.accounts.iter().next();
            Reply::status(request, availability(ctx, any).await)
        }
        Command::GetBiometricsStatusForUser => Reply::status(request, availability(ctx, account).await),
        Command::UnlockWithBiometricsForUser => {
            // An unenrolled userId gets false at once, never `wrongUserId`.
            let Some(account) = account else { return Reply::refused(request) };
            match unlock::request(ctx, account.id).await {
                Outcome::Key(key) => Reply::unlocked(request, Zeroizing::new(b64(key.as_bytes()))),
                Outcome::Refused(_) => Reply::refused(request),
            }
        }
        // The extension uses this for its "verify your identity" dialogs
        // (`user-verification.service.ts`), including passkey user
        // verification. Answering true here would make every such dialog a
        // no-op, so it is refused until a real phone round-trip exists for
        // it; the extension then falls back to the PIN or master password.
        Command::AuthenticateWithBiometrics => Reply::yes_no(request, false),
        Command::CanEnableBiometricUnlock => Reply::yes_no(request, account.is_some()),
        Command::Unknown => Reply::refused(request),
    }
}

/// Available only when the path can plausibly work: an enrolled account,
/// a readable Noise key, a known address, no invalidation, and the phone
/// not believed down. When it is believed down and enough time has passed,
/// one ping decides, so the state recovers without polling.
pub async fn availability(ctx: &Ctx, account: Option<&Account>) -> BiometricsStatus {
    let Some(account) = account else { return NOT_ENROLLED };
    let Ok(key) = ctx.secrets.noise_static().await else { return UNAVAILABLE };
    let (addr, retry) = {
        let state = ctx.state.lock().unwrap();
        if state.invalidated.contains(&account.id) {
            return UNAVAILABLE;
        }
        let Some(addr) = state.addr else { return UNAVAILABLE };
        if !state.believed_down() {
            return BiometricsStatus::Available;
        }
        (addr, state.last_attempt.is_none_or(|t| t.elapsed() >= RETRY_AFTER))
    };
    if !retry {
        return UNAVAILABLE;
    }
    let ok = ctx.phone.ping(key.as_bytes(), addr).await;
    ctx.state.lock().unwrap().note_reach(ok);
    if ok { BiometricsStatus::Available } else { UNAVAILABLE }
}
