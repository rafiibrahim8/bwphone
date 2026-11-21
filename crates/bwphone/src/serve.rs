//! One browser's pipe, relayed by its proxy, routed by userId. A pipe
//! carries one of two protocols, told apart frame by frame: the legacy
//! native-messaging commands (`bwphone-nm`), or Bitwarden's SDK IPC
//! (`bwphone-ipc`), which the extension uses for biometrics instead when
//! the server-side `biometrics-sdk-ipc` flag is on.

use std::{sync::Arc, time::Duration};

use bwphone_ipc::{
    envelope::Us,
    peer::{Event as IpcEvent, Peer as IpcPeer},
    rpc::{CallId, Request as IpcRequest, Response as IpcResponse, Status as IpcStatus},
};
use bwphone_nm::{
    NmError, b64,
    frame::{read_frame, write_frame},
    msg::{BiometricsStatus, Command, Reply, Request},
    peer::{Event, Peer, now_ms},
};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::{Mutex as AsyncMutex, mpsc},
    task::JoinSet,
};
use zeroize::Zeroizing;

use crate::{
    Ctx,
    accounts::Account,
    unlock::{self, Outcome, RETRY_AFTER},
};

/// What the extension is told when the phone path cannot work right now.
pub const UNAVAILABLE: BiometricsStatus = BiometricsStatus::HardwareUnavailable;
pub const NOT_ENROLLED: BiometricsStatus = BiometricsStatus::NotEnabledInConnectedDesktopApp;

/// Over SDK IPC the extension gives a status query 500 ms
/// (`BIOMETRICS_NO_INTERACTION_TIMEOUT`), a Noise handshake included, and
/// shows "desktop disconnected" past it. The answer must come from what is
/// already known; slower work carries on in the background. 400 ms leaves
/// 100 ms for the handshake round-trip and the proxy hops, which take a
/// few milliseconds on a local pipe.
pub const STATUS_BUDGET: Duration = Duration::from_millis(400);

/// Requests on one pipe are handled concurrently: an unlock can sit on
/// the phone for most of a minute, and the extension keeps asking for
/// status meanwhile. Replies go out through one writer, in completion order.
///
/// When the pipe closes (the browser idled its service worker out, or
/// quit), the requests still in flight are aborted: nobody is left to read
/// their answers, and an unlock abandoned this way leaves the queue, or
/// takes its prompt down, instead of asking the phone for nothing.
pub async fn serve_proxy<S: AsyncRead + AsyncWrite + Unpin + Send + 'static>(stream: S, ctx: Arc<Ctx>) -> std::io::Result<()> {
    let (mut reader, mut writer) = tokio::io::split(stream);
    let (tx, mut rx) = mpsc::channel::<Zeroizing<Vec<u8>>>(32);
    let writer_task = tokio::spawn(async move {
        while let Some(bytes) = rx.recv().await {
            if write_frame(&mut writer, &bytes).await.is_err() {
                break;
            }
        }
    });
    let peer = Arc::new(tokio::sync::Mutex::new(Peer::new()));
    tx.send(Zeroizing::new(Peer::connected())).await.ok();
    // Dropped with this function, on a clean end or an error: that aborts every request in it.
    let mut requests = JoinSet::new();
    // Created on the first SDK IPC frame; the extension opens a separate pipe for it.
    let mut ipc: Option<Arc<AsyncMutex<IpcPeer>>> = None;

    while let Some(frame) = read_frame(&mut reader).await? {
        while requests.try_join_next().is_some() {}
        if bwphone_ipc::is_ipc(&frame) {
            let ipc = ipc.get_or_insert_with(|| Arc::new(AsyncMutex::new(IpcPeer::new()))).clone();
            on_ipc_frame(&frame, ipc, &ctx, &tx, &mut requests).await;
            continue;
        }
        let event = peer.lock().await.receive(&frame, now_ms());
        match event {
            Ok(Event::Setup { reply, .. }) => {
                tx.send(Zeroizing::new(reply)).await.ok();
            }
            Ok(Event::Request(request)) => {
                let (ctx, peer, tx) = (ctx.clone(), peer.clone(), tx.clone());
                requests.spawn(async move {
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
    // The browser is gone: abort what is still in flight, and wait for it to let go of the writer.
    requests.shutdown().await;
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

/// One SDK IPC frame. Handshakes and invalidations are answered at once,
/// queued before the peer's lock is released, so no answer sealed under a
/// new session can overtake the finish that creates it. Requests run
/// concurrently, like the legacy ones, and each answer is sealed and
/// queued under the same lock, so frames leave in nonce order.
async fn on_ipc_frame(
    frame: &[u8],
    ipc: Arc<AsyncMutex<IpcPeer>>,
    ctx: &Arc<Ctx>,
    tx: &mpsc::Sender<Zeroizing<Vec<u8>>>,
    requests: &mut JoinSet<()>,
) {
    let mut peer = ipc.lock().await;
    let event = peer.receive(frame);
    if let Ok(IpcEvent::Send(bytes)) = event {
        tx.send(Zeroizing::new(bytes)).await.ok();
        return;
    }
    drop(peer);
    match event {
        Ok(IpcEvent::Send(_)) => unreachable!("sent above"),
        Ok(IpcEvent::Call { to, id, request }) => {
            let (ctx, tx) = (ctx.clone(), tx.clone());
            requests.spawn(async move {
                let response = handle_ipc(&ctx, &request).await;
                answer_ipc(&ipc, &tx, to, &id, &response).await;
            });
        }
        Ok(IpcEvent::Ignored(why)) => tracing::debug!(why, "ipc frame ignored"),
        Err(e) => tracing::info!("ipc frame dropped: {e}"),
    }
}

async fn answer_ipc(ipc: &AsyncMutex<IpcPeer>, tx: &mpsc::Sender<Zeroizing<Vec<u8>>>, to: Us, id: &CallId, response: &IpcResponse) {
    let mut peer = ipc.lock().await;
    match peer.answer(to, id, response) {
        Ok(bytes) => {
            tx.send(Zeroizing::new(bytes)).await.ok();
        }
        Err(e) => tracing::info!(request = id.request_type, "ipc answer dropped: {e}"),
    }
}

/// The desktop app's biometrics handlers, over SDK IPC. Same engine and
/// same answers as the legacy commands.
async fn handle_ipc(ctx: &Arc<Ctx>, request: &IpcRequest) -> IpcResponse {
    match request {
        IpcRequest::Discover => IpcResponse::Discover { version: format!("bwphone {}", env!("CARGO_PKG_VERSION")) },
        IpcRequest::GetBiometricsStatus { user_id } => {
            let account = ctx.accounts.by_user_id(user_id).map(|a| a.id);
            let status = match availability_within(ctx, account, STATUS_BUDGET).await {
                BiometricsStatus::Available => IpcStatus::Available,
                NOT_ENROLLED => IpcStatus::NotEnabled,
                _ => IpcStatus::HardwareUnavailable,
            };
            IpcResponse::Status(status)
        }
        IpcRequest::UnlockBiometrics { user_id } => {
            // An unenrolled userId gets no key at once; the phone is not asked.
            let Some(account) = ctx.accounts.by_user_id(user_id) else { return IpcResponse::Unlock(None) };
            match unlock::request(ctx, account.id).await {
                Outcome::Key(key) => IpcResponse::Unlock(Some(Zeroizing::new(b64(key.as_bytes())))),
                Outcome::Refused(_) => IpcResponse::Unlock(None),
            }
        }
        // As `authenticateWithBiometrics`: refused until a real phone
        // round-trip exists, so the extension falls back to PIN or password.
        IpcRequest::AuthenticateBiometrics => IpcResponse::Bool(false),
        IpcRequest::Unknown => IpcResponse::NoHandlerFound,
        IpcRequest::Malformed => IpcResponse::RequestDeserialization,
    }
}

/// [`availability`] within `budget`. The check runs on its own task: past
/// the budget the answer is unavailable, and the check (a cold wallet
/// read, a recovery ping) still finishes and updates the state the next
/// query reads.
pub async fn availability_within(ctx: &Arc<Ctx>, account_id: Option<[u8; 16]>, budget: Duration) -> BiometricsStatus {
    let ctx = ctx.clone();
    let check = tokio::spawn(async move {
        let account = account_id.and_then(|id| ctx.accounts.by_id(&id));
        availability(&ctx, account).await
    });
    match tokio::time::timeout(budget, check).await {
        Ok(Ok(status)) => status,
        _ => UNAVAILABLE,
    }
}

/// Available only when the path can plausibly work: an enrolled account,
/// a readable Noise key, a known address, no invalidation, and the phone
/// not believed down. When it is believed down and enough time has passed,
/// one ping decides, so the state recovers without polling. Only one such
/// ping runs at a time; queries meanwhile wait for its result. A ping's
/// result is recorded only if no hello or reach happened while it ran, so
/// a ping to an address the phone has left cannot mark it down.
pub async fn availability(ctx: &Ctx, account: Option<&Account>) -> BiometricsStatus {
    let Some(account) = account else { return NOT_ENROLLED };
    let Ok(key) = ctx.secrets.noise_static().await else { return UNAVAILABLE };
    enum Next {
        Ping(std::net::SocketAddr, u64, tokio::sync::watch::Sender<Option<bool>>),
        Wait(tokio::sync::watch::Receiver<Option<bool>>),
    }
    let next = {
        let mut state = ctx.state.lock().unwrap();
        if state.invalidated.contains(&account.id) {
            return UNAVAILABLE;
        }
        let Some(addr) = state.addr else { return UNAVAILABLE };
        if !state.believed_down() {
            return BiometricsStatus::Available;
        }
        if let Some(rx) = &state.ping {
            Next::Wait(rx.clone())
        } else {
            if state.last_attempt.is_some_and(|t| t.elapsed() < RETRY_AFTER) {
                return UNAVAILABLE;
            }
            let (tx, rx) = tokio::sync::watch::channel(None);
            state.ping = Some(rx);
            Next::Ping(addr, state.generation, tx)
        }
    };
    let ok = match next {
        // The pinger went away without an answer (its pipe closed): unavailable.
        Next::Wait(mut rx) => rx.wait_for(Option::is_some).await.ok().and_then(|v| *v).unwrap_or(false),
        Next::Ping(addr, generation, tx) => {
            // Cleared however the ping ends, including when this future is dropped.
            struct Pinging<'a>(&'a Ctx);
            impl Drop for Pinging<'_> {
                fn drop(&mut self) {
                    if let Ok(mut state) = self.0.state.lock() {
                        state.ping = None;
                    }
                }
            }
            let _pinging = Pinging(ctx);
            let reached = ctx.phone.ping(key.as_bytes(), addr).await;
            let ok = {
                let mut state = ctx.state.lock().unwrap();
                if state.generation == generation {
                    state.note_reach(reached);
                    reached
                } else {
                    // A hello or a reach came in meanwhile: it is the fresher word.
                    state.addr.is_some() && !state.believed_down()
                }
            };
            tx.send_replace(Some(ok));
            ok
        }
    };
    if ok { BiometricsStatus::Available } else { UNAVAILABLE }
}
