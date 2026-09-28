//! The unlock engine: one queue, one phone session at a time, the two-phase
//! budget. Every failure before the prompt is on the phone returns within
//! the reach budget; the only long wait is the one where it already is.

use std::{
    collections::{HashSet, VecDeque},
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use bwphone_transport::msg::Status;
use bwphone_wrap::UserKey;
use tokio::sync::{Notify, oneshot};

use crate::{
    Ctx,
    phone::{Answer, REACH_BUDGET, ReachFailure},
};

/// The extension abandons a request after this.
pub const EXTENSION_TIMEOUT: Duration = Duration::from_secs(60);
/// The most a person gets, pocket to fingerprint: 5 + 45 + 10 is the
/// extension's 60 s exactly.
pub const HUMAN_MAX: Duration = Duration::from_secs(45);
/// Left for the GCM open, the reply and scheduling jitter before the
/// extension's 60 s cutoff. The spec's figure.
pub const HEADROOM: Duration = Duration::from_secs(10);
/// A queued request that would get less than this is refused at once.
pub const MIN_HUMAN: Duration = Duration::from_secs(15);
/// After a failed reach, how long before a status query tries a ping.
pub const RETRY_AFTER: Duration = Duration::from_secs(30);

pub struct Job {
    pub account_id: [u8; 16],
    pub arrived: Instant,
    pub reply: oneshot::Sender<Outcome>,
}

#[derive(Debug, Clone)]
pub enum Outcome {
    Key(Arc<UserKey>),
    Refused(Reason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Reason {
    NoAccount,
    /// No hello yet and nothing in `pairing.json`.
    NoAddress,
    WalletLocked,
    /// Queued too long behind other requests.
    TooLate,
    Unreachable,
    /// Someone else's request is on the phone.
    Busy,
    /// The phone refused before any prompt.
    PhoneRefused(Status),
    Denied,
    /// None of these: someone else's prompt was on the phone.
    Rejected,
    Expired,
    UsePassword,
    /// The blob failed authentication under the returned `K_wrap`.
    Tampered,
    /// Whoever asked went away (the browser closed its pipe) and nobody
    /// else is waiting for this account.
    Abandoned,
    /// The account's Keystore key is gone; re-enrol.
    Invalidated,
}

impl Reason {
    pub fn as_str(&self) -> String {
        match self {
            Self::PhoneRefused(s) => format!("phone_refused:{}", serde_json::to_value(s).unwrap().as_str().unwrap_or("?")),
            other => format!("{other:?}").to_lowercase(),
        }
    }
}

/// What the daemon knows about the phone right now.
#[derive(Debug, Default)]
pub struct PhoneState {
    pub addr: Option<SocketAddr>,
    pub last_reach_ok: Option<bool>,
    pub last_attempt: Option<Instant>,
    pub invalidated: HashSet<[u8; 16]>,
}

impl PhoneState {
    pub fn believed_down(&self) -> bool {
        self.last_reach_ok == Some(false)
    }

    pub fn note_reach(&mut self, ok: bool) {
        self.last_reach_ok = Some(ok);
        self.last_attempt = Some(Instant::now());
    }

    pub fn note_hello(&mut self, addr: SocketAddr) {
        self.addr = Some(addr);
        self.last_reach_ok = None;
    }
}

#[derive(Default)]
pub struct Queue {
    jobs: Mutex<VecDeque<Job>>,
    wake: Notify,
}

impl Queue {
    pub fn push(&self, job: Job) {
        self.jobs.lock().unwrap().push_back(job);
        self.wake.notify_one();
    }

    async fn pop(&self) -> Job {
        loop {
            if let Some(job) = self.jobs.lock().unwrap().pop_front() {
                return job;
            }
            self.wake.notified().await;
        }
    }

    /// Someone still waiting for this account, behind the job being run.
    fn has_waiting(&self, account_id: &[u8; 16]) -> bool {
        self.jobs.lock().unwrap().iter().any(|j| j.account_id == *account_id && !j.reply.is_closed())
    }

    /// Everything waiting for the same account: two browsers share one answer.
    fn drain_account(&self, account_id: &[u8; 16]) -> Vec<Job> {
        let mut jobs = self.jobs.lock().unwrap();
        let (same, rest): (VecDeque<_>, VecDeque<_>) = jobs.drain(..).partition(|j| j.account_id == *account_id);
        *jobs = rest;
        same.into()
    }

    pub fn len(&self) -> usize {
        self.jobs.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// Ask for an unlock and wait for the answer.
pub async fn request(ctx: &Ctx, account_id: [u8; 16]) -> Outcome {
    let (tx, rx) = oneshot::channel();
    ctx.queue.push(Job { account_id, arrived: Instant::now(), reply: tx });
    rx.await.unwrap_or(Outcome::Refused(Reason::Unreachable))
}

pub async fn worker(ctx: Arc<Ctx>) {
    loop {
        let mut job = ctx.queue.pop().await;
        // The browser left while this sat in the queue: do not ask the phone for nobody.
        if job.reply.is_closed() {
            tracing::info!(account = %crate::accounts::id_hex(&job.account_id), "unlock abandoned before it started");
            continue;
        }
        let outcome = run(&ctx, &mut job).await;
        if let Outcome::Key(key) = &outcome {
            for other in ctx.queue.drain_account(&job.account_id) {
                if other.reply.is_closed() {
                    continue;
                }
                let outcome = if other.arrived.elapsed() + HEADROOM < EXTENSION_TIMEOUT {
                    Outcome::Key(key.clone())
                } else {
                    Outcome::Refused(Reason::TooLate)
                };
                let _ = other.reply.send(outcome);
            }
        }
        tracing::info!(account = %crate::accounts::id_hex(&job.account_id), outcome = ?outcome_name(&outcome), "unlock finished");
        let _ = job.reply.send(outcome);
    }
}

fn outcome_name(o: &Outcome) -> String {
    match o {
        Outcome::Key(_) => "ok".into(),
        Outcome::Refused(r) => r.as_str(),
    }
}

/// How the human phase ended.
enum End {
    Answer(Answer),
    UsePassword,
    Abandoned,
}

async fn run(ctx: &Ctx, job: &mut Job) -> Outcome {
    let refused = |r| Outcome::Refused(r);
    let Some(account) = ctx.accounts.by_id(&job.account_id) else { return refused(Reason::NoAccount) };

    let remaining = EXTENSION_TIMEOUT.saturating_sub(job.arrived.elapsed());
    let human = remaining.saturating_sub(REACH_BUDGET + HEADROOM).min(HUMAN_MAX);
    if human < MIN_HUMAN {
        return refused(Reason::TooLate);
    }

    let addr = {
        let state = ctx.state.lock().unwrap();
        if state.invalidated.contains(&account.id) {
            return refused(Reason::Invalidated);
        }
        match state.addr {
            Some(a) => a,
            None => return refused(Reason::NoAddress),
        }
    };
    let Ok(key) = ctx.secrets.noise_static().await else { return refused(Reason::WalletLocked) };

    let reached = match ctx
        .phone
        .reach(key.as_bytes(), addr, &account.id, account.blob.rsa_ct(), human.as_millis() as u64)
        .await
    {
        Ok(r) => {
            ctx.state.lock().unwrap().note_reach(true);
            r
        }
        Err(ReachFailure::Refused(Status::Busy)) => {
            ctx.state.lock().unwrap().note_reach(true);
            ctx.notifier
                .warn(
                    "Another unlock request is waiting on your phone",
                    "The daemon did not send it. If it wasn't you, deny it and press Revoke.",
                )
                .await;
            return refused(Reason::Busy);
        }
        Err(ReachFailure::Refused(Status::RateLimited)) => {
            ctx.state.lock().unwrap().note_reach(true);
            // Refused before any prompt, so the phone shows nothing: say it here.
            ctx.notifier
                .warn(
                    "Your phone refused: too many unlock requests in the last hour",
                    "Unless you have unlocked that often yourself, someone else has been asking. Press Revoke on the phone. The limits are in BW Phone's settings.",
                )
                .await;
            return refused(Reason::PhoneRefused(Status::RateLimited));
        }
        Err(ReachFailure::Refused(Status::Invalidated)) => {
            let mut state = ctx.state.lock().unwrap();
            state.note_reach(true);
            state.invalidated.insert(account.id);
            return refused(Reason::Invalidated);
        }
        Err(ReachFailure::Refused(status)) => {
            ctx.state.lock().unwrap().note_reach(true);
            return refused(Reason::PhoneRefused(status));
        }
        Err(e) => {
            tracing::info!("phone not reached: {e}");
            ctx.state.lock().unwrap().note_reach(false);
            return refused(Reason::Unreachable);
        }
    };

    let mut prompt = ctx.notifier.unlock_prompt(&account.label, reached.emoji).await;
    let answer = reached.answer(human + Duration::from_secs(1));
    tokio::pin!(answer);
    // If the browser that asked goes away, its prompt comes down (dropping the
    // session tells the phone), unless another request for this account is
    // queued behind it and would take the same answer.
    let mut asker_gone = false;
    let end = loop {
        tokio::select! {
            answer = &mut answer => break End::Answer(answer),
            _ = prompt.use_password() => break End::UsePassword,
            _ = job.reply.closed(), if !asker_gone => {
                if !ctx.queue.has_waiting(&account.id) {
                    break End::Abandoned;
                }
                asker_gone = true;
            }
        }
    };
    prompt.close().await;

    match end {
        End::UsePassword => refused(Reason::UsePassword),
        End::Abandoned => refused(Reason::Abandoned),
        End::Answer(answer) => settle(ctx, account, answer).await,
    }
}

/// The phone's final answer to a prompt that was shown.
async fn settle(ctx: &Ctx, account: &crate::accounts::Account, answer: Answer) -> Outcome {
    let refused = |r| Outcome::Refused(r);
    match answer {
        Answer::KWrap(k_wrap) => match bwphone_wrap::unwrap(&account.blob, &k_wrap) {
            Ok(user_key) => Outcome::Key(Arc::new(user_key)),
            Err(_) => {
                ctx.notifier
                    .warn("vault.blob failed authentication", &format!("The blob for {} did not open under the key the phone returned. It may have been altered.", account.label))
                    .await;
                refused(Reason::Tampered)
            }
        },
        Answer::Refused(Status::Rejected) => {
            ctx.notifier
                .warn(
                    "Someone else asked your phone to unlock",
                    "You tapped None of these. If that request wasn't yours, press Revoke on the phone.",
                )
                .await;
            refused(Reason::Rejected)
        }
        Answer::Refused(Status::Denied) => refused(Reason::Denied),
        Answer::Refused(Status::Expired) | Answer::TimedOut => refused(Reason::Expired),
        Answer::Refused(Status::Invalidated) => {
            ctx.state.lock().unwrap().invalidated.insert(account.id);
            refused(Reason::Invalidated)
        }
        Answer::Refused(status) => refused(Reason::PhoneRefused(status)),
        Answer::Protocol(what) => {
            tracing::warn!("phone session broke after the prompt: {what}");
            refused(Reason::Unreachable)
        }
    }
}
