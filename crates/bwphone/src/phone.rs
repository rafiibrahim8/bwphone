//! The PC's side of one phone session: connect, Noise KK, one request,
//! then the two replies. The reach clock starts at the first Noise payload,
//! not at `connect()`: the kernel completes a TCP handshake into the backlog
//! even when the app is asleep.

use std::{net::SocketAddr, time::Duration};

use bwphone_transport::{
    PROTOCOL_VERSION, b64, emoji,
    msg::{Context, Request, RequestBody, Response, Status},
    noise::{self, Channel, ChannelError},
    random_id, unb64,
};
use bwphone_wrap::KWrap;
use tokio::{net::TcpStream, time::timeout};
use zeroize::Zeroize as _;

/// Bounded separately, so a black-holed SYN cannot eat the reach budget.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(3);
/// Handshake plus `prompt_posted`, from the first Noise payload.
pub const REACH_BUDGET: Duration = Duration::from_secs(5);
pub const PING_BUDGET: Duration = Duration::from_secs(2);
/// `enrol_begin` makes the phone generate an RSA-2048 key before it answers,
/// which in StrongBox can take several seconds on its own.
pub const ENROL_BEGIN_BUDGET: Duration = Duration::from_secs(30);

/// What identifies the paired phone, and what the request says about us.
#[derive(Debug, Clone)]
pub struct Phone {
    pub public: [u8; 32],
    pub pairing_id: [u8; 16],
    pub host: String,
}

#[derive(Debug, thiserror::Error)]
pub enum ReachFailure {
    #[error("connect: {0}")]
    Connect(std::io::Error),
    #[error("no answer within the reach budget")]
    Timeout,
    #[error("channel: {0}")]
    Channel(#[from] ChannelError),
    #[error("phone refused: {0:?}")]
    Refused(Status),
    #[error("protocol: {0}")]
    Protocol(&'static str),
}

/// The prompt is on the phone. Dropping this closes the session.
pub struct Reached {
    channel: Channel<TcpStream>,
    req_id: String,
    pub emoji: &'static str,
}

#[derive(Debug)]
pub enum Answer {
    KWrap(KWrap),
    Refused(Status),
    /// Our own deadline; a `K_wrap` arriving later is never read.
    TimedOut,
    Protocol(&'static str),
}

impl Phone {
    pub async fn reach(
        &self,
        private: &[u8; 32],
        addr: SocketAddr,
        account_id: &[u8; 16],
        rsa_ct: &[u8],
        expires_in_ms: u64,
    ) -> Result<Reached, ReachFailure> {
        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| ReachFailure::Timeout)?
            .map_err(ReachFailure::Connect)?;
        let _ = stream.set_nodelay(true);
        // Our half of the emoji derivation, committed before we see the phone's.
        let mut pc_nonce = [0u8; emoji::NONCE_LEN];
        rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut pc_nonce);
        let body = RequestBody::Unwrap {
            account: b64(account_id),
            rsa_ct: b64(rsa_ct),
            expires_in_ms,
            nonce: b64(&pc_nonce),
            context: Context { host: self.host.clone() },
        };
        let (channel, req_id, response) = timeout(REACH_BUDGET, self.exchange(stream, private, body))
            .await
            .map_err(|_| ReachFailure::Timeout)??;
        match response.status {
            Status::PromptPosted => {
                let phone_nonce: [u8; emoji::NONCE_LEN] = response
                    .nonce
                    .as_deref()
                    .and_then(|n| unb64(n).ok())
                    .and_then(|v| v.try_into().ok())
                    .ok_or(ReachFailure::Protocol("prompt_posted without a 32-byte nonce"))?;
                Ok(Reached { emoji: emoji::for_session(channel.handshake_hash(), &pc_nonce, &phone_nonce), channel, req_id })
            }
            status => Err(ReachFailure::Refused(status)),
        }
    }

    /// One request, one reply, for the enrollment messages (`enrol_begin`,
    /// `set_pin`): the phone answers at once or refuses.
    pub async fn request(&self, private: &[u8; 32], addr: SocketAddr, body: RequestBody) -> Result<Response, ReachFailure> {
        self.request_within(private, addr, body, REACH_BUDGET).await
    }

    /// [`Phone::request`] with its own budget for the whole exchange.
    pub async fn request_within(
        &self,
        private: &[u8; 32],
        addr: SocketAddr,
        body: RequestBody,
        budget: Duration,
    ) -> Result<Response, ReachFailure> {
        let stream = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr))
            .await
            .map_err(|_| ReachFailure::Timeout)?
            .map_err(ReachFailure::Connect)?;
        let (_, _, response) = timeout(budget, self.exchange(stream, private, body)).await.map_err(|_| ReachFailure::Timeout)??;
        Ok(response)
    }

    /// Reachability only; the phone shows nothing.
    pub async fn ping(&self, private: &[u8; 32], addr: SocketAddr) -> bool {
        let Ok(Ok(stream)) = timeout(CONNECT_TIMEOUT, TcpStream::connect(addr)).await else { return false };
        matches!(
            timeout(PING_BUDGET, self.exchange(stream, private, RequestBody::Ping)).await,
            Ok(Ok((_, _, Response { status: Status::Pong, .. })))
        )
    }

    async fn exchange(
        &self,
        stream: TcpStream,
        private: &[u8; 32],
        body: RequestBody,
    ) -> Result<(Channel<TcpStream>, String, Response), ReachFailure> {
        let mut channel = noise::kk_initiate(stream, private, &self.public, &self.pairing_id).await?;
        let req_id = b64(&random_id());
        channel.send_json(&Request::new(req_id.clone(), body)).await?;
        let response: Response = channel.recv_json().await?;
        if response.v != PROTOCOL_VERSION {
            return Err(ReachFailure::Protocol("wrong protocol version"));
        }
        if response.req_id != req_id {
            return Err(ReachFailure::Protocol("reply to a different request"));
        }
        Ok((channel, req_id, response))
    }
}

impl Reached {
    pub async fn answer(mut self, budget: Duration) -> Answer {
        let mut response: Response = match timeout(budget, self.channel.recv_json()).await {
            Err(_) => return Answer::TimedOut,
            Ok(Err(_)) => return Answer::Protocol("channel closed"),
            Ok(Ok(r)) => r,
        };
        if response.req_id != self.req_id {
            return Answer::Protocol("reply to a different request");
        }
        match response.status {
            Status::Ok => {
                // The base64 form is key material too; wipe it once decoded.
                let Some(mut text) = response.k_wrap.take() else { return Answer::Protocol("ok without K_wrap") };
                let decoded = unb64(&text);
                text.zeroize();
                let Ok(mut raw) = decoded else { return Answer::Protocol("K_wrap is not base64") };
                let k = KWrap::from_slice(&raw);
                raw.zeroize();
                k.map(Answer::KWrap).unwrap_or(Answer::Protocol("K_wrap is not 32 bytes"))
            }
            status => Answer::Refused(status),
        }
    }
}
