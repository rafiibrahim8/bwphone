//! A phone with no Android in it. It links the same transport crate, holds
//! each account's RSA key in memory and answers without a fingerprint, but
//! it enforces every rule the real phone enforces: the write-once pin
//! (refused without a prompt), one request in flight, the deadline, the
//! emoji pick, `enrol_begin` only while the Enrol screen is open, and
//! silence before a valid request.
//!
//! The person holding it is a closure: given the prompt, it decides.

use std::{
    collections::HashMap,
    future::Future,
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use bwphone_transport::{
    PROTOCOL_VERSION, b64, emoji,
    msg::{Request, RequestBody, Response, Status},
    noise::{self, StaticKeypair},
    unb64,
};
use bwphone_wrap::{
    RSA_CT_LEN,
    phone::{self, Pin as CtPin},
    rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::DecodePrivateKey as _, pkcs8::EncodePublicKey as _},
};
use tokio::{
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::timeout,
};

/// A connection that has not finished the handshake and sent its request
/// by then is dropped, silently.
pub const PRE_AUTH_TIMEOUT: Duration = Duration::from_secs(5);

pub struct Account {
    pub label: String,
    pub private: RsaPrivateKey,
    pub pin: Option<CtPin>,
    pub unlocks: u32,
}

/// What the person sees on the phone's screen.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Prompt {
    pub account_id: [u8; 16],
    pub label: String,
    /// The real one, derived from the handshake hash.
    pub emoji: &'static str,
    /// The five on screen, the real one among them, in random order.
    pub choices: [&'static str; emoji::CHOICES],
    pub host: String,
    pub expires_in_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// The right emoji, then a fingerprint.
    Approve,
    /// Dismissed the prompt.
    Deny,
    /// Tapped one of the decoys.
    WrongEmoji,
    /// Tapped None of these.
    NoneOfThese,
    /// Never answers; the deadline runs out.
    Ignore,
}

pub type Person = Arc<dyn Fn(Prompt) -> Pin<Box<dyn Future<Output = Decision> + Send>> + Send + Sync>;

pub fn always(decision: Decision) -> Person {
    Arc::new(move |_| Box::pin(async move { decision }))
}

pub fn after(delay: Duration, decision: Decision) -> Person {
    Arc::new(move |_| {
        Box::pin(async move {
            tokio::time::sleep(delay).await;
            decision
        })
    })
}

/// Everything the phone did, for tests to assert on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Event {
    Pong,
    /// Refused before any prompt.
    Refused { account: Option<[u8; 16]>, status: Status },
    Prompted(Prompt),
    Answered { account: [u8; 16], decision: Decision, status: Status },
    Enrolled([u8; 16]),
    Pinned([u8; 16]),
}

pub struct FakePhone {
    keys: StaticKeypair,
    pc_pub: [u8; 32],
    pairing_id: [u8; 16],
    accounts: Mutex<HashMap<[u8; 16], Account>>,
    enrol_open: AtomicBool,
    busy: AtomicBool,
    person: Person,
    /// A key to hand out at the next `enrol_begin`, so tests need not
    /// generate RSA-2048 in a debug build.
    next_enrol_key: Mutex<Option<RsaPrivateKey>>,
    /// Refuse the next unwrap with this status after the pin check, as the
    /// real phone does for limits the fake does not model (`rate_limited`).
    refuse_next: Mutex<Option<Status>>,
    pub events: Mutex<Vec<Event>>,
}

impl FakePhone {
    pub fn new(pc_pub: [u8; 32], pairing_id: [u8; 16], person: Person) -> Self {
        Self {
            keys: StaticKeypair::generate().expect("x25519 keygen"),
            pc_pub,
            pairing_id,
            accounts: Mutex::new(HashMap::new()),
            enrol_open: AtomicBool::new(false),
            busy: AtomicBool::new(false),
            person,
            next_enrol_key: Mutex::new(None),
            refuse_next: Mutex::new(None),
            events: Mutex::new(Vec::new()),
        }
    }

    /// The phone's X25519 public key, as the PC learns it at pairing.
    pub fn public(&self) -> [u8; 32] {
        self.keys.public
    }

    pub fn add_account(&self, id: [u8; 16], label: &str, private: RsaPrivateKey, pin: Option<CtPin>) {
        self.accounts.lock().unwrap().insert(id, Account { label: label.into(), private, pin, unlocks: 0 });
    }

    pub fn set_pin(&self, id: &[u8; 16], pin: Option<CtPin>) {
        if let Some(a) = self.accounts.lock().unwrap().get_mut(id) {
            a.pin = pin;
        }
    }

    pub fn open_enrol(&self, open: bool) {
        self.enrol_open.store(open, Ordering::SeqCst);
    }

    pub fn set_next_enrol_key(&self, key: RsaPrivateKey) {
        *self.next_enrol_key.lock().unwrap() = Some(key);
    }

    pub fn refuse_next_unwrap(&self, status: Status) {
        *self.refuse_next.lock().unwrap() = Some(status);
    }

    pub fn events(&self) -> Vec<Event> {
        self.events.lock().unwrap().clone()
    }

    fn record(&self, e: Event) {
        self.events.lock().unwrap().push(e);
    }

    /// Bind and serve until the task is dropped. Returns the bound address.
    pub async fn listen(self: Arc<Self>, addr: &str) -> std::io::Result<(SocketAddr, JoinHandle<()>)> {
        let listener = TcpListener::bind(addr).await?;
        let local = listener.local_addr()?;
        let task = tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else { break };
                let phone = self.clone();
                tokio::spawn(async move { phone.handle(stream).await });
            }
        });
        Ok((local, task))
    }

    /// One connection: handshake, one request, one or two replies.
    /// Nothing visible happens before a valid request; failures close silently.
    pub async fn handle(self: Arc<Self>, stream: TcpStream) {
        let handshake = noise::kk_respond(stream, &self.keys.private, &self.pc_pub, &self.pairing_id);
        let Ok(Ok(mut ch)) = timeout(PRE_AUTH_TIMEOUT, handshake).await else { return };
        let Ok(Ok(req)) = timeout(PRE_AUTH_TIMEOUT, ch.recv_json::<Request>()).await else { return };
        if req.v != PROTOCOL_VERSION {
            return;
        }
        let hash = *ch.handshake_hash();
        let req_id = req.req_id.clone();
        let response = match req.body {
            RequestBody::Ping => {
                self.record(Event::Pong);
                Response::status(&req_id, Status::Pong)
            }
            RequestBody::Unwrap { account, rsa_ct, expires_in_ms, nonce, context } => {
                let Some(id) = account_id(&account) else {
                    self.record(Event::Refused { account: None, status: Status::UnknownAccount });
                    return;
                };
                let Some(rsa_ct) = unb64(&rsa_ct).ok().and_then(|v| <[u8; RSA_CT_LEN]>::try_from(v).ok()) else {
                    self.record(Event::Refused { account: Some(id), status: Status::Error });
                    return;
                };
                let Some(pc_nonce) = unb64(&nonce).ok().and_then(|v| <[u8; emoji::NONCE_LEN]>::try_from(v).ok()) else {
                    self.record(Event::Refused { account: Some(id), status: Status::Error });
                    return;
                };
                // Everything below the pin check is refused without a prompt.
                let known = self.accounts.lock().unwrap().get(&id).map(|a| (a.label.clone(), a.pin));
                let Some((label, pin)) = known else {
                    self.record(Event::Refused { account: Some(id), status: Status::UnknownAccount });
                    let _ = ch.send_json(&Response::status(&req_id, Status::UnknownAccount)).await;
                    return;
                };
                if !pin.is_some_and(|p| p.matches(&rsa_ct)) {
                    self.record(Event::Refused { account: Some(id), status: Status::PinMismatch });
                    let _ = ch.send_json(&Response::status(&req_id, Status::PinMismatch)).await;
                    return;
                }
                let forced = self.refuse_next.lock().unwrap().take();
                if let Some(status) = forced {
                    self.record(Event::Refused { account: Some(id), status });
                    let _ = ch.send_json(&Response::status(&req_id, status)).await;
                    return;
                }
                if self.busy.compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst).is_err() {
                    self.record(Event::Refused { account: Some(id), status: Status::Busy });
                    let _ = ch.send_json(&Response::status(&req_id, Status::Busy)).await;
                    return;
                }
                let _guard = BusyGuard(&self.busy);

                let mut phone_nonce = [0u8; emoji::NONCE_LEN];
                rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut phone_nonce);
                if ch.send_json(&Response::prompt_posted(&req_id, &phone_nonce)).await.is_err() {
                    return;
                }
                let real = emoji::index(&hash, &pc_nonce, &phone_nonce);
                let choices = emoji::phone_choices(real, &mut rand::rngs::OsRng).map(|i| emoji::EMOJI[i]);
                let prompt = Prompt {
                    account_id: id,
                    label,
                    emoji: emoji::EMOJI[real],
                    choices,
                    host: context.host,
                    expires_in_ms,
                };
                self.record(Event::Prompted(prompt.clone()));
                let started = std::time::Instant::now();
                let deadline = Duration::from_millis(expires_in_ms);
                let decision = timeout(deadline, (self.person)(prompt)).await.unwrap_or(Decision::Ignore);
                if decision == Decision::Ignore {
                    // Nobody answered: the prompt stays up, and the phone stays busy, until the deadline.
                    tokio::time::sleep(deadline.saturating_sub(started.elapsed())).await;
                }
                let mut response = Response::status(&req_id, Status::Expired);
                let status = match decision {
                    Decision::Approve => {
                        let k_wrap = {
                            let accounts = self.accounts.lock().unwrap();
                            phone::decrypt_k_wrap(&accounts[&id].private, &rsa_ct)
                        };
                        match k_wrap {
                            Ok(k) => {
                                response.k_wrap = Some(b64(k.as_bytes()));
                                self.accounts.lock().unwrap().get_mut(&id).unwrap().unlocks += 1;
                                Status::Ok
                            }
                            Err(_) => Status::Error,
                        }
                    }
                    Decision::Deny | Decision::WrongEmoji => Status::Denied,
                    Decision::NoneOfThese => Status::Rejected,
                    // The deadline ran out: the prompt is cancelled and no K_wrap is ever sent.
                    Decision::Ignore => Status::Expired,
                };
                response.status = status;
                self.record(Event::Answered { account: id, decision, status });
                response
            }
            RequestBody::EnrolBegin { account, label_hint } => {
                let Some(id) = account_id(&account) else { return };
                let taken = self.accounts.lock().unwrap().values().any(|a| a.label.eq_ignore_ascii_case(&label_hint));
                if !self.enrol_open.load(Ordering::SeqCst) {
                    self.record(Event::Refused { account: Some(id), status: Status::NotAllowed });
                    Response::status(&req_id, Status::NotAllowed)
                } else if taken {
                    // As the real phone: one name, one account.
                    self.record(Event::Refused { account: Some(id), status: Status::LabelTaken });
                    Response::status(&req_id, Status::LabelTaken)
                } else {
                    let private = self
                        .next_enrol_key
                        .lock()
                        .unwrap()
                        .take()
                        .unwrap_or_else(|| RsaPrivateKey::new(&mut rand::rngs::OsRng, 2048).expect("rsa keygen"));
                    let public = RsaPublicKey::from(&private);
                    let fresh = match self.accounts.lock().unwrap().entry(id) {
                        std::collections::hash_map::Entry::Occupied(_) => false,
                        std::collections::hash_map::Entry::Vacant(v) => {
                            v.insert(Account { label: label_hint.clone(), private, pin: None, unlocks: 0 });
                            true
                        }
                    };
                    if fresh {
                        self.record(Event::Enrolled(id));
                        let mut r = Response::status(&req_id, Status::Ok);
                        r.rsa_pub = Some(b64(public.to_public_key_der().expect("spki").as_bytes()));
                        r.label = Some(label_hint);
                        r
                    } else {
                        self.record(Event::Refused { account: Some(id), status: Status::NotAllowed });
                        Response::status(&req_id, Status::NotAllowed)
                    }
                }
            }
            RequestBody::SetPin { account, pin } => {
                let Some(id) = account_id(&account) else { return };
                let pin = unb64(&pin).ok().and_then(|p| CtPin::from_bytes(&p));
                let mut accounts = self.accounts.lock().unwrap();
                let status = match (self.enrol_open.load(Ordering::SeqCst), accounts.get_mut(&id), pin) {
                    (false, _, _) => Status::NotAllowed,
                    (_, None, _) => Status::UnknownAccount,
                    (_, Some(a), Some(pin)) if a.pin.is_none() => {
                        a.pin = Some(pin);
                        Status::Ok
                    }
                    _ => Status::NotAllowed,
                };
                drop(accounts);
                self.record(if status == Status::Ok {
                    Event::Pinned(id)
                } else {
                    Event::Refused { account: Some(id), status }
                });
                Response::status(&req_id, status)
            }
        };
        let _ = ch.send_json(&response).await;
    }
}

struct BusyGuard<'a>(&'a AtomicBool);

impl Drop for BusyGuard<'_> {
    fn drop(&mut self) {
        self.0.store(false, Ordering::SeqCst);
    }
}

fn account_id(b64_id: &str) -> Option<[u8; 16]> {
    unb64(b64_id).ok()?.try_into().ok()
}

/// Fixed RSA-2048 keys for tests and the fake phone binary: `0` and `1`.
/// Never used for anything real.
pub fn fixed_rsa_key(n: usize) -> RsaPrivateKey {
    RsaPrivateKey::from_pkcs8_pem(FIXED_KEYS[n]).expect("fixed test key")
}

const FIXED_KEYS: [&str; 2] = [
    "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6MQOKZ9cQx9YQ
fClGiakoNOANrvTZ8DDStG6U85+c9Lw1zvC8jcqLs+IqdlpNnJcKpQKYYIYt3+tL
BQQFVeC4d6GTET3oSmmMbj3nru6Jmsyj8cvQjjZ3Yj2arGRdfM17kTQhukUDubKN
vDrlEYDl8Se4bq2LpWn99Ky/zRtJVagQNvuC9GbzTRI+400zsob1OqEop4i4d9DB
44ckFW/paJb9oZcSJirRbmD9hapzaHmP6pnXlDiWIbclOO1Qs8JPmT3MLBvC+pKm
rJ9SqlRlG5YNzRcVsw8WH/2s12nP5WyXI5N3P0DdnccwS8hqidvuSVL1/J5Y2kI8
ye8osvUxAgMBAAECggEADrmXnRePQ616OX2ISiLS9PIRkiN3C9FaGx/X6wHFasVU
KTE/irnv/dJxHYiUpbSvoVDhfqmLkw81bY5s/fsHta8IYTgo3DkeVdPWI3+LL+jF
LGYQB2Nn3VMwqg3eNiKLoa0fIVe4442JGHp9ceZLemPzDzv5j6S6WDJEgzq2YLs5
7XKvjXeVvNzdkN7hdOXOBcsjIvZGjcJmnkftz94z+aqx+MpteKyVRlRqPy3dfONw
w2C816zrPH2ilQp5hQEZhOP1d/FmTb+MWa0Zx9mecvz0UGD4Ek4Qxe53f4qWcsTl
WXNxO3wTEs27PXqspc/4xrIZD5xA+fBigsqyF8G/EQKBgQDhdKoN1ncRhaSuGtAg
4blUvuglk9nxcvENLQ7GwmZx9uAMQdLKhsLl0o5LZ5+5JEYI1GsSh7jIVj2B56Nn
QLFLl2SGW0Y3vOPfE1BE+ELSxrKgRcNvfErsvjFsWLwYe3IysjYBgumaqDMh0sCm
GVcaiq5yGAuSWOWaqW0O/EbwhQKBgQDTapKPISWzpYo9oMSsNSoyep+vr2e396+9
q4ZDO04XlqF0FoWJkEZgqNlv8anZRGuCOerle4gePPvQWSRjREkRnTbSnJE4YOEB
2euEu+8sCpvFEG7JqpaoZOkDuHeug/LM6vbSdtz02N17E0MD3hVvzzymZqTOP//k
0DQuoqzHvQKBgQCy7Y/4o3ij41irBIShVANuCoTbLdgOE5bTSisr+ySq1a9Ciwrr
yL/s/YoIthjBKtSaNVs0vZodBLST4G6Ch4kt4Nza9J1ppvOCGyXdVtpRxXgGUtek
JxSfhuJahqHhHDepnF3YHTmgkFTkRwq1x+6lFeMUkZi9cOfoMwZmmjkCsQKBgGdr
W7ROd73wfbZ1/Z9sBm9ZEuKDQI56yGpVDMG4shPR6Lr8BWjsvbCtCGi9Y+PXl2vF
30VQ754zIM+ju6wfjErkiBvw4Q0ePxODwbVVpcL6kYaN6lQWccqASog6Zbll7JEX
Y5RC9wWDTJzXKFItAnmGe9m+nmISZqBMxSoHA9RVAoGAWkCrf/+h7fSZXmwbbRUa
jmKfCd+euZpz+ILoPh8RBwYFdb8h23h9tm2te14hr4TJauYcVrAyTwcqBU7NNtFw
BI3iwIaBsTclk92AlLmSme4H4o+kojoCQf4HnnZcVG+vk9BPMlHY4kjwoCX5EaSD
mPNAvFv20T4Uz4cKejKx/LI=
-----END PRIVATE KEY-----",
    "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCq5QDN64hZSm6z
7OLtYSVJxx/hDsAVSOH5jeS3tPADQlMaB1MEgBwLKr00wSQtw17tJBK0LI3+/Ima
+HtZJu04LEhE9/Nh1rkToAB0+BObzkpYx9V4P0UhJgdo8x1bjupLrfafVos85CEL
RxDA7gtOJcqkkFItrxBIJjLx+yGDmXwYioDJve+T7tePxHAdqgY4ItatHmYPo3ey
wHCfd82w36sFdnWM0ex2T1sXEMJUFyErnAyr86m8np2ohZVBIhXE5o3KjQ2V7nI2
eiaIz67n8ag97bqgwkFIX5IIsSitsIAXnNUWnPpb+anDz1FC+VjlKA01KPm90ZP+
4TM9sAyjAgMBAAECggEAEVKDIVxVhs9/pydE3VDyiabweUyYdc/ccAJNA74Ichwf
9kx1wsgFj7A2W4mUVDswfRMh/jdh8U3B2P6E6kWC2CXM8Yi8l9c/DVkzkqeuvSVM
7fDbl4O6SyDisWWrPSOgZiltDTulg3eQTedXMGcwqCw2fTXPzqenG9kbYuHUxNT4
kwEAsMgTj0hgRA11M8nowQfeVS3Qtzjxb1Mz2lwO9OfsEBgQwNI0IYES9bkqo5bi
MctD8wufWhtdjKzwGA7WseczY5P1m678UmRrZcCOXJzA/+nXlqinJI7zJUrwP5nY
pJlH8IbVMf6K+6gEWuiFEzNsUH1vUJyV4gftas1pAQKBgQDRTZF1YLXd8QzSX0p7
v2QmmO1wmJgTa8kSpWt695wInDkEr0xIgF9Ac7D4fTVByMv5yqxdrJtLAbn9IkMf
9w0HQL+K4T4C+QzTmdKxh19JMFHBGV2mpas+QBIpl7gpITujbW4FOkTpYAIDB+5x
PCP9FC1VxXik9ZlwUu+lGh6BgQKBgQDRBbgfMB8jqFuLUchn2oLlGLDvCcRo39Rb
j8r9sC+TQQLyVJ5LErspV9qtaKQcW5p4jLJEC7tk8eVfW20qc3kvUiyWhA8j6B7u
chS3jVRWkNoln7GprVA1Rrp6gXaRnvNUkvyT56Thg3kPC5xu7I5f35qpuHS45iCw
nZOfrwBYIwKBgGOCE2PQxOZt0gC6mTjYN486Kbjcc4DYP9KDnuPpkN9vFpSpmwTl
M2P7HOom7QkHpCJwPx6SD4rLmVdF0NADrsgB+o7Wo5raOUTo3wjUKXMsa9H4c1Pl
c9K2t2va3A2B5U6/mg0WNOkXYh16ydxAEYQi8aLTrZYPxhFm/NRr5JEBAoGAaYe5
rgVds2MM1Qo1ZDmuXHxa2FTWFRzs2k1+7xZE7tOj6TVPthd+5yC0B1kNgkO9eZ+P
YUuLESwP4lUGiKhERt/2IwgJnNdUxo5SZ1mzewEnIle+GyylkkBjZfZ3Jo5ZzBlp
7ELHvBPkyvPRxy8nsr/yFj5KsA9/8audHMH+KoECgYEAgL/h47tMbzqAx54kwTxU
XqCsgOly75BFu0QFMGlix3zMDeTf7HSO97runCicOx3cLjjqTlFez5WlokmdQJz0
a+Nf7b59rnfNXVTgESem0Wx3gJLYGs97QokCn8aN3GCWekfdjBJK+O6tAa9gsOH4
PQnakctn8mhKxp4yVRCI4Pk=
-----END PRIVATE KEY-----",
];
