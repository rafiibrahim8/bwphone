//! One browser connection's state: the session key from `setupEncryption`
//! and the `appId` it belongs to. Frames in, frames out; the daemon decides
//! what to answer.

use zeroize::Zeroizing;

use crate::{
    NmError,
    handshake::setup_encryption,
    msg::{
        CONNECTED, Incoming, IncomingBody, InvalidateEncryption, OuterReply, Reply, Request, SetupReply,
        is_fresh,
    },
    session::{EncString, SessionKey},
};

#[derive(Default)]
pub struct Peer {
    key: Option<SessionKey>,
    app_id: Option<String>,
}

#[derive(Debug)]
pub enum Event {
    /// The handshake completed; send `reply` at once.
    Setup { user_id: Option<String>, reply: Vec<u8> },
    /// A decrypted, fresh request to answer with [`Peer::reply`].
    Request(Request),
    /// Its timestamp was outside the 10 s window; ignore it.
    Stale(Request),
    /// Encrypted traffic before a handshake, or from a different `appId`:
    /// send [`Peer::invalidate`] and wait for a new `setupEncryption`.
    NoChannel,
    /// A plaintext command we do not know. Ignore.
    Unknown(String),
}

impl Peer {
    pub fn new() -> Self {
        Self::default()
    }

    /// The first frame on the pipe.
    pub fn connected() -> Vec<u8> {
        serde_json::to_vec(&CONNECTED).expect("static")
    }

    pub fn app_id(&self) -> Option<&str> {
        self.app_id.as_deref()
    }

    pub fn receive(&mut self, frame: &[u8], now_ms: i64) -> Result<Event, NmError> {
        let incoming: Incoming = serde_json::from_slice(frame)?;
        match incoming.message {
            IncomingBody::Plain(plain) if plain.command == "setupEncryption" => {
                let public_key = plain.public_key.ok_or(NmError::Malformed("setupEncryption without publicKey"))?;
                let (key, shared_secret) = setup_encryption(&public_key)?;
                let reply = serde_json::to_vec(&SetupReply::new(&incoming.app_id, shared_secret))?;
                self.key = Some(key);
                self.app_id = Some(incoming.app_id);
                Ok(Event::Setup { user_id: plain.user_id, reply })
            }
            IncomingBody::Plain(plain) => Ok(Event::Unknown(plain.command)),
            IncomingBody::Encrypted(enc) => {
                let (Some(key), Some(app_id)) = (&self.key, &self.app_id) else {
                    return Ok(Event::NoChannel);
                };
                if *app_id != incoming.app_id {
                    return Ok(Event::NoChannel);
                }
                let plain = enc.open(key)?;
                let request: Request = serde_json::from_slice(&plain)?;
                Ok(if is_fresh(request.timestamp, now_ms) { Event::Request(request) } else { Event::Stale(request) })
            }
        }
    }

    /// Stamps the reply with `now_ms` and seals it. Call this when the
    /// answer is in hand, not when the request arrived.
    pub fn reply(&self, mut reply: Reply, now_ms: i64) -> Result<Zeroizing<Vec<u8>>, NmError> {
        let (Some(key), Some(app_id)) = (&self.key, &self.app_id) else {
            return Err(NmError::NoChannel);
        };
        reply.timestamp = now_ms;
        let inner = Zeroizing::new(serde_json::to_vec(&reply)?);
        let message = EncString::seal(key, &inner);
        let outer = OuterReply { app_id, message_id: reply.message_id, message };
        Ok(Zeroizing::new(serde_json::to_vec(&outer)?))
    }

    /// Drops the channel and tells the extension to redo the handshake.
    pub fn invalidate(&mut self, message_id: Option<i64>) -> Option<Vec<u8>> {
        self.key = None;
        let app_id = self.app_id.take()?;
        serde_json::to_vec(&InvalidateEncryption::new(&app_id, message_id)).ok()
    }
}

/// Milliseconds since the Unix epoch, as `Date.now()` counts them.
pub fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        b64,
        msg::{BiometricsStatus, Command, MESSAGE_VALID_TIMEOUT_MS},
        tests::extension_keypair,
        unb64,
    };
    use rsa::{Oaep, pkcs8::EncodePublicKey as _};
    use serde_json::json;
    use sha1::Sha1;

    /// The extension's side, enough to drive a [`Peer`].
    struct Extension {
        private: rsa::RsaPrivateKey,
        spki_b64: String,
        key: Option<SessionKey>,
        next_id: i64,
    }

    impl Extension {
        fn new() -> Self {
            let (private, public) = extension_keypair();
            let spki_b64 = b64(public.to_public_key_der().unwrap().as_bytes());
            Self { private, spki_b64, key: None, next_id: 0 }
        }

        fn setup(&mut self) -> Vec<u8> {
            let id = self.next_id;
            self.next_id += 1;
            serde_json::to_vec(&json!({"appId": "app-1", "message": {
                "command": "setupEncryption", "publicKey": self.spki_b64, "userId": "user-1",
                "messageId": id, "timestamp": now_ms()
            }}))
            .unwrap()
        }

        fn take_setup_reply(&mut self, frame: &[u8]) {
            let v: serde_json::Value = serde_json::from_slice(frame).unwrap();
            assert_eq!(v["command"], "setupEncryption");
            assert_eq!(v["messageId"], -1);
            assert_eq!(v["appId"], "app-1");
            let ct = unb64(v["sharedSecret"].as_str().unwrap()).unwrap();
            let raw = self.private.decrypt(Oaep::new::<Sha1>(), &ct).unwrap();
            self.key = Some(SessionKey::from_slice(&raw).unwrap());
        }

        fn send(&mut self, command: &str, timestamp: i64) -> (i64, Vec<u8>) {
            let id = self.next_id;
            self.next_id += 1;
            let inner = json!({"command": command, "messageId": id, "userId": "user-1", "timestamp": timestamp});
            let enc = EncString::seal(self.key.as_ref().unwrap(), &serde_json::to_vec(&inner).unwrap());
            (id, serde_json::to_vec(&json!({"appId": "app-1", "message": enc})).unwrap())
        }

        fn open_reply(&self, frame: &[u8]) -> (String, serde_json::Value) {
            let v: serde_json::Value = serde_json::from_slice(frame).unwrap();
            assert!(v.get("command").is_none());
            let app_id = v["appId"].as_str().unwrap().to_owned();
            let enc: EncString = serde_json::from_value(v["message"].clone()).unwrap();
            let plain = enc.open(self.key.as_ref().unwrap()).unwrap();
            (app_id, serde_json::from_slice(&plain).unwrap())
        }
    }

    #[test]
    fn full_conversation() {
        let mut ext = Extension::new();
        let mut peer = Peer::new();
        assert_eq!(Peer::connected(), br#"{"command":"connected"}"#);

        let now = now_ms();
        let Event::Setup { user_id, reply } = peer.receive(&ext.setup(), now).unwrap() else { panic!() };
        assert_eq!(user_id.as_deref(), Some("user-1"));
        assert_eq!(peer.app_id(), Some("app-1"));
        ext.take_setup_reply(&reply);

        let (id, frame) = ext.send("getBiometricsStatus", now);
        let Event::Request(req) = peer.receive(&frame, now).unwrap() else { panic!() };
        assert_eq!(req.command, Command::GetBiometricsStatus);
        assert_eq!(req.message_id, id);
        assert_eq!(req.user_id.as_deref(), Some("user-1"));

        let sent_at = now + 30_000;
        let out = peer.reply(Reply::status(&req, BiometricsStatus::Available), sent_at).unwrap();
        let (app_id, inner) = ext.open_reply(&out);
        assert_eq!(app_id, "app-1");
        assert_eq!(inner["messageId"], id);
        assert_eq!(inner["response"], 0);
        assert_eq!(inner["timestamp"], sent_at, "stamped at send, not at arrival");

        let (id, frame) = ext.send("unlockWithBiometricsForUser", now);
        let Event::Request(req) = peer.receive(&frame, now).unwrap() else { panic!() };
        let out = peer.reply(Reply::unlocked(&req, Zeroizing::new("S0VZ".into())), now).unwrap();
        let (_, inner) = ext.open_reply(&out);
        assert_eq!(inner, json!({"command": "unlockWithBiometricsForUser", "messageId": id, "response": true, "userKeyB64": "S0VZ", "timestamp": now}));
    }

    #[test]
    fn stale_other_app_and_no_channel() {
        let mut ext = Extension::new();
        let mut peer = Peer::new();
        let now = now_ms();

        // Encrypted traffic before any handshake: no channel.
        let mut stray = Extension::new();
        stray.key = Some(SessionKey::generate());
        let (_, frame) = stray.send("getBiometricsStatus", now);
        assert!(matches!(peer.receive(&frame, now).unwrap(), Event::NoChannel));
        assert!(matches!(peer.reply(Reply::refused(&Request { command: Command::Unknown, message_id: 0, user_id: None, timestamp: 0 }), now), Err(NmError::NoChannel)));
        assert!(peer.invalidate(None).is_none(), "nothing to invalidate yet");

        let Event::Setup { reply, .. } = peer.receive(&ext.setup(), now).unwrap() else { panic!() };
        ext.take_setup_reply(&reply);

        let (_, frame) = ext.send("getBiometricsStatus", now - MESSAGE_VALID_TIMEOUT_MS - 1);
        assert!(matches!(peer.receive(&frame, now).unwrap(), Event::Stale(_)));

        // Another appId under the same key is refused as no channel.
        let (_, frame) = ext.send("getBiometricsStatus", now);
        let mut v: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        v["appId"] = json!("app-2");
        assert!(matches!(peer.receive(&serde_json::to_vec(&v).unwrap(), now).unwrap(), Event::NoChannel));

        // A frame under a stale key is a MAC failure, not a panic.
        let (_, frame) = stray.send("getBiometricsStatus", now);
        let mut v: serde_json::Value = serde_json::from_slice(&frame).unwrap();
        v["appId"] = json!("app-1");
        assert!(matches!(peer.receive(&serde_json::to_vec(&v).unwrap(), now), Err(NmError::Mac)));

        let plain = serde_json::to_vec(&json!({"appId": "app-1", "message": {"command": "somethingElse"}})).unwrap();
        assert!(matches!(peer.receive(&plain, now).unwrap(), Event::Unknown(c) if c == "somethingElse"));

        let inv = peer.invalidate(Some(3)).unwrap();
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&inv).unwrap(),
            json!({"command": "invalidateEncryption", "appId": "app-1", "messageId": 3})
        );
        assert!(peer.app_id().is_none());
        let (_, frame) = ext.send("getBiometricsStatus", now);
        assert!(matches!(peer.receive(&frame, now).unwrap(), Event::NoChannel));
    }

    #[test]
    fn garbage_is_an_error() {
        let mut peer = Peer::new();
        assert!(matches!(peer.receive(b"not json", 0), Err(NmError::Json(_))));
        let no_key = serde_json::to_vec(&json!({"appId": "a", "message": {"command": "setupEncryption"}})).unwrap();
        assert!(matches!(peer.receive(&no_key, 0), Err(NmError::Malformed(_))));
    }
}
