//! JSON messages carried inside the Noise channel. Every message carries
//! `"v": 3`; a message with any other version is refused.
//!
//! Binary fields are standard base64 with padding.

use serde::{Deserialize, Serialize};

use crate::PROTOCOL_VERSION;

/// A request from the PC to the phone. One session carries one request.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Request {
    pub v: u8,
    pub req_id: String,
    #[serde(flatten)]
    pub body: RequestBody,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RequestBody {
    /// Reachability check. The phone answers `pong` and shows nothing.
    Ping,
    /// Decrypt `rsa_ct` with the account's Keystore key after the emoji pick
    /// and a fingerprint. The emoji is not sent: both sides derive it from the
    /// handshake hash, this `nonce` (32 random bytes) and the phone's nonce
    /// in `prompt_posted`.
    Unwrap { account: String, rsa_ct: String, expires_in_ms: u64, nonce: String, context: Context },
    /// Ask the phone to create an account key. Refused unless the person has
    /// the phone's Enrol screen open.
    EnrolBegin { account: String, label_hint: String },
    /// Pin the one ciphertext this account's key will decrypt. Write-once.
    SetPin { account: String, pin: String },
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Context {
    pub host: String,
}

impl Request {
    pub fn new(req_id: String, body: RequestBody) -> Self {
        Self { v: PROTOCOL_VERSION, req_id, body }
    }
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    /// Interim: the prompt is on the phone. Ends the reach phase.
    PromptPosted,
    Ok,
    Pong,
    /// The person denied, dismissed, or picked the wrong emoji.
    Denied,
    /// The person tapped None of these. The PC raises an alarm.
    Rejected,
    PinMismatch,
    RateLimited,
    /// Another request is already on the phone. Since the daemon never has two
    /// of its own in flight, this means someone else is asking.
    Busy,
    Expired,
    /// The account's Keystore key is gone (new fingerprint, screen lock removed).
    Invalidated,
    UnknownAccount,
    /// Refused by policy, e.g. `enrol_begin` without the Enrol screen open,
    /// or a second `set_pin`.
    NotAllowed,
    /// `enrol_begin` for a label the phone already has (case-insensitive).
    LabelTaken,
    Error,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct Response {
    pub v: u8,
    pub req_id: String,
    pub status: Status,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub k_wrap: Option<String>,
    /// `prompt_posted`: the phone's 32 random bytes for the emoji derivation.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub nonce: Option<String>,
    /// `enrol_begin`: the new key's RSA public key, SPKI DER.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rsa_pub: Option<String>,
    /// `enrol_begin`: the label the person chose on the phone.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
}

impl Response {
    pub fn status(req_id: &str, status: Status) -> Self {
        Self {
            v: PROTOCOL_VERSION,
            req_id: req_id.to_owned(),
            status,
            k_wrap: None,
            nonce: None,
            rsa_pub: None,
            label: None,
        }
    }

    /// The interim reply: the prompt is on screen, and here is the phone's
    /// half of the emoji derivation.
    pub fn prompt_posted(req_id: &str, phone_nonce: &[u8; crate::emoji::NONCE_LEN]) -> Self {
        let mut r = Self::status(req_id, Status::PromptPosted);
        r.nonce = Some(crate::b64(phone_nonce));
        r
    }
}

/// Pairing, phone to PC: the first transport message after NKpsk0.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PairHello {
    pub v: u8,
    pub x25519_pub: String,
    pub listen_port: u16,
    pub device_label: String,
}

/// Pairing, both directions: whether the person confirmed the six words.
/// Neither side commits anything until it has sent and received `true`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct PairConfirm {
    pub v: u8,
    pub confirmed: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wire_shape() {
        let req = Request::new(
            "abc".into(),
            RequestBody::Unwrap {
                account: "acc".into(),
                rsa_ct: "ct".into(),
                expires_in_ms: 45000,
                nonce: crate::b64(&[3u8; 32]),
                context: Context { host: "ibra-PC".into() },
            },
        );
        let json: serde_json::Value = serde_json::to_value(&req).unwrap();
        assert_eq!(json["v"], 3);
        assert_eq!(json["type"], "unwrap");
        assert_eq!(json["expires_in_ms"], 45000);
        assert_eq!(serde_json::from_value::<Request>(json).unwrap(), req);

        let ping = serde_json::to_value(Request::new("x".into(), RequestBody::Ping)).unwrap();
        assert_eq!(ping, serde_json::json!({"v": 3, "req_id": "x", "type": "ping"}));
    }

    #[test]
    fn response_omits_absent_fields() {
        let json = serde_json::to_value(Response::status("r", Status::Ok)).unwrap();
        assert_eq!(json, serde_json::json!({"v": 3, "req_id": "r", "status": "ok"}));
        let posted = serde_json::to_value(Response::prompt_posted("r", &[5u8; 32])).unwrap();
        assert_eq!(posted["status"], "prompt_posted");
        assert_eq!(crate::unb64(posted["nonce"].as_str().unwrap()).unwrap(), vec![5u8; 32]);
    }
}
