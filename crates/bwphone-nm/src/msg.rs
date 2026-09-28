//! The messages, as `nativeMessaging.background.ts` sends and reads them.
//!
//! Extension → host, always `{"appId", "message"}`, where `message` is the
//! plaintext `setupEncryption` request or an [`EncString`] object.
//!
//! Host → extension, dispatched on the outer `command`: `connected`,
//! `disconnected`, `setupEncryption` (with `sharedSecret`),
//! `invalidateEncryption`, `wrongUserId`; no `command` means an encrypted
//! reply in `message`, accepted only when `appId` matches.

use serde::{Deserialize, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::session::EncString;

/// A reply whose inner `timestamp` is further than this from the
/// extension's clock is dropped silently.
pub const MESSAGE_VALID_TIMEOUT_MS: i64 = 10_000;
/// The extension abandons a request after this.
pub const MESSAGE_NO_RESPONSE_TIMEOUT_MS: i64 = 60_000;

pub fn is_fresh(timestamp_ms: i64, now_ms: i64) -> bool {
    (timestamp_ms - now_ms).abs() <= MESSAGE_VALID_TIMEOUT_MS
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Incoming {
    pub app_id: String,
    pub message: IncomingBody,
}

#[derive(Debug, Deserialize)]
#[serde(untagged)]
pub enum IncomingBody {
    Encrypted(EncString),
    Plain(PlainRequest),
}

/// The only plaintext request: `setupEncryption`.
#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PlainRequest {
    pub command: String,
    #[serde(default)]
    pub public_key: Option<String>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub message_id: Option<i64>,
    #[serde(default)]
    pub timestamp: Option<i64>,
}

/// `libs/key-management/src/biometrics/biometrics-commands.ts`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum Command {
    GetBiometricsStatus,
    GetBiometricsStatusForUser,
    UnlockWithBiometricsForUser,
    AuthenticateWithBiometrics,
    CanEnableBiometricUnlock,
    #[serde(other)]
    Unknown,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Request {
    pub command: Command,
    pub message_id: i64,
    /// The active account's Bitwarden userId; routing keys off it.
    #[serde(default)]
    pub user_id: Option<String>,
    pub timestamp: i64,
}

/// `libs/key-management/src/biometrics/biometrics-status.ts`, by value.
/// `Available` is the only success; which unavailable status to report is
/// the daemon's choice.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BiometricsStatus {
    Available = 0,
    UnlockNeeded = 1,
    HardwareUnavailable = 2,
    AutoSetupNeeded = 3,
    ManualSetupNeeded = 4,
    PlatformUnsupported = 5,
    DesktopDisconnected = 6,
    NotEnabledLocally = 7,
    NotEnabledInConnectedDesktopApp = 8,
    NativeMessagingPermissionMissing = 9,
}

impl Serialize for BiometricsStatus {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_u8(*self as u8)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(untagged)]
pub enum Response {
    Status(BiometricsStatus),
    Bool(bool),
}

/// The inner reply. Its `timestamp` is stamped when it is sealed, not when
/// it is built, so a 30 s wait on the phone cannot produce a stale reply.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
pub struct Reply {
    pub command: Command,
    pub message_id: i64,
    pub response: Response,
    #[serde(skip_serializing_if = "Option::is_none", serialize_with = "secret_string")]
    pub user_key_b64: Option<Zeroizing<String>>,
    pub(crate) timestamp: i64,
}

impl std::fmt::Debug for Reply {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Reply")
            .field("command", &self.command)
            .field("message_id", &self.message_id)
            .field("response", &self.response)
            .field("user_key_b64", &self.user_key_b64.as_ref().map(|_| "<redacted>"))
            .field("timestamp", &self.timestamp)
            .finish()
    }
}

fn secret_string<S: Serializer>(v: &Option<Zeroizing<String>>, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(v.as_deref().map(String::as_str).unwrap_or_default())
}

impl Reply {
    fn to(req: &Request, response: Response) -> Self {
        Self { command: req.command, message_id: req.message_id, response, user_key_b64: None, timestamp: 0 }
    }

    /// `getBiometricsStatus` / `getBiometricsStatusForUser`.
    pub fn status(req: &Request, status: BiometricsStatus) -> Self {
        Self::to(req, Response::Status(status))
    }

    /// `unlockWithBiometricsForUser` succeeded: the user key, base64.
    pub fn unlocked(req: &Request, user_key_b64: Zeroizing<String>) -> Self {
        let mut r = Self::to(req, Response::Bool(true));
        r.user_key_b64 = Some(user_key_b64);
        r
    }

    /// `{"response": false}`: the extension shows the password box at once.
    pub fn refused(req: &Request) -> Self {
        Self::to(req, Response::Bool(false))
    }

    /// `authenticateWithBiometrics` / `canEnableBiometricUnlock`.
    pub fn yes_no(req: &Request, ok: bool) -> Self {
        Self::to(req, Response::Bool(ok))
    }
}

/// An encrypted reply: no outer `command`, so the extension's default
/// branch decrypts `message` after checking `appId`.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct OuterReply<'a> {
    pub app_id: &'a str,
    pub message_id: i64,
    pub message: EncString,
}

/// The handshake reply. `messageId` is -1 by contract: it tells the
/// extension this is a modern desktop client.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct SetupReply<'a> {
    pub app_id: &'a str,
    pub command: &'static str,
    pub message_id: i64,
    pub shared_secret: String,
}

impl<'a> SetupReply<'a> {
    pub fn new(app_id: &'a str, shared_secret: String) -> Self {
        Self { app_id, command: "setupEncryption", message_id: -1, shared_secret }
    }
}

#[derive(Debug, Serialize)]
pub struct Control {
    pub command: &'static str,
}

pub const CONNECTED: Control = Control { command: "connected" };
pub const DISCONNECTED: Control = Control { command: "disconnected" };

/// Tells the extension to tear its channel down and handshake again.
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct InvalidateEncryption<'a> {
    pub command: &'static str,
    pub app_id: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<i64>,
}

impl<'a> InvalidateEncryption<'a> {
    pub fn new(app_id: &'a str, message_id: Option<i64>) -> Self {
        Self { command: "invalidateEncryption", app_id, message_id }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn incoming_setup_and_encrypted_bodies_parse() {
        let setup: Incoming = serde_json::from_value(json!({
            "appId": "app-1",
            "message": {"command": "setupEncryption", "publicKey": "AAAA", "userId": "u1", "messageId": 0, "timestamp": 1}
        }))
        .unwrap();
        assert_eq!(setup.app_id, "app-1");
        match setup.message {
            IncomingBody::Plain(p) => {
                assert_eq!(p.command, "setupEncryption");
                assert_eq!(p.public_key.as_deref(), Some("AAAA"));
                assert_eq!(p.user_id.as_deref(), Some("u1"));
            }
            other => panic!("{other:?}"),
        }

        let enc: Incoming = serde_json::from_value(json!({
            "appId": "app-1",
            "message": {"encryptedString": "2.a|b|c", "encryptionType": 2, "iv": "a", "data": "b", "mac": "c"}
        }))
        .unwrap();
        assert!(matches!(enc.message, IncomingBody::Encrypted(e) if e.encrypted_string == "2.a|b|c"));
    }

    #[test]
    fn request_commands_and_unknowns() {
        let req: Request = serde_json::from_value(json!({
            "command": "unlockWithBiometricsForUser", "messageId": 3, "userId": "u1", "timestamp": 5
        }))
        .unwrap();
        assert_eq!(req.command, Command::UnlockWithBiometricsForUser);
        let odd: Request =
            serde_json::from_value(json!({"command": "somethingNew", "messageId": 3, "timestamp": 5})).unwrap();
        assert_eq!(odd.command, Command::Unknown);
        assert_eq!(odd.user_id, None);
    }

    #[test]
    fn reply_shapes() {
        let req = Request { command: Command::GetBiometricsStatus, message_id: 9, user_id: None, timestamp: 0 };
        let mut r = Reply::status(&req, BiometricsStatus::Available);
        r.timestamp = 42;
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({"command": "getBiometricsStatus", "messageId": 9, "response": 0, "timestamp": 42})
        );
        let mut r = Reply::status(&req, BiometricsStatus::HardwareUnavailable);
        r.timestamp = 1;
        assert_eq!(serde_json::to_value(&r).unwrap()["response"], 2);

        let req = Request { command: Command::UnlockWithBiometricsForUser, message_id: 10, user_id: None, timestamp: 0 };
        let mut r = Reply::unlocked(&req, Zeroizing::new("S0VZ".into()));
        r.timestamp = 7;
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({"command": "unlockWithBiometricsForUser", "messageId": 10, "response": true, "userKeyB64": "S0VZ", "timestamp": 7})
        );
        let mut r = Reply::refused(&req);
        r.timestamp = 7;
        assert_eq!(
            serde_json::to_value(&r).unwrap(),
            json!({"command": "unlockWithBiometricsForUser", "messageId": 10, "response": false, "timestamp": 7})
        );
    }

    #[test]
    fn outer_shapes() {
        assert_eq!(
            serde_json::to_value(SetupReply::new("app", "c2VjcmV0".into())).unwrap(),
            json!({"appId": "app", "command": "setupEncryption", "messageId": -1, "sharedSecret": "c2VjcmV0"})
        );
        assert_eq!(serde_json::to_value(CONNECTED).unwrap(), json!({"command": "connected"}));
        assert_eq!(
            serde_json::to_value(InvalidateEncryption::new("app", Some(4))).unwrap(),
            json!({"command": "invalidateEncryption", "appId": "app", "messageId": 4})
        );
        let outer = OuterReply {
            app_id: "app",
            message_id: 4,
            message: EncString {
                encrypted_string: "2.a|b|c".into(),
                encryption_type: 2,
                iv: Some("a".into()),
                data: Some("b".into()),
                mac: Some("c".into()),
            },
        };
        let v = serde_json::to_value(&outer).unwrap();
        assert!(v.get("command").is_none(), "an encrypted reply carries no outer command");
        assert_eq!(v["appId"], "app");
        assert_eq!(v["message"]["encryptionType"], 2);
    }

    #[test]
    fn freshness_window() {
        assert!(is_fresh(1_000_000, 1_000_000 + MESSAGE_VALID_TIMEOUT_MS));
        assert!(is_fresh(1_000_000 + MESSAGE_VALID_TIMEOUT_MS, 1_000_000));
        assert!(!is_fresh(1_000_000, 1_000_000 + MESSAGE_VALID_TIMEOUT_MS + 1));
    }
}
