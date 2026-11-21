//! The RPC layer inside the channel (`bitwarden-ipc/src/rpc/`), JSON.
//!
//! Request, on envelope topic `RpcRequestMessage`:
//! `{"request", "request_id", "request_type", "response_topic"}`.
//! Response, on envelope topic `response_topic`:
//! `{"result": {"Ok": …} | {"Err": …}, "request_id", "request_type"}`.
//!
//! The requests the extension sends to the desktop
//! (`bitwarden-shared-unlock/src/wasm/biometrics.rs`,
//! `bitwarden-ipc/src/discover/mod.rs`):
//!
//! | `request_type` | `request` | `Ok` |
//! |---|---|---|
//! | `DiscoverRequest` | `null` | `{"version"}` |
//! | `GetBiometricsStatus` | `{"user_id"}` | `"Available"` / `"UnlockNeeded"` / `"HardwareUnavailable"` / `"NotEnabled"` |
//! | `UnlockBiometrics` | `{"user_id"}` | `{"user_key": <base64 or null>}` |
//! | `AuthenticateBiometrics` | `null` | `true` / `false` |
//!
//! Anything else is answered `{"Err": "NoHandlerFound"}`, as the SDK's
//! handler registry does; a known type whose `request` does not parse,
//! `{"Err": {"RequestDeserialization": …}}`.

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::IpcError;

/// The fixed envelope topic every RPC request travels on.
pub const REQUEST_TOPIC: &str = "RpcRequestMessage";

/// What identifies a request, echoed in its response.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct CallId {
    pub request_id: String,
    pub request_type: String,
    pub response_topic: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Request {
    Discover,
    GetBiometricsStatus { user_id: String },
    UnlockBiometrics { user_id: String },
    AuthenticateBiometrics,
    /// Some other request type: answered `NoHandlerFound`.
    Unknown,
    /// A known type whose `request` does not parse: answered
    /// `RequestDeserialization`, as the SDK's handler does, so the
    /// requester fails at once instead of waiting out its timeout.
    Malformed,
}

/// Longest `request_id`, `request_type` or `response_topic` accepted. The
/// SDK's are a UUID, a short name, and `RpcResponseMessage:<uuid>`.
pub const MAX_ID_LEN: usize = 128;

#[derive(Deserialize)]
struct Body<T> {
    request: T,
}

#[derive(Deserialize)]
struct ForUser {
    user_id: String,
}

/// Reads a decrypted request. Only the fields a known request type
/// defines are parsed; nothing else in the plaintext is copied out.
pub fn parse(plain: &[u8]) -> Result<(CallId, Request), IpcError> {
    let id: CallId = serde_json::from_slice(plain).map_err(|_| IpcError::Rpc)?;
    if [&id.request_id, &id.request_type, &id.response_topic].iter().any(|s| s.len() > MAX_ID_LEN) {
        return Err(IpcError::Rpc);
    }
    let for_user = || serde_json::from_slice::<Body<ForUser>>(plain).ok().map(|b| b.request.user_id);
    let request = match id.request_type.as_str() {
        "DiscoverRequest" => Request::Discover,
        "GetBiometricsStatus" => for_user().map_or(Request::Malformed, |user_id| Request::GetBiometricsStatus { user_id }),
        "UnlockBiometrics" => for_user().map_or(Request::Malformed, |user_id| Request::UnlockBiometrics { user_id }),
        "AuthenticateBiometrics" => Request::AuthenticateBiometrics,
        _ => Request::Unknown,
    };
    Ok((id, request))
}

/// `bitwarden-shared-unlock`'s `BiometricsStatus`, by name.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum Status {
    Available,
    UnlockNeeded,
    HardwareUnavailable,
    /// The extension shows this as "not enabled in the connected desktop app".
    NotEnabled,
}

pub enum Response {
    Discover { version: String },
    Status(Status),
    /// The user key, standard base64 of its 64 bytes; `None` when the unlock
    /// failed for any reason, which sends the extension to the password box.
    Unlock(Option<Zeroizing<String>>),
    Bool(bool),
    NoHandlerFound,
    RequestDeserialization,
}

impl std::fmt::Debug for Response {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Discover { version } => f.debug_struct("Discover").field("version", version).finish(),
            Self::Status(s) => f.debug_tuple("Status").field(s).finish(),
            Self::Unlock(k) => f.debug_tuple("Unlock").field(&k.as_ref().map(|_| "<redacted>")).finish(),
            Self::Bool(b) => f.debug_tuple("Bool").field(b).finish(),
            Self::NoHandlerFound => f.write_str("NoHandlerFound"),
            Self::RequestDeserialization => f.write_str("RequestDeserialization"),
        }
    }
}

#[derive(Serialize)]
struct Outgoing<'a, T: Serialize> {
    result: Result<T, RpcError>,
    request_id: &'a str,
    request_type: &'a str,
}

/// The SDK's `RpcError`: the variants a handler-side answer uses.
#[derive(Serialize)]
enum RpcError {
    NoHandlerFound,
    RequestDeserialization(&'static str),
}

#[derive(Serialize)]
struct Version<'a> {
    version: &'a str,
}

#[derive(Serialize)]
struct Unlocked<'a> {
    user_key: Option<&'a str>,
}

/// Room for everything but the ids, the user key's 88 base64 bytes included.
const ENCODE_BASE: usize = 512;

/// The response's JSON. It may hold the user key, so it is built in one
/// zeroising buffer that is large enough never to reallocate: JSON can
/// escape each id byte to six (`\u0001`).
pub fn encode(id: &CallId, response: &Response) -> Zeroizing<Vec<u8>> {
    let mut buf = Zeroizing::new(Vec::with_capacity(ENCODE_BASE + 6 * (id.request_id.len() + id.request_type.len())));
    fn write<T: Serialize>(buf: &mut Vec<u8>, id: &CallId, result: Result<T, RpcError>) {
        let out = Outgoing { result, request_id: &id.request_id, request_type: &id.request_type };
        serde_json::to_writer(buf, &out).expect("static shape");
    }
    match response {
        Response::Discover { version } => write(&mut buf, id, Ok(Version { version })),
        Response::Status(s) => write(&mut buf, id, Ok(s)),
        Response::Unlock(key) => write(&mut buf, id, Ok(Unlocked { user_key: key.as_deref().map(String::as_str) })),
        Response::Bool(b) => write(&mut buf, id, Ok(b)),
        Response::NoHandlerFound => write::<()>(&mut buf, id, Err(RpcError::NoHandlerFound)),
        Response::RequestDeserialization => {
            write::<()>(&mut buf, id, Err(RpcError::RequestDeserialization("malformed request")))
        }
    }
    debug_assert!(buf.capacity() >= buf.len());
    buf
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn request(request_type: &str, request: serde_json::Value) -> Vec<u8> {
        serde_json::to_vec(&json!({
            "request": request, "request_id": "r-1", "request_type": request_type,
            "response_topic": "RpcResponseMessage:r-1"
        }))
        .unwrap()
    }

    #[test]
    fn parses_the_four_requests() {
        let user = "6e5f3b2a-0c1d-4e8f-9a7b-112233445566";
        let (id, r) = parse(&request("GetBiometricsStatus", json!({"user_id": user}))).unwrap();
        assert_eq!(id.response_topic, "RpcResponseMessage:r-1");
        assert_eq!(r, Request::GetBiometricsStatus { user_id: user.into() });
        let (_, r) = parse(&request("UnlockBiometrics", json!({"user_id": user}))).unwrap();
        assert_eq!(r, Request::UnlockBiometrics { user_id: user.into() });
        assert_eq!(parse(&request("DiscoverRequest", json!(null))).unwrap().1, Request::Discover);
        assert_eq!(parse(&request("AuthenticateBiometrics", json!(null))).unwrap().1, Request::AuthenticateBiometrics);
        assert_eq!(parse(&request("SomethingNew", json!({"x": 1}))).unwrap().1, Request::Unknown);
        assert_eq!(parse(&request("UnlockBiometrics", json!(null))).unwrap().1, Request::Malformed);
        assert_eq!(parse(&request("GetBiometricsStatus", json!({"user_id": 5}))).unwrap().1, Request::Malformed);
        assert!(parse(b"{}").is_err());
        let long = serde_json::to_vec(&json!({"request": null, "request_id": "x".repeat(MAX_ID_LEN + 1),
            "request_type": "DiscoverRequest", "response_topic": "t"})).unwrap();
        assert!(parse(&long).is_err());
    }

    #[test]
    fn response_shapes() {
        let id = parse(&request("GetBiometricsStatus", json!({"user_id": "u"}))).unwrap().0;
        let v = |r: Response| serde_json::from_slice::<serde_json::Value>(&encode(&id, &r)).unwrap();
        let ids = |result: serde_json::Value| json!({"result": result, "request_id": "r-1", "request_type": "GetBiometricsStatus"});

        assert_eq!(v(Response::Status(Status::Available)), ids(json!({"Ok": "Available"})));
        assert_eq!(v(Response::Status(Status::NotEnabled)), ids(json!({"Ok": "NotEnabled"})));
        assert_eq!(v(Response::Bool(false)), ids(json!({"Ok": false})));
        assert_eq!(v(Response::Discover { version: "bwphone 1".into() }), ids(json!({"Ok": {"version": "bwphone 1"}})));
        assert_eq!(v(Response::Unlock(Some(Zeroizing::new("S0VZ".into())))), ids(json!({"Ok": {"user_key": "S0VZ"}})));
        assert_eq!(v(Response::Unlock(None)), ids(json!({"Ok": {"user_key": null}})));
        assert_eq!(v(Response::NoHandlerFound), ids(json!({"Err": "NoHandlerFound"})));
        assert_eq!(v(Response::RequestDeserialization), ids(json!({"Err": {"RequestDeserialization": "malformed request"}})));
        assert_eq!(format!("{:?}", Response::Unlock(Some(Zeroizing::new("S0VZ".into())))), "Unlock(Some(\"<redacted>\"))");
    }

    /// Worst-case ids, every byte escaped to six: the key's buffer never grows.
    #[test]
    fn encode_never_reallocates() {
        let nasty = "\u{1}".repeat(MAX_ID_LEN);
        let id = CallId { request_id: nasty.clone(), request_type: nasty, response_topic: "t".into() };
        let key = Zeroizing::new("A".repeat(88));
        let cap = ENCODE_BASE + 6 * (id.request_id.len() + id.request_type.len());
        let out = encode(&id, &Response::Unlock(Some(key)));
        assert_eq!(out.capacity(), cap, "reallocated: {} > {cap}", out.len());
    }
}
