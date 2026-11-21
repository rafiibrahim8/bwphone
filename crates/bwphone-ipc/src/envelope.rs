//! The JSON around every frame on the native-messaging pipe
//! (`libs/common/src/platform/ipc/ipc-message.ts`).
//!
//! Extension → host:
//! `{"type":"bitwarden-ipc-message","message":{"destination","payload":[bytes],"topic"}}`.
//!
//! Host → extension: the desktop app's main process forwards what its
//! renderer sends as `forwarded-bitwarden-ipc-message` with
//! `originalSource: "DesktopRenderer"`. A plain `bitwarden-ipc-message`
//! is taken as coming from `DesktopMain`. The extension only accepts a
//! handshake finish or an RPC response from the endpoint it addressed,
//! so a reply must name that endpoint as its source.

use serde::{Deserialize, Serialize};

use crate::IpcError;

pub const IPC_MESSAGE: &str = "bitwarden-ipc-message";
pub const FORWARDED_IPC_MESSAGE: &str = "forwarded-bitwarden-ipc-message";

/// The desktop endpoint the extension addressed: who we answer as.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Us {
    /// The biometrics handlers live here in the real desktop app.
    DesktopRenderer,
    DesktopMain,
}

impl Us {
    fn from_destination(v: &serde_json::Value) -> Option<Self> {
        match v.as_str()? {
            "DesktopRenderer" => Some(Self::DesktopRenderer),
            "DesktopMain" => Some(Self::DesktopMain),
            _ => None,
        }
    }
}

#[derive(Deserialize)]
struct TypeOnly {
    #[serde(rename = "type")]
    kind: Option<String>,
}

/// True for an SDK IPC message, false for anything else (the legacy
/// native-messaging protocol has no `type` field).
pub fn is_ipc(frame: &[u8]) -> bool {
    serde_json::from_slice::<TypeOnly>(frame).is_ok_and(|t| t.kind.as_deref() == Some(IPC_MESSAGE))
}

#[derive(Deserialize)]
struct Incoming {
    #[serde(rename = "type")]
    kind: String,
    message: IncomingBody,
}

#[derive(Deserialize)]
struct IncomingBody {
    destination: serde_json::Value,
    payload: Vec<u8>,
    #[serde(default)]
    topic: Option<String>,
}

/// One envelope from the extension, addressed to a desktop endpoint.
#[derive(Debug)]
pub struct Received {
    pub to: Us,
    pub payload: Vec<u8>,
    pub topic: Option<String>,
}

/// `Ok(None)` for a well-formed envelope addressed somewhere we do not answer for.
pub fn parse(frame: &[u8]) -> Result<Option<Received>, IpcError> {
    let incoming: Incoming = serde_json::from_slice(frame).map_err(|_| IpcError::Envelope)?;
    if incoming.kind != IPC_MESSAGE {
        return Err(IpcError::Envelope);
    }
    let Some(to) = Us::from_destination(&incoming.message.destination) else { return Ok(None) };
    Ok(Some(Received { to, payload: incoming.message.payload, topic: incoming.message.topic }))
}

#[derive(Serialize)]
struct Outgoing<'a> {
    #[serde(rename = "type")]
    kind: &'static str,
    message: OutgoingBody<'a>,
    #[serde(rename = "originalSource", skip_serializing_if = "Option::is_none")]
    original_source: Option<&'static str>,
}

#[derive(Serialize)]
struct OutgoingBody<'a> {
    destination: Destination,
    payload: &'a [u8],
    topic: Option<&'a str>,
}

/// `{"BrowserBackground":{"id":"Own"}}`: the extension's background page,
/// a valid `Endpoint` for the extension to rebuild.
#[derive(Serialize)]
enum Destination {
    BrowserBackground { id: HostId },
}

#[derive(Serialize)]
enum HostId {
    Own,
}

/// Wraps `payload` (a CBOR frame) as `from` sends it to the extension.
pub fn wrap(from: Us, payload: &[u8], topic: Option<&str>) -> Vec<u8> {
    let (kind, original_source) = match from {
        Us::DesktopRenderer => (FORWARDED_IPC_MESSAGE, Some("DesktopRenderer")),
        Us::DesktopMain => (IPC_MESSAGE, None),
    };
    let out = Outgoing {
        kind,
        message: OutgoingBody { destination: Destination::BrowserBackground { id: HostId::Own }, payload, topic },
        original_source,
    };
    serde_json::to_vec(&out).expect("static shape")
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn detects_only_ipc_messages() {
        assert!(is_ipc(br#"{"type":"bitwarden-ipc-message","message":{}}"#));
        assert!(!is_ipc(br#"{"appId":"a","message":{"command":"setupEncryption"}}"#));
        assert!(!is_ipc(br#"{"type":"something-else"}"#));
        assert!(!is_ipc(b"not json"));
    }

    #[test]
    fn parses_what_the_extension_posts() {
        let frame = serde_json::to_vec(&json!({"type": "bitwarden-ipc-message", "message": {
            "destination": "DesktopRenderer", "payload": [1, 2, 255], "topic": null
        }}))
        .unwrap();
        let r = parse(&frame).unwrap().unwrap();
        assert_eq!(r.to, Us::DesktopRenderer);
        assert_eq!(r.payload, [1, 2, 255]);
        assert_eq!(r.topic, None);

        let frame = serde_json::to_vec(&json!({"type": "bitwarden-ipc-message", "message": {
            "destination": "DesktopMain", "payload": [], "topic": "RpcRequestMessage"
        }}))
        .unwrap();
        let r = parse(&frame).unwrap().unwrap();
        assert_eq!((r.to, r.topic.as_deref()), (Us::DesktopMain, Some("RpcRequestMessage")));

        let elsewhere = serde_json::to_vec(&json!({"type": "bitwarden-ipc-message", "message": {
            "destination": {"BrowserBackground": {"id": "Own"}}, "payload": []
        }}))
        .unwrap();
        assert!(parse(&elsewhere).unwrap().is_none());
        assert!(parse(br#"{"type":"bitwarden-ipc-message","message":{"destination":"DesktopRenderer","payload":[256]}}"#).is_err());
    }

    #[test]
    fn replies_name_the_addressed_endpoint_as_source() {
        let v: serde_json::Value = serde_json::from_slice(&wrap(Us::DesktopRenderer, &[1, 2], Some("t"))).unwrap();
        assert_eq!(
            v,
            json!({"type": "forwarded-bitwarden-ipc-message", "message": {
                "destination": {"BrowserBackground": {"id": "Own"}}, "payload": [1, 2], "topic": "t"
            }, "originalSource": "DesktopRenderer"})
        );
        let v: serde_json::Value = serde_json::from_slice(&wrap(Us::DesktopMain, &[], None)).unwrap();
        assert_eq!(
            v,
            json!({"type": "bitwarden-ipc-message", "message": {
                "destination": {"BrowserBackground": {"id": "Own"}}, "payload": [], "topic": null
            }})
        );
    }
}
