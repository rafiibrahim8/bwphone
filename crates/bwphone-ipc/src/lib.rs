//! Bitwarden's SDK IPC biometrics protocol, as the desktop end must speak
//! it. With the server-side `biometrics-sdk-ipc` flag on, the extension
//! asks for biometrics status, unlock and verification over this channel
//! only, never over the legacy native-messaging commands.
//!
//! Implemented from `bitwarden/clients` at `browser-v2026.11.0`
//! (`apps/browser/src/platform/ipc/transports/desktop-ipc.transport.ts`,
//! `apps/browser/src/key-management/biometrics/background-browser-biometrics.service.ts`)
//! and `bitwarden/sdk-internal` at `5b7fbb41`, the `0.2.0-main.1214` that
//! release ships (`crates/bitwarden-ipc`, `crates/bitwarden-shared-unlock`).
//! Written from the protocol, not linked: those crates are GPL-3.0.
//!
//! Layers, outside in:
//! - [`envelope`]: the JSON on the native-messaging pipe.
//! - [`frame`]: CBOR frames: handshake, transport, invalidation.
//! - [`noise`]: the Noise NN responder and the raw-split AEAD transport.
//! - [`rpc`]: the JSON requests and responses inside the channel.
//! - [`peer`]: one pipe's state machine over all of the above.

pub mod envelope;
pub mod frame;
pub mod noise;
pub mod peer;
pub mod rpc;

pub use envelope::is_ipc;

#[derive(Debug, thiserror::Error)]
pub enum IpcError {
    #[error("not an IPC envelope")]
    Envelope,
    #[error("malformed CBOR frame")]
    Cbor,
    #[error("Noise handshake failed")]
    Handshake,
    #[error("transport frame did not decrypt")]
    Decrypt,
    #[error("transport nonce not above the last one: replay")]
    Replay,
    #[error("payload too large for one transport frame")]
    TooLarge,
    #[error("malformed RPC request")]
    Rpc,
    #[error("no session with this endpoint")]
    NoSession,
}
