//! The Noise static private key and `hello_key` live in the wallet (ksecretd,
//! over `org.freedesktop.secrets`), never in a file. The daemon reads each
//! once, keeps it in zeroised memory, and does not touch D-Bus again while
//! serving. Until the wallet is unlocked it reports unavailable and tries
//! again on the next request.
//!
//! The daemon is the only process that reads the wallet: `bwphone-hello`
//! gets `hello_key` from the daemon over its socket, so it can run with no
//! session bus at all.
//!
//! Item attributes are `service=bwphone`, `key=noise-static` / `key=hello`.
//! Labels and attributes are plaintext on disk, so they say nothing more.

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use bwphone_transport::unb64;
use secret_service::{EncryptionType, SecretService};
use zeroize::{Zeroize as _, Zeroizing};

pub const SERVICE: &str = "bwphone";
pub const NOISE_STATIC: &str = "noise-static";
pub const HELLO: &str = "hello";

#[derive(Debug, thiserror::Error, Clone, PartialEq, Eq)]
pub enum SecretsError {
    #[error("the wallet is locked")]
    Locked,
    #[error("no `{0}` item in the wallet: pair first")]
    Missing(&'static str),
    #[error("wallet item `{0}` is not a 32-byte key")]
    Shape(&'static str),
    #[error("secret service: {0}")]
    Bus(String),
}

pub struct Key32(Zeroizing<[u8; 32]>);

impl Key32 {
    pub fn new(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl std::fmt::Debug for Key32 {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("Key32(..)")
    }
}

type Cache = Mutex<Option<Arc<Key32>>>;

pub enum Secrets {
    /// The wallet, each item read once and cached.
    Wallet { noise: Cache, hello: Cache },
    /// Keys handed in directly: tests and the fake-phone dev loop.
    Fixed { noise: Arc<Key32>, hello: Option<Arc<Key32>> },
}

impl Secrets {
    pub fn wallet() -> Self {
        Self::Wallet { noise: Mutex::new(None), hello: Mutex::new(None) }
    }

    pub fn fixed(noise: [u8; 32]) -> Self {
        Self::Fixed { noise: Arc::new(Key32::new(noise)), hello: None }
    }

    pub fn fixed_with_hello(noise: [u8; 32], hello: [u8; 32]) -> Self {
        Self::Fixed { noise: Arc::new(Key32::new(noise)), hello: Some(Arc::new(Key32::new(hello))) }
    }

    pub async fn noise_static(&self) -> Result<Arc<Key32>, SecretsError> {
        match self {
            Self::Fixed { noise, .. } => Ok(noise.clone()),
            Self::Wallet { noise, .. } => cached(noise, NOISE_STATIC).await,
        }
    }

    pub async fn hello_key(&self) -> Result<Arc<Key32>, SecretsError> {
        match self {
            Self::Fixed { hello, .. } => hello.clone().ok_or(SecretsError::Missing(HELLO)),
            Self::Wallet { hello, .. } => cached(hello, HELLO).await,
        }
    }
}

async fn cached(cache: &Cache, key: &'static str) -> Result<Arc<Key32>, SecretsError> {
    if let Some(k) = cache.lock().unwrap().clone() {
        return Ok(k);
    }
    let k = Arc::new(read_item(key).await?);
    *cache.lock().unwrap() = Some(k.clone());
    Ok(k)
}

/// One item, by its `key` attribute. Stored raw (32 bytes) or as base64.
pub async fn read_item(key: &'static str) -> Result<Key32, SecretsError> {
    let ss = SecretService::connect(EncryptionType::Dh).await.map_err(bus)?;
    let found = ss.search_items(HashMap::from([("service", SERVICE), ("key", key)])).await.map_err(bus)?;
    let Some(item) = found.unlocked.first() else {
        return Err(if found.locked.is_empty() { SecretsError::Missing(key) } else { SecretsError::Locked });
    };
    let mut raw = item.get_secret().await.map_err(bus)?;
    let parsed = <[u8; 32]>::try_from(raw.as_slice())
        .ok()
        .or_else(|| std::str::from_utf8(&raw).ok().and_then(|s| unb64(s.trim()).ok()).and_then(|v| v.try_into().ok()));
    raw.zeroize();
    parsed.map(Key32::new).ok_or(SecretsError::Shape(key))
}

/// Pairing writes here: raw 32 bytes, replacing any earlier item.
pub async fn write_item(key: &'static str, label: &str, value: &[u8; 32]) -> Result<(), SecretsError> {
    let ss = SecretService::connect(EncryptionType::Dh).await.map_err(bus)?;
    let collection = ss.get_default_collection().await.map_err(bus)?;
    collection.ensure_unlocked().await.map_err(bus)?;
    collection
        .create_item(label, HashMap::from([("service", SERVICE), ("key", key)]), value, true, "application/octet-stream")
        .await
        .map_err(bus)?;
    Ok(())
}

fn bus(e: secret_service::Error) -> SecretsError {
    SecretsError::Bus(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Against the live wallet: `cargo test -p bwphone live_wallet -- --ignored`.
    /// Proves the D-Bus plumbing; the item itself need not exist yet.
    #[tokio::test]
    #[ignore]
    async fn live_wallet_smoke() {
        match read_item(NOISE_STATIC).await {
            Ok(k) => assert_eq!(k.as_bytes().len(), 32),
            Err(SecretsError::Missing(_)) | Err(SecretsError::Locked) => {}
            Err(e) => panic!("{e}"),
        }
    }
}
