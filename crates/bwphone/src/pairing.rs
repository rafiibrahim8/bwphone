//! `pairing.json`, 0644, nothing secret: the phone's X25519 public key, the
//! pairing ID, its label, the port it listens on, and where it was last
//! heard from.

use std::{fs, io, net::IpAddr, path::Path};

use bwphone_transport::{b64, unb64};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Pairing {
    pub phone_x25519_pub: String,
    pub pairing_id: String,
    pub device_label: String,
    pub paired_at: String,
    pub phone_port: u16,
    /// Where `bwphone-hello` listens for the phone's address announcements.
    #[serde(default = "default_hello_port")]
    pub hello_port: u16,
    #[serde(default)]
    pub last_address: Option<IpAddr>,
    #[serde(default)]
    pub last_hello_seq: u64,
}

#[derive(Debug, thiserror::Error)]
pub enum PairingError {
    #[error("i/o: {0}")]
    Io(#[from] io::Error),
    #[error("pairing.json: {0}")]
    Json(#[from] serde_json::Error),
    #[error("pairing.json: {0} is not 32 bytes of base64")]
    Key(&'static str),
}

impl Pairing {
    pub fn load(path: &Path) -> Result<Option<Self>, PairingError> {
        match fs::read(path) {
            Ok(bytes) => Ok(Some(serde_json::from_slice(&bytes)?)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(e) => Err(e.into()),
        }
    }

    pub fn save(&self, path: &Path) -> Result<(), PairingError> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let tmp = path.with_extension("json.tmp");
        fs::write(&tmp, serde_json::to_vec_pretty(self)?)?;
        fs::rename(&tmp, path)?;
        Ok(())
    }

    pub fn phone_pub(&self) -> Result<[u8; 32], PairingError> {
        decode(&self.phone_x25519_pub).ok_or(PairingError::Key("phone_x25519_pub"))
    }

    pub fn pairing_id(&self) -> Result<[u8; 16], PairingError> {
        unb64(&self.pairing_id).ok().and_then(|v| v.try_into().ok()).ok_or(PairingError::Key("pairing_id"))
    }

    pub fn new(phone_pub: &[u8; 32], pairing_id: &[u8; 16], device_label: &str, phone_port: u16, paired_at: &str) -> Self {
        Self {
            phone_x25519_pub: b64(phone_pub),
            pairing_id: b64(pairing_id),
            device_label: device_label.into(),
            paired_at: paired_at.into(),
            phone_port,
            hello_port: default_hello_port(),
            last_address: None,
            last_hello_seq: 0,
        }
    }
}

fn default_hello_port() -> u16 {
    bwphone_transport::DEFAULT_HELLO_PORT
}

fn decode(s: &str) -> Option<[u8; 32]> {
    unb64(s).ok()?.try_into().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_and_bad_keys() {
        let dir = std::env::temp_dir().join(format!("bwphone-pairing-{}", std::process::id()));
        let path = dir.join("pairing.json");
        let _ = fs::remove_dir_all(&dir);
        assert_eq!(Pairing::load(&path).unwrap(), None);

        let mut p = Pairing::new(&[1; 32], &[2; 16], "Pixel", 8731, "2026-09-27");
        p.last_address = Some("10.0.0.7".parse().unwrap());
        p.last_hello_seq = 4;
        p.save(&path).unwrap();
        let loaded = Pairing::load(&path).unwrap().unwrap();
        assert_eq!(loaded, p);
        assert_eq!(loaded.phone_pub().unwrap(), [1; 32]);
        assert_eq!(loaded.pairing_id().unwrap(), [2; 16]);

        let bad = Pairing { phone_x25519_pub: "AAAA".into(), ..p };
        assert!(matches!(bad.phone_pub(), Err(PairingError::Key("phone_x25519_pub"))));
        fs::remove_dir_all(&dir).unwrap();
    }
}
