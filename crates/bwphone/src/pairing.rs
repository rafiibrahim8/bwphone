//! `pairing.json`, 0644, nothing secret: the phone's X25519 public key, the
//! pairing ID, its label, the port it listens on, and where it was last
//! heard from.

use std::{
    fs, io,
    net::{IpAddr, SocketAddr},
    path::Path,
};

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
    /// The port the last hello announced. The phone falls back to an
    /// ephemeral port when its own is taken, so this can differ from
    /// `phone_port`; absent until the first hello.
    #[serde(default)]
    pub last_port: Option<u16>,
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

    /// Where to reach the phone: the last hello's address and port, or the
    /// port from pairing if no hello has named one yet.
    pub fn last_phone_addr(&self) -> Option<SocketAddr> {
        self.last_address.map(|ip| SocketAddr::new(ip, self.last_port.unwrap_or(self.phone_port)))
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
            last_port: None,
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
        assert_eq!(p.last_phone_addr(), Some("10.0.0.7:8731".parse().unwrap()), "no hello yet: the paired port");
        p.last_port = Some(40123);
        assert_eq!(p.last_phone_addr(), Some("10.0.0.7:40123".parse().unwrap()));
        p.last_hello_seq = 4;
        p.save(&path).unwrap();
        let loaded = Pairing::load(&path).unwrap().unwrap();
        assert_eq!(loaded, p);
        assert_eq!(loaded.phone_pub().unwrap(), [1; 32]);
        assert_eq!(loaded.pairing_id().unwrap(), [2; 16]);

        // A pairing.json written before last_port existed still loads.
        let old = r#"{"phone_x25519_pub":"AQ==","pairing_id":"Ag==","device_label":"Pixel","paired_at":"x","phone_port":8731,"last_address":"10.0.0.7"}"#;
        let old: Pairing = serde_json::from_str(old).unwrap();
        assert_eq!(old.last_port, None);
        assert_eq!(old.last_phone_addr(), Some("10.0.0.7:8731".parse().unwrap()));

        let bad = Pairing { phone_x25519_pub: "AAAA".into(), ..p };
        assert!(matches!(bad.phone_pub(), Err(PairingError::Key("phone_x25519_pub"))));
        fs::remove_dir_all(&dir).unwrap();
    }
}
