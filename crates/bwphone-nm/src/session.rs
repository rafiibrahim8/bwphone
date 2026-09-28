//! The per-connection session key and EncString type 2, the encryption
//! every message after the handshake wears.
//!
//! ```text
//! key = 64 bytes: [0..32] AES-256, [32..64] HMAC-SHA256
//! iv  = 16 random bytes
//! ct  = AES-256-CBC(key[0..32], iv, PKCS#7(plaintext))
//! mac = HMAC-SHA256(key[32..64], iv || ct)
//! str = "2." + b64(iv) + "|" + b64(ct) + "|" + b64(mac)
//! ```
//!
//! On the wire it is an object, never a bare string: the extension reads
//! `.encryptionType` and `.encryptedString` off it.

use aes::Aes256;
use cbc::cipher::{BlockDecryptMut as _, BlockEncryptMut as _, KeyIvInit as _, block_padding::Pkcs7};
use hmac::{Hmac, Mac as _};
use rand::RngCore as _;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use zeroize::Zeroizing;

use crate::{NmError, b64, unb64};

type Encryptor = cbc::Encryptor<Aes256>;
type Decryptor = cbc::Decryptor<Aes256>;

/// `EncryptionType.AesCbc256_HmacSha256_B64`.
pub const ENCRYPTION_TYPE: u8 = 2;
const IV_LEN: usize = 16;
const MAC_LEN: usize = 32;

/// 64 bytes from the CSPRNG at `setupEncryption`. Zeroised on drop.
pub struct SessionKey(Zeroizing<[u8; 64]>);

impl SessionKey {
    pub fn generate() -> Self {
        let mut k = Zeroizing::new([0u8; 64]);
        rand::rngs::OsRng.fill_bytes(&mut *k);
        Self(k)
    }

    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut k = Zeroizing::new([0u8; 64]);
        k.copy_from_slice(<&[u8; 64]>::try_from(bytes).ok()?);
        Some(Self(k))
    }

    pub fn as_bytes(&self) -> &[u8; 64] {
        &self.0
    }

    fn enc(&self) -> &[u8] {
        &self.0[..32]
    }

    fn mac(&self) -> &[u8] {
        &self.0[32..]
    }
}

impl std::fmt::Debug for SessionKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SessionKey(..)")
    }
}

/// The object form the extension sends and expects. `encrypted_string` is
/// authoritative; the split fields repeat it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncString {
    pub encrypted_string: String,
    pub encryption_type: u8,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub iv: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub mac: Option<String>,
}

impl EncString {
    pub fn seal(key: &SessionKey, plaintext: &[u8]) -> Self {
        let mut iv = [0u8; IV_LEN];
        rand::rngs::OsRng.fill_bytes(&mut iv);
        let ct = Encryptor::new(key.enc().into(), &iv.into()).encrypt_padded_vec_mut::<Pkcs7>(plaintext);
        let mut mac = Hmac::<Sha256>::new_from_slice(key.mac()).expect("HMAC takes any key length");
        mac.update(&iv);
        mac.update(&ct);
        let (iv, data, mac) = (b64(&iv), b64(&ct), b64(&mac.finalize().into_bytes()));
        Self {
            encrypted_string: format!("{ENCRYPTION_TYPE}.{iv}|{data}|{mac}"),
            encryption_type: ENCRYPTION_TYPE,
            iv: Some(iv),
            data: Some(data),
            mac: Some(mac),
        }
    }

    /// MAC first, in constant time; decrypt only what authenticates.
    pub fn open(&self, key: &SessionKey) -> Result<Zeroizing<Vec<u8>>, NmError> {
        if self.encryption_type != ENCRYPTION_TYPE {
            return Err(NmError::EncryptionType(self.encryption_type));
        }
        let body = self
            .encrypted_string
            .strip_prefix(&format!("{ENCRYPTION_TYPE}."))
            .ok_or(NmError::Malformed("encryptedString does not start with \"2.\""))?;
        let mut parts = body.split('|');
        let (iv, ct, mac) = match (parts.next(), parts.next(), parts.next(), parts.next()) {
            (Some(iv), Some(ct), Some(mac), None) => (unb64(iv)?, unb64(ct)?, unb64(mac)?),
            _ => return Err(NmError::Malformed("encryptedString is not iv|ct|mac")),
        };
        if iv.len() != IV_LEN || mac.len() != MAC_LEN {
            return Err(NmError::Malformed("iv or mac has the wrong length"));
        }
        let mut expected = Hmac::<Sha256>::new_from_slice(key.mac()).expect("HMAC takes any key length");
        expected.update(&iv);
        expected.update(&ct);
        expected.verify_slice(&mac).map_err(|_| NmError::Mac)?;
        let plain = Decryptor::new(key.enc().into(), iv.as_slice().into())
            .decrypt_padded_vec_mut::<Pkcs7>(&ct)
            .map_err(|_| NmError::Malformed("bad block length or padding"))?;
        Ok(Zeroizing::new(plain))
    }
}

/// The CLI's `EncArrayBuffer`: the same cipher, but binary and in a
/// different order — `type(1) || iv(16) || mac(32) || ct`. This is how
/// `data.json` holds the unlocked user key under `BW_SESSION`.
pub fn open_array_buffer(key: &SessionKey, buf: &[u8]) -> Result<Zeroizing<Vec<u8>>, NmError> {
    let Some((&t, rest)) = buf.split_first() else { return Err(NmError::Malformed("empty EncArrayBuffer")) };
    if t != ENCRYPTION_TYPE {
        return Err(NmError::EncryptionType(t));
    }
    if rest.len() < IV_LEN + MAC_LEN + 16 {
        return Err(NmError::Malformed("EncArrayBuffer too short"));
    }
    let (iv, rest) = rest.split_at(IV_LEN);
    let (mac, ct) = rest.split_at(MAC_LEN);
    let mut expected = Hmac::<Sha256>::new_from_slice(key.mac()).expect("HMAC takes any key length");
    expected.update(iv);
    expected.update(ct);
    expected.verify_slice(mac).map_err(|_| NmError::Mac)?;
    let plain = Decryptor::new(key.enc().into(), iv.into())
        .decrypt_padded_vec_mut::<Pkcs7>(ct)
        .map_err(|_| NmError::Malformed("bad block length or padding"))?;
    Ok(Zeroizing::new(plain))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The OpenSSL vector again, in the binary layout: `2 || iv || mac || ct`.
    #[test]
    fn array_buffer_layout_is_iv_mac_ct() {
        let iv = unb64("EBESExQVFhcYGRobHB0eHw==").unwrap();
        let ct = unb64("qvdjEcOQngx3KQqL0nFQhqx62SMkb0tCw5xmi3rOimgmpF6qtVjiJJG3A511RraTBCxLBtBcP0I4ygtB9Wvd1ayy9b5g90iU+v3qUw9KQgk=").unwrap();
        let mac = unb64("i//GexfhCkk4ymWiZJhQNPxY7FO3GHl3KEefu4RArgk=").unwrap();
        let buf = [&[2u8][..], &iv, &mac, &ct].concat();
        assert_eq!(&*open_array_buffer(&fixed_key(), &buf).unwrap(), br#"{"command":"getBiometricsStatus","messageId":7,"timestamp":1790500000000}"#);
        let string_order = [&[2u8][..], &iv, &ct, &mac].concat();
        assert!(matches!(open_array_buffer(&fixed_key(), &string_order), Err(NmError::Mac)), "the string order must not be accepted");
        assert!(matches!(open_array_buffer(&fixed_key(), &[0u8; 80]), Err(NmError::EncryptionType(0))));
    }

    fn fixed_key() -> SessionKey {
        SessionKey::from_slice(&std::array::from_fn::<u8, 64, _>(|i| i as u8)).unwrap()
    }

    /// Computed independently with `openssl enc -aes-256-cbc` and
    /// `openssl dgst -sha256 -mac HMAC` over iv || ct, key 0x00..0x3f, iv 0x10..0x1f.
    #[test]
    fn known_answer_from_openssl() {
        let iv = "EBESExQVFhcYGRobHB0eHw==";
        let ct = "qvdjEcOQngx3KQqL0nFQhqx62SMkb0tCw5xmi3rOimgmpF6qtVjiJJG3A511RraTBCxLBtBcP0I4ygtB9Wvd1ayy9b5g90iU+v3qUw9KQgk=";
        let mac = "i//GexfhCkk4ymWiZJhQNPxY7FO3GHl3KEefu4RArgk=";
        let enc = EncString {
            encrypted_string: format!("2.{iv}|{ct}|{mac}"),
            encryption_type: 2,
            iv: None,
            data: None,
            mac: None,
        };
        let plain = enc.open(&fixed_key()).unwrap();
        assert_eq!(&*plain, br#"{"command":"getBiometricsStatus","messageId":7,"timestamp":1790500000000}"#);
    }

    #[test]
    fn seal_open_round_trip_and_object_shape() {
        let key = fixed_key();
        let enc = EncString::seal(&key, b"{\"response\":true}");
        assert_eq!(&*enc.open(&key).unwrap(), b"{\"response\":true}");
        assert_eq!(enc.encryption_type, 2);
        let expected = format!(
            "2.{}|{}|{}",
            enc.iv.as_ref().unwrap(),
            enc.data.as_ref().unwrap(),
            enc.mac.as_ref().unwrap()
        );
        assert_eq!(enc.encrypted_string, expected);
        assert_eq!(unb64(enc.iv.as_ref().unwrap()).unwrap().len(), 16);

        let json = serde_json::to_value(&enc).unwrap();
        assert!(json.is_object(), "must be the object form, never a bare string");
        for field in ["encryptedString", "encryptionType", "iv", "data", "mac"] {
            assert!(json.get(field).is_some(), "missing {field}");
        }
        assert_eq!(serde_json::from_value::<EncString>(json).unwrap(), enc);
        assert!(serde_json::from_str::<EncString>("\"2.a|b|c\"").is_err());

        assert_ne!(EncString::seal(&key, b"x").iv, EncString::seal(&key, b"x").iv, "iv must be fresh");
    }

    #[test]
    fn tampering_and_wrong_keys_fail_the_mac() {
        let key = fixed_key();
        let enc = EncString::seal(&key, b"secret");
        let other = SessionKey::generate();
        assert!(matches!(enc.open(&other), Err(NmError::Mac)));

        let mut tampered = enc.clone();
        let mut bytes = unb64(tampered.data.as_ref().unwrap()).unwrap();
        bytes[0] ^= 1;
        let data = b64(&bytes);
        tampered.encrypted_string =
            format!("2.{}|{}|{}", tampered.iv.as_ref().unwrap(), data, tampered.mac.as_ref().unwrap());
        assert!(matches!(tampered.open(&key), Err(NmError::Mac)));

        let mut wrong_type = enc.clone();
        wrong_type.encryption_type = 0;
        assert!(matches!(wrong_type.open(&key), Err(NmError::EncryptionType(0))));

        let mut malformed = enc.clone();
        malformed.encrypted_string = "2.onlyone".into();
        assert!(matches!(malformed.open(&key), Err(NmError::Malformed(_))));
    }

    #[test]
    fn session_key_does_not_print() {
        assert_eq!(format!("{:?}", fixed_key()), "SessionKey(..)");
        assert!(SessionKey::from_slice(&[0; 63]).is_none());
    }
}
