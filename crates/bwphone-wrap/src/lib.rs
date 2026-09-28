//! `vault.blob`, version 0x04: one account's user key, wrapped once at
//! enrollment and never rewritten.
//!
//! ```text
//! offset  size  field
//! 0       1     version = 0x04
//! 1       256   RSA-2048-OAEP ciphertext of K_wrap: SHA-256 label hash, MGF1-SHA1
//! 257     12    AES-256-GCM nonce
//! 269     80    ciphertext + tag over the 64-byte user key
//! ```
//!
//! 349 bytes. AAD is bytes 0..257 (version ‖ rsa_ct), so a forged RSA
//! ciphertext paired with the real AES ciphertext fails the tag. The phone
//! decrypts only `K_wrap`; the user key never leaves the PC.
//!
//! Why MGF1 is SHA-1: Android Keystore before Android 14 accepts no other
//! MGF1 digest for OAEP (`AndroidKeyStoreRSACipherSpi`: "Only SHA-1
//! supported"), and the app runs from Android 9. MGF1 relies on no collision
//! resistance, so SHA-1 there costs nothing; it is also the Keystore default.
//!
//! Versions 0x01 and 0x02 belong to drafts that never ran, and 0x03 used
//! MGF1-SHA256, which Android 12 and 13 cannot decrypt. All three are refused
//! before anything else happens.

pub mod phone;
pub mod store;

use aes_gcm::{
    Aes256Gcm, Nonce,
    aead::{Aead, KeyInit, Payload},
};
use rand::RngCore as _;
use rsa::{Oaep, RsaPublicKey, traits::PublicKeyParts as _};
use sha1::Sha1;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

pub use rsa;

pub const VERSION: u8 = 0x04;
pub const RSA_CT_LEN: usize = 256;
pub const NONCE_LEN: usize = 12;
pub const USER_KEY_LEN: usize = 64;
pub const TAG_LEN: usize = 16;
pub const K_WRAP_LEN: usize = 32;
/// version ‖ rsa_ct: the AAD.
pub const HEADER_LEN: usize = 1 + RSA_CT_LEN;
pub const BLOB_LEN: usize = HEADER_LEN + NONCE_LEN + USER_KEY_LEN + TAG_LEN;

#[derive(Debug, thiserror::Error)]
pub enum WrapError {
    #[error("blob is {0} bytes, not {BLOB_LEN}")]
    Length(usize),
    #[error("blob version 0x{0:02x} is retired; revoke the account on the phone and enroll it again")]
    RetiredVersion(u8),
    #[error("unknown blob version 0x{0:02x}")]
    UnknownVersion(u8),
    #[error("RSA modulus is {0} bytes, not {RSA_CT_LEN}")]
    KeySize(usize),
    #[error("rsa: {0}")]
    Rsa(#[from] rsa::Error),
    #[error("authentication failed: wrong K_wrap, or the blob was altered")]
    Authentication,
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
}

/// The 64-byte Bitwarden user key. Zeroised on drop, never printed.
pub struct UserKey(Zeroizing<[u8; USER_KEY_LEN]>);

impl UserKey {
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut k = Zeroizing::new([0u8; USER_KEY_LEN]);
        k.copy_from_slice(<&[u8; USER_KEY_LEN]>::try_from(bytes).ok()?);
        Some(Self(k))
    }

    pub fn as_bytes(&self) -> &[u8; USER_KEY_LEN] {
        &self.0
    }

    /// SHA-256 of the key as hex: the only form of it that is ever shown,
    /// compared at enrollment against `bwphone unlock --dry-run`.
    pub fn fingerprint(&self) -> String {
        hex(&Sha256::digest(self.0.as_slice()))
    }
}

impl PartialEq for UserKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&*other.0).into()
    }
}

impl std::fmt::Debug for UserKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("UserKey(..)")
    }
}

/// The 32-byte AES key that seals the user key. Zeroised on drop.
pub struct KWrap(Zeroizing<[u8; K_WRAP_LEN]>);

impl KWrap {
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        let mut k = Zeroizing::new([0u8; K_WRAP_LEN]);
        k.copy_from_slice(<&[u8; K_WRAP_LEN]>::try_from(bytes).ok()?);
        Some(Self(k))
    }

    pub fn as_bytes(&self) -> &[u8; K_WRAP_LEN] {
        &self.0
    }
}

impl std::fmt::Debug for KWrap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("KWrap(..)")
    }
}

/// A parsed, version-checked blob. Inert without the phone.
#[derive(Clone, PartialEq, Eq)]
pub struct Blob([u8; BLOB_LEN]);

impl Blob {
    /// Refuses retired versions first, so a 0x01, 0x02 or 0x03 blob is named
    /// as such rather than failing a length check.
    pub fn parse(bytes: &[u8]) -> Result<Self, WrapError> {
        match bytes.first() {
            Some(&VERSION) => {}
            Some(&v @ 0x01..=0x03) => return Err(WrapError::RetiredVersion(v)),
            Some(&v) => return Err(WrapError::UnknownVersion(v)),
            None => return Err(WrapError::Length(0)),
        }
        let bytes = <[u8; BLOB_LEN]>::try_from(bytes).map_err(|_| WrapError::Length(bytes.len()))?;
        Ok(Self(bytes))
    }

    pub fn as_bytes(&self) -> &[u8; BLOB_LEN] {
        &self.0
    }

    /// version ‖ rsa_ct, the GCM AAD.
    pub fn header(&self) -> &[u8] {
        &self.0[..HEADER_LEN]
    }

    /// What goes to the phone.
    pub fn rsa_ct(&self) -> &[u8; RSA_CT_LEN] {
        self.0[1..HEADER_LEN].try_into().expect("fixed offsets")
    }

    fn nonce(&self) -> &[u8] {
        &self.0[HEADER_LEN..HEADER_LEN + NONCE_LEN]
    }

    fn sealed(&self) -> &[u8] {
        &self.0[HEADER_LEN + NONCE_LEN..]
    }
}

impl std::fmt::Debug for Blob {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Blob(v{}, rsa_ct {})", self.0[0], hex(&Sha256::digest(self.rsa_ct())[..4]))
    }
}

/// Enrollment step 1–5: a fresh `K_wrap` sealed to the account's RSA key
/// and the user key sealed under `K_wrap`. `K_wrap` is zeroised before this
/// returns; the only way to get it back is the phone.
pub fn wrap(phone_rsa_pub: &RsaPublicKey, user_key: &UserKey) -> Result<Blob, WrapError> {
    let size = phone_rsa_pub.size();
    if size != RSA_CT_LEN {
        return Err(WrapError::KeySize(size));
    }
    let mut rng = rand::rngs::OsRng;

    let mut k_wrap = KWrap(Zeroizing::new([0u8; K_WRAP_LEN]));
    rng.fill_bytes(&mut *k_wrap.0);
    let rsa_ct = phone_rsa_pub.encrypt(&mut rng, oaep(), k_wrap.as_bytes())?;
    let mut nonce = [0u8; NONCE_LEN];
    rng.fill_bytes(&mut nonce);

    let mut bytes = [0u8; BLOB_LEN];
    bytes[0] = VERSION;
    bytes[1..HEADER_LEN].copy_from_slice(&rsa_ct);
    bytes[HEADER_LEN..HEADER_LEN + NONCE_LEN].copy_from_slice(&nonce);
    let sealed = Aes256Gcm::new(k_wrap.as_bytes().into())
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload { msg: user_key.as_bytes(), aad: &bytes[..HEADER_LEN] },
        )
        .map_err(|_| WrapError::Authentication)?;
    bytes[HEADER_LEN + NONCE_LEN..].copy_from_slice(&sealed);
    Ok(Blob(bytes))
}

/// Unwrap step 5: open the user key with the `K_wrap` the phone returned.
/// A tag mismatch means the wrong key or an altered blob; the caller aborts
/// loudly and writes nothing.
pub fn unwrap(blob: &Blob, k_wrap: &KWrap) -> Result<UserKey, WrapError> {
    let opened = Zeroizing::new(
        Aes256Gcm::new(k_wrap.as_bytes().into())
            .decrypt(Nonce::from_slice(blob.nonce()), Payload { msg: blob.sealed(), aad: blob.header() })
            .map_err(|_| WrapError::Authentication)?,
    );
    UserKey::from_slice(&opened).ok_or(WrapError::Authentication)
}

/// RSA-OAEP as both ends run it: SHA-256 label hash, MGF1-SHA1. On the
/// phone: `OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, …)`.
pub fn oaep() -> Oaep {
    Oaep::new_with_mgf_hash::<Sha256, Sha1>()
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[cfg(test)]
pub(crate) mod testkeys {
    use rsa::{RsaPrivateKey, RsaPublicKey, pkcs8::DecodePrivateKey as _};

    /// A fixed RSA-2048 keypair, standing in for one account's Keystore key.
    pub const ACCOUNT_A: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC6MQOKZ9cQx9YQ
fClGiakoNOANrvTZ8DDStG6U85+c9Lw1zvC8jcqLs+IqdlpNnJcKpQKYYIYt3+tL
BQQFVeC4d6GTET3oSmmMbj3nru6Jmsyj8cvQjjZ3Yj2arGRdfM17kTQhukUDubKN
vDrlEYDl8Se4bq2LpWn99Ky/zRtJVagQNvuC9GbzTRI+400zsob1OqEop4i4d9DB
44ckFW/paJb9oZcSJirRbmD9hapzaHmP6pnXlDiWIbclOO1Qs8JPmT3MLBvC+pKm
rJ9SqlRlG5YNzRcVsw8WH/2s12nP5WyXI5N3P0DdnccwS8hqidvuSVL1/J5Y2kI8
ye8osvUxAgMBAAECggEADrmXnRePQ616OX2ISiLS9PIRkiN3C9FaGx/X6wHFasVU
KTE/irnv/dJxHYiUpbSvoVDhfqmLkw81bY5s/fsHta8IYTgo3DkeVdPWI3+LL+jF
LGYQB2Nn3VMwqg3eNiKLoa0fIVe4442JGHp9ceZLemPzDzv5j6S6WDJEgzq2YLs5
7XKvjXeVvNzdkN7hdOXOBcsjIvZGjcJmnkftz94z+aqx+MpteKyVRlRqPy3dfONw
w2C816zrPH2ilQp5hQEZhOP1d/FmTb+MWa0Zx9mecvz0UGD4Ek4Qxe53f4qWcsTl
WXNxO3wTEs27PXqspc/4xrIZD5xA+fBigsqyF8G/EQKBgQDhdKoN1ncRhaSuGtAg
4blUvuglk9nxcvENLQ7GwmZx9uAMQdLKhsLl0o5LZ5+5JEYI1GsSh7jIVj2B56Nn
QLFLl2SGW0Y3vOPfE1BE+ELSxrKgRcNvfErsvjFsWLwYe3IysjYBgumaqDMh0sCm
GVcaiq5yGAuSWOWaqW0O/EbwhQKBgQDTapKPISWzpYo9oMSsNSoyep+vr2e396+9
q4ZDO04XlqF0FoWJkEZgqNlv8anZRGuCOerle4gePPvQWSRjREkRnTbSnJE4YOEB
2euEu+8sCpvFEG7JqpaoZOkDuHeug/LM6vbSdtz02N17E0MD3hVvzzymZqTOP//k
0DQuoqzHvQKBgQCy7Y/4o3ij41irBIShVANuCoTbLdgOE5bTSisr+ySq1a9Ciwrr
yL/s/YoIthjBKtSaNVs0vZodBLST4G6Ch4kt4Nza9J1ppvOCGyXdVtpRxXgGUtek
JxSfhuJahqHhHDepnF3YHTmgkFTkRwq1x+6lFeMUkZi9cOfoMwZmmjkCsQKBgGdr
W7ROd73wfbZ1/Z9sBm9ZEuKDQI56yGpVDMG4shPR6Lr8BWjsvbCtCGi9Y+PXl2vF
30VQ754zIM+ju6wfjErkiBvw4Q0ePxODwbVVpcL6kYaN6lQWccqASog6Zbll7JEX
Y5RC9wWDTJzXKFItAnmGe9m+nmISZqBMxSoHA9RVAoGAWkCrf/+h7fSZXmwbbRUa
jmKfCd+euZpz+ILoPh8RBwYFdb8h23h9tm2te14hr4TJauYcVrAyTwcqBU7NNtFw
BI3iwIaBsTclk92AlLmSme4H4o+kojoCQf4HnnZcVG+vk9BPMlHY4kjwoCX5EaSD
mPNAvFv20T4Uz4cKejKx/LI=
-----END PRIVATE KEY-----";

    pub fn account_a() -> (RsaPrivateKey, RsaPublicKey) {
        let private = RsaPrivateKey::from_pkcs8_pem(ACCOUNT_A).unwrap();
        let public = RsaPublicKey::from(&private);
        (private, public)
    }

    pub fn account_b() -> (RsaPrivateKey, RsaPublicKey) {
        let private = RsaPrivateKey::from_pkcs8_pem(ACCOUNT_B).unwrap();
        let public = RsaPublicKey::from(&private);
        (private, public)
    }

    /// The fixed user key of the known-answer tests: 0x00..0x3f.
    pub fn user_key() -> super::UserKey {
        super::UserKey::from_slice(&std::array::from_fn::<u8, 64, _>(|i| i as u8)).unwrap()
    }

    /// A second fixed keypair: another account's key, for the cross-account test.
    pub const ACCOUNT_B: &str = "-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQCq5QDN64hZSm6z
7OLtYSVJxx/hDsAVSOH5jeS3tPADQlMaB1MEgBwLKr00wSQtw17tJBK0LI3+/Ima
+HtZJu04LEhE9/Nh1rkToAB0+BObzkpYx9V4P0UhJgdo8x1bjupLrfafVos85CEL
RxDA7gtOJcqkkFItrxBIJjLx+yGDmXwYioDJve+T7tePxHAdqgY4ItatHmYPo3ey
wHCfd82w36sFdnWM0ex2T1sXEMJUFyErnAyr86m8np2ohZVBIhXE5o3KjQ2V7nI2
eiaIz67n8ag97bqgwkFIX5IIsSitsIAXnNUWnPpb+anDz1FC+VjlKA01KPm90ZP+
4TM9sAyjAgMBAAECggEAEVKDIVxVhs9/pydE3VDyiabweUyYdc/ccAJNA74Ichwf
9kx1wsgFj7A2W4mUVDswfRMh/jdh8U3B2P6E6kWC2CXM8Yi8l9c/DVkzkqeuvSVM
7fDbl4O6SyDisWWrPSOgZiltDTulg3eQTedXMGcwqCw2fTXPzqenG9kbYuHUxNT4
kwEAsMgTj0hgRA11M8nowQfeVS3Qtzjxb1Mz2lwO9OfsEBgQwNI0IYES9bkqo5bi
MctD8wufWhtdjKzwGA7WseczY5P1m678UmRrZcCOXJzA/+nXlqinJI7zJUrwP5nY
pJlH8IbVMf6K+6gEWuiFEzNsUH1vUJyV4gftas1pAQKBgQDRTZF1YLXd8QzSX0p7
v2QmmO1wmJgTa8kSpWt695wInDkEr0xIgF9Ac7D4fTVByMv5yqxdrJtLAbn9IkMf
9w0HQL+K4T4C+QzTmdKxh19JMFHBGV2mpas+QBIpl7gpITujbW4FOkTpYAIDB+5x
PCP9FC1VxXik9ZlwUu+lGh6BgQKBgQDRBbgfMB8jqFuLUchn2oLlGLDvCcRo39Rb
j8r9sC+TQQLyVJ5LErspV9qtaKQcW5p4jLJEC7tk8eVfW20qc3kvUiyWhA8j6B7u
chS3jVRWkNoln7GprVA1Rrp6gXaRnvNUkvyT56Thg3kPC5xu7I5f35qpuHS45iCw
nZOfrwBYIwKBgGOCE2PQxOZt0gC6mTjYN486Kbjcc4DYP9KDnuPpkN9vFpSpmwTl
M2P7HOom7QkHpCJwPx6SD4rLmVdF0NADrsgB+o7Wo5raOUTo3wjUKXMsa9H4c1Pl
c9K2t2va3A2B5U6/mg0WNOkXYh16ydxAEYQi8aLTrZYPxhFm/NRr5JEBAoGAaYe5
rgVds2MM1Qo1ZDmuXHxa2FTWFRzs2k1+7xZE7tOj6TVPthd+5yC0B1kNgkO9eZ+P
YUuLESwP4lUGiKhERt/2IwgJnNdUxo5SZ1mzewEnIle+GyylkkBjZfZ3Jo5ZzBlp
7ELHvBPkyvPRxy8nsr/yFj5KsA9/8audHMH+KoECgYEAgL/h47tMbzqAx54kwTxU
XqCsgOly75BFu0QFMGlix3zMDeTf7HSO97runCicOx3cLjjqTlFez5WlokmdQJz0
a+Nf7b59rnfNXVTgESem0Wx3gJLYGs97QokCn8aN3GCWekfdjBJK+O6tAa9gsOH4
PQnakctn8mhKxp4yVRCI4Pk=
-----END PRIVATE KEY-----";
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::phone;
    use crate::testkeys::{account_a, account_b, user_key};

    #[test]
    fn layout_is_349_bytes() {
        assert_eq!(BLOB_LEN, 349);
        assert_eq!(HEADER_LEN, 257);
    }

    #[test]
    fn round_trip_through_the_phone() {
        let (private, public) = account_a();
        let key = user_key();
        let blob = wrap(&public, &key).unwrap();
        let reparsed = Blob::parse(blob.as_bytes()).unwrap();
        assert_eq!(reparsed, blob);

        let k_wrap = phone::decrypt_k_wrap(&private, blob.rsa_ct()).unwrap();
        let opened = unwrap(&blob, &k_wrap).unwrap();
        assert!(opened == key);
        assert_eq!(opened.fingerprint(), key.fingerprint());
        assert_eq!(opened.fingerprint().len(), 64);
    }

    #[test]
    fn two_wraps_of_one_key_differ() {
        let (_, public) = account_a();
        let key = user_key();
        let a = wrap(&public, &key).unwrap();
        let b = wrap(&public, &key).unwrap();
        assert_ne!(a.rsa_ct(), b.rsa_ct(), "K_wrap must be fresh");
        assert_ne!(a.nonce(), b.nonce(), "nonce must be fresh");
    }

    #[test]
    fn every_single_bit_flip_is_refused() {
        let (private, public) = account_a();
        let blob = wrap(&public, &user_key()).unwrap();
        let k_wrap = phone::decrypt_k_wrap(&private, blob.rsa_ct()).unwrap();
        for byte in 0..BLOB_LEN {
            for bit in 0..8 {
                let mut bytes = *blob.as_bytes();
                bytes[byte] ^= 1 << bit;
                let outcome = Blob::parse(&bytes).and_then(|b| unwrap(&b, &k_wrap));
                assert!(outcome.is_err(), "flipping byte {byte} bit {bit} was accepted");
            }
        }
    }

    #[test]
    fn substituted_rsa_ct_fails_the_tag() {
        let (private, public) = account_a();
        let key = user_key();
        let real = wrap(&public, &key).unwrap();
        let other = wrap(&public, &key).unwrap();

        // The real AES ciphertext under a header carrying someone else's K_wrap.
        let mut forged = *real.as_bytes();
        forged[1..HEADER_LEN].copy_from_slice(other.rsa_ct());
        let forged = Blob::parse(&forged).unwrap();

        // The phone decrypts the substituted rsa_ct happily; the PC's open must not.
        let k_other = phone::decrypt_k_wrap(&private, forged.rsa_ct()).unwrap();
        assert!(matches!(unwrap(&forged, &k_other), Err(WrapError::Authentication)));
        // And the right K_wrap against the altered AAD fails too.
        let k_real = phone::decrypt_k_wrap(&private, real.rsa_ct()).unwrap();
        assert!(matches!(unwrap(&forged, &k_real), Err(WrapError::Authentication)));
    }

    #[test]
    fn retired_and_unknown_versions_are_refused_before_anything_else() {
        let (_, public) = account_a();
        let mut bytes = *wrap(&public, &user_key()).unwrap().as_bytes();
        for v in [0x01, 0x02, 0x03] {
            bytes[0] = v;
            assert!(matches!(Blob::parse(&bytes), Err(WrapError::RetiredVersion(x)) if x == v));
            // Even at a different length: the version is what is named.
            assert!(matches!(Blob::parse(&bytes[..190]), Err(WrapError::RetiredVersion(x)) if x == v));
        }
        bytes[0] = 0x05;
        assert!(matches!(Blob::parse(&bytes), Err(WrapError::UnknownVersion(0x05))));
        bytes[0] = VERSION;
        assert!(matches!(Blob::parse(&bytes[..BLOB_LEN - 1]), Err(WrapError::Length(348))));
        assert!(matches!(Blob::parse(&[]), Err(WrapError::Length(0))));
    }

    /// The MGF1 trap, both ways: a wrap under MGF1-SHA256 (what 0x03 did)
    /// must not open under the phone's MGF1-SHA1, and ours must not open
    /// under MGF1-SHA256. A mismatch here is a blob that looks perfect and
    /// never unwraps.
    #[test]
    fn mgf1_digest_is_sha1_and_nothing_else() {
        let (private, public) = account_a();
        let k = [0x42u8; K_WRAP_LEN];
        let sha256_mgf = public.encrypt(&mut rand::rngs::OsRng, Oaep::new::<Sha256>(), &k).unwrap();
        assert!(phone::decrypt_k_wrap(&private, sha256_mgf.as_slice().try_into().unwrap()).is_err());

        let blob = wrap(&public, &user_key()).unwrap();
        assert!(private.decrypt(Oaep::new::<Sha256>(), blob.rsa_ct()).is_err(), "MGF1 must not be SHA-256");
        assert!(private.decrypt(Oaep::new::<Sha1>(), blob.rsa_ct()).is_err(), "the label hash must stay SHA-256");
        assert_eq!(private.decrypt(Oaep::new_with_mgf_hash::<Sha256, Sha1>(), blob.rsa_ct()).unwrap().len(), K_WRAP_LEN);
    }

    #[test]
    fn another_accounts_key_cannot_open_this_ciphertext() {
        let (_, public_a) = account_a();
        let (private_b, _) = account_b();
        let blob = wrap(&public_a, &user_key()).unwrap();
        assert!(matches!(phone::decrypt_k_wrap(&private_b, blob.rsa_ct()), Err(WrapError::Rsa(_))));
    }

    #[test]
    fn wrong_key_size_is_refused() {
        let small = rsa::RsaPrivateKey::new(&mut rand::rngs::OsRng, 1024).unwrap();
        let err = wrap(&rsa::RsaPublicKey::from(&small), &user_key()).unwrap_err();
        assert!(matches!(err, WrapError::KeySize(128)));
    }

    #[test]
    fn secrets_do_not_print() {
        let key = user_key();
        assert_eq!(format!("{key:?}"), "UserKey(..)");
        let k = KWrap::from_slice(&[7u8; 32]).unwrap();
        assert_eq!(format!("{k:?}"), "KWrap(..)");
        assert!(UserKey::from_slice(&[0u8; 63]).is_none());
        assert!(KWrap::from_slice(&[0u8; 31]).is_none());
    }
}
