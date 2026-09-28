//! What the phone does with a blob's `rsa_ct`: the write-once pin check, and
//! the OAEP decrypt the real phone runs inside the Keystore behind a
//! fingerprint.
//!
//! The fake phone and the tests run the decrypt in software with the same
//! parameters ([`crate::oaep`]: SHA-256 label hash, MGF1-SHA1), so a wrap
//! that opens here also opens under Android's
//! `OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, …)` — the
//! one MGF1 digest Keystore accepts on every Android version.

use rsa::RsaPrivateKey;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroize as _;

use crate::{KWrap, RSA_CT_LEN, WrapError};

/// `H(rsa_ct)`: the one ciphertext an account's key will ever decrypt.
/// Set once from the Enrol screen; compared before any prompt.
#[derive(Clone, Copy)]
pub struct Pin([u8; 32]);

impl Pin {
    pub fn of(rsa_ct: &[u8; RSA_CT_LEN]) -> Self {
        Self(Sha256::digest(rsa_ct).into())
    }

    pub fn from_bytes(bytes: &[u8]) -> Option<Self> {
        bytes.try_into().ok().map(Self)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Constant time. A mismatch is refused without raising a prompt.
    pub fn matches(&self, rsa_ct: &[u8; RSA_CT_LEN]) -> bool {
        *self == Self::of(rsa_ct)
    }
}

impl PartialEq for Pin {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&other.0).into()
    }
}

impl Eq for Pin {}

impl std::fmt::Debug for Pin {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Pin({})", crate::hex(&self.0[..4]))
    }
}

/// The phone's half of an unwrap: `K_wrap = OAEP-decrypt(rsa_ct)`.
/// On the real phone this is `cipher.doFinal` inside `BiometricPrompt`.
pub fn decrypt_k_wrap(private: &RsaPrivateKey, rsa_ct: &[u8; RSA_CT_LEN]) -> Result<KWrap, WrapError> {
    let mut plain = private.decrypt_blinded(&mut rand::rngs::OsRng, crate::oaep(), rsa_ct)?;
    let k_wrap = KWrap::from_slice(&plain);
    plain.zeroize();
    k_wrap.ok_or(WrapError::Rsa(rsa::Error::Decryption))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkeys::{account_a, user_key};

    #[test]
    fn pin_matches_only_its_own_ciphertext() {
        let (_, public) = account_a();
        let a = crate::wrap(&public, &user_key()).unwrap();
        let b = crate::wrap(&public, &user_key()).unwrap();
        let pin = Pin::of(a.rsa_ct());
        assert!(pin.matches(a.rsa_ct()));
        assert!(!pin.matches(b.rsa_ct()), "an unpinned rsa_ct must be refused");
        assert_eq!(Pin::from_bytes(pin.as_bytes()), Some(pin));
        assert!(Pin::from_bytes(&pin.as_bytes()[..31]).is_none());
        assert_eq!(pin, Pin::of(a.rsa_ct()));
    }

    #[test]
    fn garbage_ciphertext_is_an_rsa_error() {
        let (private, _) = account_a();
        assert!(matches!(decrypt_k_wrap(&private, &[0x5a; RSA_CT_LEN]), Err(WrapError::Rsa(_))));
    }
}
