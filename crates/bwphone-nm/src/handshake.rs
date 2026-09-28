//! `setupEncryption`: the extension sends an RSA-2048 public key in
//! plaintext; we answer with a fresh 64-byte session key encrypted to it.
//!
//! The OAEP hash is SHA-1, pinned by the extension
//! (`HashAlgorithmForEncryption = "sha1"`, `nativeMessaging.background.ts:20`).
//! WebCrypto uses the same hash for the label and MGF1, so SHA-1 for both.
//! SHA-256 here silently fails to decrypt on the extension's side.

use rsa::{Oaep, RsaPublicKey, pkcs8::DecodePublicKey as _};
use sha1::Sha1;

use crate::{NmError, b64, session::SessionKey, unb64};

/// The session key and the `sharedSecret` field for the reply.
pub fn setup_encryption(public_key_b64: &str) -> Result<(SessionKey, String), NmError> {
    let der = unb64(public_key_b64)?;
    let public = RsaPublicKey::from_public_key_der(&der).map_err(|_| NmError::PublicKey)?;
    let key = SessionKey::generate();
    let ct = public
        .encrypt(&mut rand::rngs::OsRng, Oaep::new::<Sha1>(), key.as_bytes())
        .map_err(|_| NmError::PublicKey)?;
    Ok((key, b64(&ct)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tests::extension_keypair;
    use rsa::pkcs8::EncodePublicKey as _;
    use sha2::Sha256;

    #[test]
    fn extension_recovers_the_key_with_sha1_oaep_only() {
        let (private, public) = extension_keypair();
        let spki = b64(public.to_public_key_der().unwrap().as_bytes());
        let (key, shared_secret) = setup_encryption(&spki).unwrap();

        let ct = unb64(&shared_secret).unwrap();
        let recovered = private.decrypt(Oaep::new::<Sha1>(), &ct).unwrap();
        assert_eq!(recovered, key.as_bytes());
        assert!(private.decrypt(Oaep::new::<Sha256>(), &ct).is_err(), "must be SHA-1, not SHA-256");
    }

    #[test]
    fn bad_keys_are_refused() {
        assert!(matches!(setup_encryption("not base64!"), Err(NmError::Base64(_))));
        assert!(matches!(setup_encryption(&b64(b"not a key")), Err(NmError::PublicKey)));
    }
}
