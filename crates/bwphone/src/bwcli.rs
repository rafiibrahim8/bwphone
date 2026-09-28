//! Reading the user key out of the Bitwarden CLI, for enrollment.
//!
//! `bw unlock --raw` prints `BW_SESSION`: a fresh random 64-byte
//! AES-256-CBC + HMAC key (`unlock.command.ts:82`), not derived from the
//! password. With it the CLI keeps the unlocked user key in `data.json`
//! under `__PROTECTED__<userId>_user_auto` (`default-state.service.ts`,
//! `partialKeys.userAutoKey`), as base64 of an `EncArrayBuffer`
//! (`type || iv || mac || ct`) over the raw 64 bytes (`userKey.toBase64()`
//! decoded before encryption, `node-env-secure-storage.service.ts`).
//!
//! The session key reaches enroll on stdin (`bw unlock --raw | bwphone
//! enroll --from-stdin`), so it never enters an environment variable, the
//! shell history or another process's command line. The CLI's directory
//! should be on `/dev/shm` (`BITWARDENCLI_APPDATA_DIR`).

use std::path::Path;

use bwphone_nm::{
    session::{SessionKey, open_array_buffer},
    unb64,
};
use bwphone_wrap::UserKey;
use serde_json::Value;

const PROTECTED: &str = "__PROTECTED__";
const USER_AUTO: &str = "_user_auto";
const ACTIVE_ACCOUNT: &str = "global_account_activeAccountId";

#[derive(Debug, thiserror::Error)]
pub enum CliError {
    #[error("reading {0}: {1}")]
    Read(String, std::io::Error),
    #[error("data.json is not the JSON we expect: {0}")]
    Shape(&'static str),
    #[error("no `{PROTECTED}<userId>{USER_AUTO}` entry in data.json; is the vault unlocked with `bw unlock`? (Plan B in the spec: reimplement the login)")]
    NoUserKey,
    #[error("the user key entry did not decrypt under this session key: {0}")]
    Decrypt(bwphone_nm::NmError),
    #[error("the decrypted user key is {0} bytes, not 64")]
    Length(usize),
}

/// The active account's userId and user key from `data.json`.
pub fn read_user_key(appdata_dir: &Path, session: &SessionKey) -> Result<(String, UserKey), CliError> {
    let path = appdata_dir.join("data.json");
    let bytes = std::fs::read(&path).map_err(|e| CliError::Read(path.display().to_string(), e))?;
    let db: Value = serde_json::from_slice(&bytes).map_err(|_| CliError::Shape("not JSON"))?;
    user_key_from_db(&db, session)
}

pub fn user_key_from_db(db: &Value, session: &SessionKey) -> Result<(String, UserKey), CliError> {
    let obj = db.as_object().ok_or(CliError::Shape("top level is not an object"))?;
    let active = obj.get(ACTIVE_ACCOUNT).and_then(Value::as_str);
    let mut candidates: Vec<(&str, &str)> = obj
        .iter()
        .filter_map(|(k, v)| {
            let user = k.strip_prefix(PROTECTED)?.strip_suffix(USER_AUTO)?;
            Some((user, v.as_str()?))
        })
        .collect();
    if let Some(active) = active {
        candidates.retain(|(user, _)| *user == active);
    }
    let (user_id, enc_b64) = candidates.first().copied().ok_or(CliError::NoUserKey)?;
    let enc = unb64(enc_b64).map_err(|_| CliError::Shape("user key entry is not base64"))?;
    let plain = open_array_buffer(session, &enc).map_err(CliError::Decrypt)?;
    let key = UserKey::from_slice(&plain).ok_or(CliError::Length(plain.len()))?;
    Ok((user_id.to_owned(), key))
}

#[cfg(test)]
mod tests {
    use super::*;
    use bwphone_nm::{b64, session::EncString};
    use serde_json::json;

    fn fixed_session() -> SessionKey {
        SessionKey::from_slice(&std::array::from_fn::<u8, 64, _>(|i| i as u8)).unwrap()
    }

    /// Build the CLI's binary form from the string form our codec produces.
    fn array_buffer(session: &SessionKey, plaintext: &[u8]) -> Vec<u8> {
        let e = EncString::seal(session, plaintext);
        let (iv, ct, mac) = (unb64(e.iv.as_deref().unwrap()).unwrap(), unb64(e.data.as_deref().unwrap()).unwrap(), unb64(e.mac.as_deref().unwrap()).unwrap());
        [&[2u8][..], &iv, &mac, &ct].concat()
    }

    #[test]
    fn finds_the_active_users_key() {
        let session = fixed_session();
        let key_a = [0xA5u8; 64];
        let key_b = [0x5Au8; 64];
        let db = json!({
            "global_account_activeAccountId": "user-b",
            "__PROTECTED__user-a_user_auto": b64(&array_buffer(&session, &key_a)),
            "__PROTECTED__user-b_user_auto": b64(&array_buffer(&session, &key_b)),
            "something_else": "x",
        });
        let (user, key) = user_key_from_db(&db, &session).unwrap();
        assert_eq!(user, "user-b");
        assert_eq!(key.as_bytes(), &key_b);

        // No active id: the only entry wins.
        let db = json!({"__PROTECTED__user-a_user_auto": b64(&array_buffer(&session, &key_a))});
        assert_eq!(user_key_from_db(&db, &session).unwrap().0, "user-a");

        assert!(matches!(user_key_from_db(&json!({}), &session), Err(CliError::NoUserKey)));
        let wrong = SessionKey::generate();
        assert!(matches!(user_key_from_db(&db, &wrong), Err(CliError::Decrypt(_))));
        let short = json!({"__PROTECTED__u_user_auto": b64(&array_buffer(&session, &[1u8; 32]))});
        assert!(matches!(user_key_from_db(&short, &session), Err(CliError::Length(32))));
    }
}
