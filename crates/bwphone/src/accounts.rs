//! `accounts/<account_id>/`: one directory per Bitwarden account, holding
//! `account.json` (userId and label, for routing), `vault.blob` (0400) and
//! `phone.rsa.pub`. The `account_id` is 16 random bytes made at enrollment;
//! the phone never sees a Bitwarden identifier.

use std::{
    fs,
    path::{Path, PathBuf},
};

use bwphone_wrap::Blob;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct AccountFile {
    pub user_id: String,
    pub label: String,
}

#[derive(Debug)]
pub struct Account {
    pub id: [u8; 16],
    pub user_id: String,
    pub label: String,
    pub blob: Blob,
}

#[derive(Debug, thiserror::Error)]
pub enum AccountsError {
    #[error("{0}: {1}")]
    Io(PathBuf, std::io::Error),
    #[error("{0}: {1}")]
    Json(PathBuf, serde_json::Error),
    #[error("{0}: {1}")]
    Blob(PathBuf, bwphone_wrap::WrapError),
    #[error("two accounts claim {0}")]
    Duplicate(String),
}

/// An account whose `vault.blob` is in a retired format (0x03 used
/// MGF1-SHA256, which Android 12 and 13 cannot decrypt). It is listed and
/// removable, never served: its userId gets `false` like an unenrolled one.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retired {
    pub id: [u8; 16],
    pub user_id: String,
    pub label: String,
    pub version: u8,
}

#[derive(Debug, Default)]
pub struct Accounts {
    live: Vec<Account>,
    retired: Vec<Retired>,
}

impl Accounts {
    /// Every well-formed account directory. A directory that is not 32 hex
    /// characters is ignored; one that is but cannot be read is an error,
    /// because a half-enrolled account should be seen, not skipped. A blob in
    /// a retired format is set aside in [`Accounts::retired`] rather than
    /// failing the load, so one old account cannot stop the daemon.
    pub fn load(dir: &Path) -> Result<Self, AccountsError> {
        let mut accounts = Self::default();
        let entries = match fs::read_dir(dir) {
            Ok(e) => e,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(accounts),
            Err(e) => return Err(AccountsError::Io(dir.to_owned(), e)),
        };
        for entry in entries {
            let entry = entry.map_err(|e| AccountsError::Io(dir.to_owned(), e))?;
            let Some(id) = entry.file_name().to_str().and_then(parse_id) else { continue };
            let path = entry.path();
            let meta_path = path.join("account.json");
            let meta: AccountFile = serde_json::from_slice(
                &fs::read(&meta_path).map_err(|e| AccountsError::Io(meta_path.clone(), e))?,
            )
            .map_err(|e| AccountsError::Json(meta_path, e))?;
            let blob_path = path.join("vault.blob");
            let blob = match bwphone_wrap::store::read(&blob_path) {
                Ok(b) => b,
                Err(bwphone_wrap::WrapError::RetiredVersion(version)) => {
                    accounts.check_free(&meta.user_id, &meta.label)?;
                    accounts.retired.push(Retired { id, user_id: meta.user_id, label: meta.label, version });
                    continue;
                }
                Err(e) => return Err(AccountsError::Blob(blob_path, e)),
            };
            accounts.push(Account { id, user_id: meta.user_id, label: meta.label, blob })?;
        }
        Ok(accounts)
    }

    pub fn push(&mut self, account: Account) -> Result<(), AccountsError> {
        self.check_free(&account.user_id, &account.label)?;
        self.live.push(account);
        Ok(())
    }

    /// Neither a live nor a retired account holds this userId or label.
    fn check_free(&self, user_id: &str, label: &str) -> Result<(), AccountsError> {
        if self.by_user_id(user_id).is_some() || self.retired.iter().any(|r| r.user_id == user_id) {
            return Err(AccountsError::Duplicate(format!("userId {user_id}")));
        }
        if self.label_taken(label) {
            return Err(AccountsError::Duplicate(format!("label {label}")));
        }
        Ok(())
    }

    pub fn by_user_id(&self, user_id: &str) -> Option<&Account> {
        self.live.iter().find(|a| a.user_id == user_id)
    }

    pub fn by_label(&self, label: &str) -> Option<&Account> {
        self.live.iter().find(|a| a.label == label)
    }

    pub fn by_id(&self, id: &[u8; 16]) -> Option<&Account> {
        self.live.iter().find(|a| a.id == *id)
    }

    /// A live or a retired account has this label.
    pub fn label_taken(&self, label: &str) -> bool {
        self.by_label(label).is_some() || self.retired.iter().any(|r| r.label == label)
    }

    /// The same check, ignoring case, as the phone makes it: enroll refuses a
    /// name that differs from an existing one only in case.
    pub fn label_taken_ignoring_case(&self, label: &str) -> bool {
        let wanted = label.to_lowercase();
        self.live.iter().map(|a| &a.label).chain(self.retired.iter().map(|r| &r.label)).any(|l| l.to_lowercase() == wanted)
    }

    /// The directory id for a label, live or retired: what `account remove` deletes.
    pub fn id_for_label(&self, label: &str) -> Option<[u8; 16]> {
        self.by_label(label).map(|a| a.id).or_else(|| self.retired.iter().find(|r| r.label == label).map(|r| r.id))
    }

    pub fn iter(&self) -> impl Iterator<Item = &Account> {
        self.live.iter()
    }

    pub fn retired(&self) -> impl Iterator<Item = &Retired> {
        self.retired.iter()
    }

    pub fn is_empty(&self) -> bool {
        self.live.is_empty()
    }
}

pub fn id_hex(id: &[u8; 16]) -> String {
    id.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn parse_id(s: &str) -> Option<[u8; 16]> {
    if s.len() != 32 {
        return None;
    }
    let mut id = [0u8; 16];
    for (i, byte) in id.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).ok()?;
    }
    Some(id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_round_trip() {
        let id = std::array::from_fn(|i| (i * 17) as u8);
        assert_eq!(parse_id(&id_hex(&id)), Some(id));
        assert_eq!(parse_id("abc"), None);
        assert_eq!(parse_id(&"zz".repeat(16)), None);
    }

    #[test]
    fn loads_only_hex_dirs_and_refuses_duplicates() {
        let dir = std::env::temp_dir().join(format!("bwphone-accounts-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("not-an-account")).unwrap();
        assert!(Accounts::load(&dir).unwrap().is_empty());
        assert!(Accounts::load(&dir.join("missing")).unwrap().is_empty());

        let id = [9u8; 16];
        let acc = dir.join(id_hex(&id));
        fs::create_dir_all(&acc).unwrap();
        fs::write(acc.join("account.json"), r#"{"user_id":"u1","label":"Work"}"#).unwrap();
        assert!(matches!(Accounts::load(&dir), Err(AccountsError::Blob(_, _))), "missing blob is an error");

        let mut accounts = Accounts::default();
        let blob = Blob::parse(&{
            let mut b = vec![bwphone_wrap::VERSION];
            b.resize(bwphone_wrap::BLOB_LEN, 0);
            b
        })
        .unwrap();
        accounts.push(Account { id, user_id: "u1".into(), label: "Work".into(), blob: blob.clone() }).unwrap();
        let dup = Account { id: [1; 16], user_id: "u1".into(), label: "Other".into(), blob };
        assert!(matches!(accounts.push(dup), Err(AccountsError::Duplicate(_))));
        assert_eq!(accounts.by_user_id("u1").unwrap().label, "Work");
        assert!(accounts.by_label("Other").is_none());
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_retired_blob_is_set_aside_not_fatal() {
        let dir = std::env::temp_dir().join(format!("bwphone-accounts-retired-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let id = [7u8; 16];
        let acc = dir.join(id_hex(&id));
        fs::create_dir_all(&acc).unwrap();
        fs::write(acc.join("account.json"), r#"{"user_id":"u1","label":"Work"}"#).unwrap();
        let mut old = vec![0x03u8];
        old.resize(bwphone_wrap::BLOB_LEN, 0);
        fs::write(acc.join("vault.blob"), &old).unwrap();

        let accounts = Accounts::load(&dir).unwrap();
        assert!(accounts.is_empty(), "never served");
        assert!(accounts.by_user_id("u1").is_none());
        let r: Vec<_> = accounts.retired().collect();
        assert_eq!(r.len(), 1);
        assert_eq!((r[0].label.as_str(), r[0].version), ("Work", 0x03));
        assert!(accounts.label_taken("Work"), "enrolling Work again waits for `account remove`");
        assert_eq!(accounts.id_for_label("Work"), Some(id));
        fs::remove_dir_all(&dir).unwrap();
    }
}
