//! `vault.blob` on disk: written once at enrollment, mode 0400, and never
//! rewritten. An unlock reads it and writes nothing.

use std::{
    fs::{self, File, OpenOptions},
    io::{self, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
};

use crate::{Blob, WrapError};

/// Enrollment step 6: `tmp -> fsync(file) -> publish -> fsync(directory)`.
///
/// The tmp file is 0600 while it is written and 0400 before it is published.
/// Publishing uses `link(2)` rather than `rename(2)`: it is just as atomic,
/// and it fails with `AlreadyExists` if a blob is already there, so the
/// write-once rule holds at the filesystem, not only in the caller.
pub fn write_once(path: &Path, blob: &Blob) -> io::Result<()> {
    let dir = path
        .parent()
        .filter(|d| !d.as_os_str().is_empty())
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "blob path has no directory"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "blob path has no file name"))?;
    let tmp = dir.join(format!("{}.tmp", name.to_string_lossy()));

    // A tmp left by a crash is never the published blob; clear it.
    let _ = fs::remove_file(&tmp);
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(&tmp)?;
    let outcome = (|| {
        file.write_all(blob.as_bytes())?;
        file.sync_all()?;
        file.set_permissions(fs::Permissions::from_mode(0o400))?;
        fs::hard_link(&tmp, path)
    })();
    let _ = fs::remove_file(&tmp);
    outcome?;
    File::open(dir)?.sync_all()
}

pub fn read(path: &Path) -> Result<Blob, WrapError> {
    Blob::parse(&fs::read(path)?)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testkeys::{account_a, user_key};

    fn scratch(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("bwphone-wrap-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn writes_once_read_only_and_byte_identical() {
        let dir = scratch("once");
        let path = dir.join("vault.blob");
        let (_, public) = account_a();
        let blob = crate::wrap(&public, &user_key()).unwrap();

        write_once(&path, &blob).unwrap();
        assert_eq!(read(&path).unwrap(), blob);
        assert_eq!(fs::metadata(&path).unwrap().permissions().mode() & 0o777, 0o400);
        assert!(!dir.join("vault.blob.tmp").exists());

        let again = crate::wrap(&public, &user_key()).unwrap();
        let err = write_once(&path, &again).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AlreadyExists);
        assert_eq!(read(&path).unwrap(), blob, "the first blob must survive a second write");
        assert!(!dir.join("vault.blob.tmp").exists());

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn a_stale_tmp_does_not_block_enrollment() {
        let dir = scratch("stale");
        let path = dir.join("vault.blob");
        fs::write(dir.join("vault.blob.tmp"), b"half-written").unwrap();
        let (_, public) = account_a();
        let blob = crate::wrap(&public, &user_key()).unwrap();
        write_once(&path, &blob).unwrap();
        assert_eq!(read(&path).unwrap(), blob);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn read_rejects_a_truncated_file() {
        let dir = scratch("short");
        let path = dir.join("vault.blob");
        fs::write(&path, [crate::VERSION; 100]).unwrap();
        assert!(matches!(read(&path), Err(WrapError::Length(100))));
        assert!(matches!(read(&dir.join("missing")), Err(WrapError::Io(_))));
        fs::remove_dir_all(&dir).unwrap();
    }
}
