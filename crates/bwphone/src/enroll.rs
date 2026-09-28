//! `bwphone enroll`: one account, once. The order is the point: the
//! plaintext key is destroyed only after a full unwrap through the phone
//! has come back equal. An MGF1 mismatch produces a blob that looks perfect
//! and cannot be unwrapped; finding that after the key is gone means
//! exposing it a second time.
//!
//! 1. Enrol screen open on the phone → `enrol_begin` creates that account's
//!    Keystore key; both screens show its fingerprint.
//! 2. Wrap the user key into `vault.blob`, written once, 0400.
//! 3. `set_pin(H(rsa_ct))`, write-once on the phone.
//! 4. Self-test: emoji pick, fingerprint, `K_wrap`, open, compare.
//! 5. Only then does the caller `bw logout` and delete the CLI directory.

use std::{
    fs,
    net::SocketAddr,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

use bwphone_transport::{
    b64,
    msg::{RequestBody, Status},
    short_fingerprint, unb64,
};
use bwphone_wrap::{
    Blob, UserKey,
    phone::Pin,
    rsa::{RsaPublicKey, pkcs8::DecodePublicKey as _},
    wrap,
};

use crate::{
    accounts::{self, AccountFile, Accounts},
    bwcli,
    pair::Ui,
    pairing::Pairing,
    paths::Paths,
    phone::{Answer, Phone, ReachFailure},
    secrets::{self, Key32},
};

/// The human phase for the self-test unwrap.
pub const SELF_TEST_BUDGET_MS: u64 = 50_000;

#[derive(Debug, thiserror::Error)]
pub enum EnrollError {
    #[error("not paired: run `bwphone pair` first")]
    NotPaired,
    #[error("no phone address known: pass --phone or wait for a hello")]
    NoAddress,
    #[error("an account labelled {0} is already enrolled")]
    LabelTaken(String),
    #[error("Bitwarden account {0} is already enrolled as {1}")]
    UserEnrolled(String, String),
    #[error("{0}")]
    Cli(#[from] bwcli::CliError),
    #[error("{0}")]
    Secrets(#[from] secrets::SecretsError),
    #[error("{0}")]
    Pairing(#[from] crate::pairing::PairingError),
    #[error("phone: {0}")]
    Phone(#[from] ReachFailure),
    #[error("the phone refused {0}: {1:?}")]
    Refused(&'static str, Status),
    #[error("--label {0}")]
    LabelInvalid(&'static str),
    #[error("the phone already has an account named \"{0}\". Revoke it on the phone first, or enrol with another --label")]
    LabelTakenOnPhone(String),
    #[error("the phone refused to start an enrolment. Unlock it and open BW Phone (or its Enrol screen), make sure no unlock request is waiting on it, then run this again")]
    EnrolNotAllowed,
    #[error("the phone's enrol_begin reply is malformed: {0}")]
    Reply(&'static str),
    #[error("fingerprint not confirmed; nothing was stored")]
    FingerprintRejected,
    #[error("wrap: {0}")]
    Wrap(#[from] bwphone_wrap::WrapError),
    #[error("i/o: {0}")]
    Io(#[from] std::io::Error),
    #[error("{0}")]
    Accounts(#[from] accounts::AccountsError),
    #[error("self-test failed: {0}. The account directory was removed; revoke the account on the phone and try again")]
    SelfTest(String),
}

pub enum KeySource {
    /// A session key the person already has (from `bw login` or
    /// `bw unlock --raw`), then `data.json` in this directory.
    Session { appdata_dir: PathBuf, session: bwphone_nm::session::SessionKey },
    /// Already in hand (tests, Plan B tooling).
    Given { user_id: String, user_key: UserKey },
}

pub struct EnrollOptions {
    pub label: String,
    pub source: KeySource,
    pub phone_addr: Option<SocketAddr>,
}

/// What enrollment leaves behind, apart from the files.
pub struct Enrolled {
    pub account_id: [u8; 16],
    pub label: String,
    pub user_id: String,
    /// SHA-256 of the user key, hex: record it, compare it with `bwphone unlock`.
    pub fingerprint: String,
}

/// The phone's limit on an account name, in UTF-16 units (Kotlin's `take(32)`).
pub const LABEL_MAX: usize = 32;

/// The name as the phone will store it: trimmed, at most [`LABEL_MAX`]
/// UTF-16 units. Anything the phone would change is refused here instead, so
/// the PC and the phone always hold the same string.
pub fn clean_label(raw: &str) -> Result<String, EnrollError> {
    let label = raw.trim();
    if label.is_empty() {
        return Err(EnrollError::LabelInvalid("is empty"));
    }
    if label.encode_utf16().count() > LABEL_MAX {
        return Err(EnrollError::LabelInvalid("is longer than 32 characters"));
    }
    Ok(label.to_owned())
}

pub async fn run(paths: &Paths, opts: EnrollOptions, ui: &mut dyn Ui) -> Result<Enrolled, EnrollError> {
    let label = clean_label(&opts.label)?;
    let pairing = Pairing::load(&paths.pairing())?.ok_or(EnrollError::NotPaired)?;
    let addr = match opts.phone_addr {
        Some(a) => a,
        None => pairing.last_address.map(|ip| SocketAddr::new(ip, pairing.phone_port)).ok_or(EnrollError::NoAddress)?,
    };
    let phone = Phone { public: pairing.phone_pub()?, pairing_id: pairing.pairing_id()?, host: crate::hostname() };
    let noise = secrets::read_item(secrets::NOISE_STATIC).await?;
    let existing = Accounts::load(&paths.accounts())?;
    if existing.label_taken_ignoring_case(&label) {
        return Err(EnrollError::LabelTaken(label));
    }

    let (user_id, user_key) = match opts.source {
        KeySource::Given { user_id, user_key } => (user_id, user_key),
        KeySource::Session { appdata_dir, session } => bwcli::read_user_key(&appdata_dir, &session)?,
    };
    if let Some(label) = existing
        .by_user_id(&user_id)
        .map(|a| a.label.clone())
        .or_else(|| existing.retired().find(|r| r.user_id == user_id).map(|r| r.label.clone()))
    {
        return Err(EnrollError::UserEnrolled(user_id, label));
    }
    let fingerprint = user_key.fingerprint();

    enroll_with_key(paths, &phone, &noise, addr, &label, &user_id, &user_key, ui).await?;
    ui.show(&format!(
        "\nEnrolled {label} for Bitwarden account {user_id}.\nUser key fingerprint (record this): {fingerprint}\n\nNow: bw logout; rm -rf the CLI directory; diff the wallet; then `bwphone manifests write` if you have not."
    ));
    let account_id = Accounts::load(&paths.accounts())?.by_label(&label).map(|a| a.id).unwrap_or_default();
    Ok(Enrolled { account_id, label, user_id, fingerprint })
}

#[allow(clippy::too_many_arguments)]
async fn enroll_with_key(
    paths: &Paths,
    phone: &Phone,
    noise: &Key32,
    addr: SocketAddr,
    label: &str,
    user_id: &str,
    user_key: &UserKey,
    ui: &mut dyn Ui,
) -> Result<(), EnrollError> {
    let account_id = bwphone_transport::random_id();
    let account_b64 = b64(&account_id);

    // 1. The phone creates the key; we confirm its fingerprint on both screens.
    ui.show("Have BW Phone open on the phone, unlocked (its Enrol screen opens by itself).");
    let reply = phone
        .request_within(
            noise.as_bytes(),
            addr,
            RequestBody::EnrolBegin { account: account_b64.clone(), label_hint: label.to_owned() },
            crate::phone::ENROL_BEGIN_BUDGET,
        )
        .await?;
    match reply.status {
        Status::Ok => {}
        Status::LabelTaken => return Err(EnrollError::LabelTakenOnPhone(label.to_owned())),
        Status::NotAllowed => return Err(EnrollError::EnrolNotAllowed),
        other => return Err(EnrollError::Refused("enrol_begin", other)),
    }
    let rsa_pub_der = unb64(reply.rsa_pub.as_deref().ok_or(EnrollError::Reply("no rsa_pub"))?).map_err(|_| EnrollError::Reply("rsa_pub is not base64"))?;
    let rsa_pub = RsaPublicKey::from_public_key_der(&rsa_pub_der).map_err(|_| EnrollError::Reply("rsa_pub is not an RSA SPKI key"))?;
    // The name was cleaned to the phone's rules before asking, so the phone
    // must echo it exactly; anything else would split the two sides.
    if reply.label.as_deref().is_some_and(|l| l != label) {
        return Err(EnrollError::Reply("the phone named the account differently from --label"));
    }
    let label = label.to_owned();
    ui.show(&format!("\nThe phone created a key for \"{label}\":\n\n    {}\n", short_fingerprint(&rsa_pub_der)));
    if !ui.confirm("Does this fingerprint match the phone's screen?") {
        return Err(EnrollError::FingerprintRejected);
    }

    // 2. Wrap, and write the account directory.
    let blob = wrap(&rsa_pub, user_key)?;
    let dir = paths.accounts().join(accounts::id_hex(&account_id));
    let written = write_account(&dir, &blob, &rsa_pub_der, &AccountFile { user_id: user_id.to_owned(), label: label.clone() });
    if let Err(e) = written {
        let _ = fs::remove_dir_all(&dir);
        return Err(e);
    }

    // 3–4. Pin, then prove it opens; undo the directory if not.
    match pin_and_self_test(phone, noise, addr, &account_b64, &blob, user_key, ui).await {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = fs::remove_dir_all(&dir);
            Err(EnrollError::SelfTest(e.to_string()))
        }
    }
}

fn write_account(dir: &Path, blob: &Blob, rsa_pub_der: &[u8], meta: &AccountFile) -> Result<(), EnrollError> {
    fs::create_dir_all(dir)?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    bwphone_wrap::store::write_once(&dir.join("vault.blob"), blob)?;
    fs::write(dir.join("phone.rsa.pub"), rsa_pub_der)?;
    fs::write(dir.join("account.json"), serde_json::to_vec_pretty(meta).expect("AccountFile serialises"))?;
    Ok(())
}

async fn pin_and_self_test(
    phone: &Phone,
    noise: &Key32,
    addr: SocketAddr,
    account_b64: &str,
    blob: &Blob,
    user_key: &UserKey,
    ui: &mut dyn Ui,
) -> Result<(), EnrollError> {
    let pin = Pin::of(blob.rsa_ct());
    let reply = phone.request(noise.as_bytes(), addr, RequestBody::SetPin { account: account_b64.to_owned(), pin: b64(pin.as_bytes()) }).await?;
    if reply.status != Status::Ok {
        return Err(EnrollError::Refused("set_pin", reply.status));
    }

    let account_id: [u8; 16] = unb64(account_b64).expect("we encoded it").try_into().expect("16 bytes");
    let reached = phone.reach(noise.as_bytes(), addr, &account_id, blob.rsa_ct(), SELF_TEST_BUDGET_MS).await?;
    ui.show(&format!("\nSelf-test: pick  {}  on the phone, then your fingerprint.", reached.emoji));
    let k_wrap = match reached.answer(std::time::Duration::from_millis(SELF_TEST_BUDGET_MS + 1000)).await {
        Answer::KWrap(k) => k,
        Answer::Refused(s) => return Err(EnrollError::Refused("unwrap", s)),
        Answer::TimedOut => return Err(EnrollError::Refused("unwrap", Status::Expired)),
        Answer::Protocol(what) => return Err(EnrollError::Reply(what)),
    };
    let opened = bwphone_wrap::unwrap(blob, &k_wrap)?;
    if opened != *user_key {
        return Err(EnrollError::Reply("the unwrapped key differs from the original"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pair::Ui;
    use bwphone_fakephone::{Decision, Event, FakePhone, always, fixed_rsa_key};
    use bwphone_transport::noise::StaticKeypair;
    use std::sync::Arc;

    struct Script {
        confirm: bool,
        shown: Vec<String>,
    }

    impl Ui for Script {
        fn show(&mut self, t: &str) {
            self.shown.push(t.into());
        }
        fn confirm(&mut self, _: &str) -> bool {
            self.confirm
        }
    }

    struct World {
        paths: Paths,
        phone: Arc<FakePhone>,
        client: Phone,
        noise: Key32,
        addr: SocketAddr,
        user_key: UserKey,
    }

    async fn world(person: bwphone_fakephone::Person) -> World {
        let root = std::env::temp_dir().join(format!("bwphone-enroll-{}-{}", std::process::id(), rand::random::<u32>()));
        let _ = fs::remove_dir_all(&root);
        let paths = Paths::under(&root);
        let pc = StaticKeypair::generate().unwrap();
        let pairing_id = [2u8; 16];
        let phone = Arc::new(FakePhone::new(pc.public, pairing_id, person));
        let (addr, task) = phone.clone().listen("127.0.0.1:0").await.unwrap();
        std::mem::forget(task);
        phone.set_next_enrol_key(fixed_rsa_key(0));
        let client = Phone { public: phone.public(), pairing_id, host: "test".into() };
        let user_key = UserKey::from_slice(&[0x42u8; 64]).unwrap();
        World { paths, phone, client, noise: Key32::new(*pc.private), addr, user_key }
    }

    fn account_dirs(paths: &Paths) -> Vec<PathBuf> {
        fs::read_dir(paths.accounts()).map(|d| d.flatten().map(|e| e.path()).collect()).unwrap_or_default()
    }

    #[tokio::test]
    async fn enrols_pins_and_self_tests() {
        let w = world(always(Decision::Approve)).await;
        w.phone.open_enrol(true);
        let mut ui = Script { confirm: true, shown: vec![] };
        enroll_with_key(&w.paths, &w.client, &w.noise, w.addr, "Work", "user-1", &w.user_key, &mut ui).await.unwrap();

        let accounts = Accounts::load(&w.paths.accounts()).unwrap();
        let a = accounts.by_label("Work").unwrap();
        assert_eq!(a.user_id, "user-1");
        let dir = w.paths.accounts().join(accounts::id_hex(&a.id));
        assert_eq!(fs::metadata(dir.join("vault.blob")).unwrap().permissions().mode() & 0o777, 0o400);
        let der = fs::read(dir.join("phone.rsa.pub")).unwrap();
        assert_eq!(RsaPublicKey::from_public_key_der(&der).unwrap(), RsaPublicKey::from(&fixed_rsa_key(0)));

        let events = w.phone.events();
        assert!(matches!(events[0], Event::Enrolled(id) if id == a.id));
        assert!(matches!(events[1], Event::Pinned(id) if id == a.id));
        assert!(matches!(events[2], Event::Prompted(_)));
        assert!(matches!(events[3], Event::Answered { status: Status::Ok, .. }));
        assert!(ui.shown.iter().any(|s| s.contains(&short_fingerprint(&der))), "fingerprint shown");

        // The blob the daemon will load opens under the phone's key.
        let k = bwphone_wrap::phone::decrypt_k_wrap(&fixed_rsa_key(0), a.blob.rsa_ct()).unwrap();
        assert!(bwphone_wrap::unwrap(&a.blob, &k).unwrap() == w.user_key);
        fs::remove_dir_all(w.paths.data.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn enrol_screen_closed_is_refused_before_anything_is_written() {
        let w = world(always(Decision::Approve)).await;
        let mut ui = Script { confirm: true, shown: vec![] };
        let err = enroll_with_key(&w.paths, &w.client, &w.noise, w.addr, "Work", "user-1", &w.user_key, &mut ui).await.unwrap_err();
        assert!(matches!(err, EnrollError::EnrolNotAllowed), "{err}");
        assert!(account_dirs(&w.paths).is_empty());
    }

    #[tokio::test]
    async fn a_name_the_phone_already_has_is_refused_with_its_own_error() {
        let w = world(always(Decision::Approve)).await;
        w.phone.add_account([3; 16], "work", fixed_rsa_key(1), None);
        w.phone.open_enrol(true);
        let mut ui = Script { confirm: true, shown: vec![] };
        let err = enroll_with_key(&w.paths, &w.client, &w.noise, w.addr, "Work", "user-1", &w.user_key, &mut ui).await.unwrap_err();
        assert!(matches!(&err, EnrollError::LabelTakenOnPhone(l) if l == "Work"), "{err}");
        assert!(err.to_string().contains("already has an account named \"Work\""), "{err}");
        assert!(account_dirs(&w.paths).is_empty());
    }

    #[test]
    fn labels_are_cleaned_to_the_phones_rules_or_refused() {
        assert_eq!(clean_label("  Work \t").unwrap(), "Work");
        assert!(matches!(clean_label("   "), Err(EnrollError::LabelInvalid(_))));
        assert_eq!(clean_label(&"a".repeat(32)).unwrap().len(), 32);
        assert!(matches!(clean_label(&"a".repeat(33)), Err(EnrollError::LabelInvalid(_))));
        // 16 emoji are 32 UTF-16 units, as Kotlin counts them; 17 are too many.
        assert!(clean_label(&"🍩".repeat(16)).is_ok());
        assert!(clean_label(&"🍩".repeat(17)).is_err());
    }

    #[tokio::test]
    async fn a_name_differing_only_in_case_or_spaces_is_taken_here_already() {
        let w = world(always(Decision::Approve)).await;
        w.phone.open_enrol(true);
        let mut ui = Script { confirm: true, shown: vec![] };
        enroll_with_key(&w.paths, &w.client, &w.noise, w.addr, "Work", "user-1", &w.user_key, &mut ui).await.unwrap();
        let accounts = Accounts::load(&w.paths.accounts()).unwrap();
        assert!(accounts.label_taken_ignoring_case("work"));
        assert!(accounts.label_taken_ignoring_case(&clean_label(" WORK ").unwrap()));
        assert!(!accounts.label_taken_ignoring_case("Personal"));
        fs::remove_dir_all(w.paths.data.parent().unwrap()).unwrap();
    }

    #[tokio::test]
    async fn rejected_fingerprint_stores_nothing() {
        let w = world(always(Decision::Approve)).await;
        w.phone.open_enrol(true);
        let mut ui = Script { confirm: false, shown: vec![] };
        let err = enroll_with_key(&w.paths, &w.client, &w.noise, w.addr, "Work", "user-1", &w.user_key, &mut ui).await.unwrap_err();
        assert!(matches!(err, EnrollError::FingerprintRejected));
        assert!(account_dirs(&w.paths).is_empty());
        assert!(!w.phone.events().iter().any(|e| matches!(e, Event::Pinned(_))));
    }

    #[tokio::test]
    async fn failed_self_test_removes_the_account() {
        let w = world(always(Decision::Deny)).await;
        w.phone.open_enrol(true);
        let mut ui = Script { confirm: true, shown: vec![] };
        let err = enroll_with_key(&w.paths, &w.client, &w.noise, w.addr, "Work", "user-1", &w.user_key, &mut ui).await.unwrap_err();
        assert!(matches!(err, EnrollError::SelfTest(_)), "{err}");
        assert!(account_dirs(&w.paths).is_empty(), "the unopenable blob must not be left behind");
        assert!(w.phone.events().iter().any(|e| matches!(e, Event::Pinned(_))), "the phone did pin: revoke there");
        fs::remove_dir_all(w.paths.data.parent().unwrap()).unwrap();
    }
}
