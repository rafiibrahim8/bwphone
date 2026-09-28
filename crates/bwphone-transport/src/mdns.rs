//! The PC's discovery name: rotates daily at 00:00 UTC, and only the
//! paired phone can compute it.
//!
//! `name = base32(HMAC-SHA256(hello_key, "bwphone/v3/mdns" || "YYYY-MM-DD"))[0..16] + ".local"`
//!
//! The PC answers yesterday's, today's and tomorrow's names, which covers
//! midnight and ordinary clock skew.

use hmac::{Hmac, Mac as _};
use sha2::Sha256;

const LABEL: &[u8] = b"bwphone/v3/mdns";

/// The 16-character host label, without `.local`.
pub fn label_for_date(hello_key: &[u8; 32], date: &str) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(hello_key).expect("HMAC takes any key length");
    mac.update(LABEL);
    mac.update(date.as_bytes());
    let tag = mac.finalize().into_bytes();
    let mut s = data_encoding::BASE32_NOPAD.encode(&tag).to_ascii_lowercase();
    s.truncate(16);
    s
}

pub fn name_for_date(hello_key: &[u8; 32], date: &str) -> String {
    format!("{}.local", label_for_date(hello_key, date))
}

/// Today's name, from the phone's point of view.
pub fn name_now(hello_key: &[u8; 32], unix_secs: i64) -> String {
    name_for_date(hello_key, &utc_date(unix_secs))
}

/// The three labels the PC answers: yesterday, today, tomorrow (UTC).
pub fn labels_around(hello_key: &[u8; 32], unix_secs: i64) -> [String; 3] {
    [-86_400, 0, 86_400].map(|d| label_for_date(hello_key, &utc_date(unix_secs + d)))
}

/// `YYYY-MM-DD` for a Unix time, in UTC. Howard Hinnant's civil_from_days.
pub fn utc_date(unix_secs: i64) -> String {
    let z = unix_secs.div_euclid(86_400) + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!("{y:04}-{m:02}-{d:02}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dates() {
        assert_eq!(utc_date(0), "1970-01-01");
        assert_eq!(utc_date(951_782_400), "2000-02-29");
        assert_eq!(utc_date(1_790_467_200), "2026-09-27");
        assert_eq!(utc_date(1_790_553_599), "2026-09-27");
        assert_eq!(utc_date(1_790_553_600), "2026-09-28");
    }

    #[test]
    fn labels_rotate_daily_and_look_random() {
        let key = [3u8; 32];
        let [y, t, n] = labels_around(&key, 1_790_500_000);
        assert_eq!(t, label_for_date(&key, "2026-09-27"));
        assert_ne!(y, t);
        assert_ne!(t, n);
        assert_eq!(t.len(), 16);
        assert!(t.chars().all(|c| c.is_ascii_lowercase() || ('2'..='7').contains(&c)));
        assert_ne!(label_for_date(&[4u8; 32], "2026-09-27"), t);
    }
}
