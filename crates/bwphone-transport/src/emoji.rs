//! Emoji matching. Neither device picks the emoji: both derive it from the
//! session. The phone then surrounds it with four distinct decoys.
//!
//! # What it is derived from, and why
//!
//! The Noise handshake hash `h` alone is not enough: Noise mixes only public
//! values into it (prologue, both static public keys, both ephemerals, the
//! empty-payload tags), so anyone who holds `pairing.json` and can see the
//! two handshake frames on the LAN recomputes `h`, and with it the emoji
//! the PC is showing. So the emoji is
//!
//! ```text
//! index = HKDF-SHA256(ikm = h || pc_nonce || phone_nonce, info = "bwphone/v3/emoji")[0] & 0x1F
//! ```
//!
//! where `pc_nonce` travels in the encrypted unwrap request and
//! `phone_nonce` in the encrypted `prompt_posted` reply. Both are under the
//! transport keys, which need `ee`: a passive observer cannot read them even
//! with the PC's static key. And the order matters: the PC commits
//! its nonce before it sees the phone's, and `h` was fixed before either, so
//! neither side can steer the result — an attacker holding the PC key
//! can only open whole sessions and hope, at one in 32 each, which the phone
//! counts and rate-limits.

use hkdf::Hkdf;
use rand::seq::SliceRandom as _;
use sha2::Sha256;

/// 16 food, 16 faces. 32 = 2^5, so five bits pick one with no bias. Nothing
/// newer than Emoji 11, so Android 12 and Noto Color Emoji both draw them.
pub const EMOJI: [&str; 32] = [
    "🍎", "🍌", "🍇", "🍉", "🍓", "🍍", "🥑", "🥕", "🌽", "🥦", "🧀", "🍕", "🍔", "🍩", "🍪", "🍦",
    "😀", "😂", "😍", "😎", "😇", "🙃", "🤓", "😡", "😱", "😴", "🤔", "🤢", "🤡", "🤠", "🥶", "🥳",
];

/// How many emojis the phone shows (the real one plus decoys).
pub const CHOICES: usize = 5;

/// Both nonces are this long; anything else is refused before any prompt.
pub const NONCE_LEN: usize = 32;

pub fn index(handshake_hash: &[u8; 32], pc_nonce: &[u8; NONCE_LEN], phone_nonce: &[u8; NONCE_LEN]) -> usize {
    let ikm = [handshake_hash.as_slice(), pc_nonce, phone_nonce].concat();
    let mut okm = [0u8; 32];
    Hkdf::<Sha256>::new(None, &ikm)
        .expand(b"bwphone/v3/emoji", &mut okm)
        .expect("32 bytes is a valid HKDF-SHA256 length");
    (okm[0] & 0x1F) as usize
}

pub fn for_session(handshake_hash: &[u8; 32], pc_nonce: &[u8; NONCE_LEN], phone_nonce: &[u8; NONCE_LEN]) -> &'static str {
    EMOJI[index(handshake_hash, pc_nonce, phone_nonce)]
}

/// Phone side: the real index plus four decoys drawn without replacement from
/// the other 31, shuffled. No emoji appears twice.
pub fn phone_choices<R: rand::Rng + rand::CryptoRng>(real: usize, rng: &mut R) -> [usize; CHOICES] {
    let mut others: Vec<usize> = (0..EMOJI.len()).filter(|&i| i != real).collect();
    others.shuffle(rng);
    let mut choices = [real, others[0], others[1], others[2], others[3]];
    choices.shuffle(rng);
    choices
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_is_32_distinct() {
        let mut v = EMOJI.to_vec();
        v.sort();
        v.dedup();
        assert_eq!(v.len(), 32);
    }

    #[test]
    fn choices_are_distinct_and_contain_the_real_one() {
        let mut rng = rand::rngs::OsRng;
        for real in 0..EMOJI.len() {
            for _ in 0..50 {
                let c = phone_choices(real, &mut rng);
                assert!(c.contains(&real));
                let mut s = c.to_vec();
                s.sort();
                s.dedup();
                assert_eq!(s.len(), CHOICES);
            }
        }
    }

    #[test]
    fn derivation_is_deterministic_in_range_and_depends_on_every_input() {
        let (h, l, p) = ([42u8; 32], [1u8; 32], [2u8; 32]);
        assert_eq!(index(&h, &l, &p), index(&h, &l, &p));
        assert!(index(&h, &l, &p) < 32);
        // Each input moves the result somewhere over a few tries: no input is ignored.
        let moved = |f: &dyn Fn(u8) -> usize| (0..64u8).any(|i| f(i) != f(0));
        assert!(moved(&|i| index(&[i; 32], &l, &p)));
        assert!(moved(&|i| index(&h, &[i; 32], &p)));
        assert!(moved(&|i| index(&h, &l, &[i; 32])));
    }

    /// The phone's nonce arrives after the PC's is committed, so a PC
    /// that wants a particular emoji cannot choose its nonce to get it: over
    /// random phone nonces the outcome is uniform regardless of the PC's.
    #[test]
    fn pc_cannot_steer_across_phone_nonces() {
        use rand::RngCore as _;
        let h = [7u8; 32];
        let pc = [9u8; 32];
        let mut counts = [0u32; 32];
        let mut rng = rand::rngs::OsRng;
        for _ in 0..3200 {
            let mut phone = [0u8; 32];
            rng.fill_bytes(&mut phone);
            counts[index(&h, &pc, &phone)] += 1;
        }
        assert!(counts.iter().all(|&c| (40..=160).contains(&c)), "{counts:?}");
    }
}
