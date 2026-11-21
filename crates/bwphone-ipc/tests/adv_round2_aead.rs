//! Round 2, fix 2: the hand-rolled transport AEAD against snow's own
//! ciphers (the `browser` initiator seals and opens with snow), every
//! suite, at the edges: empty plaintext, one byte, the largest frame,
//! one past it, and nonces that differ only in their high bytes (which
//! would catch a wrong endianness in the 12-byte nonce).
//!
//! `cargo test -p bwphone-ipc --all-features --test adv_round2_aead`

use bwphone_ipc::{
    IpcError,
    frame::CipherSuite,
    noise::{MAX_PLAINTEXT, initiator::Initiator, respond},
};

const SUITES: [CipherSuite; 3] = [
    CipherSuite::Noise_NN_P256_AESGCM_SHA256,
    CipherSuite::Noise_NN_25519_AESGCM_SHA256,
    CipherSuite::Noise_NN_25519_ChaChaPoly_BLAKE2s,
];

#[test]
fn aead_matches_snow_at_the_edges() {
    for suite in SUITES {
        let (mut browser, start) = Initiator::start(suite);
        let (finish, mut session) = respond(&start).unwrap();
        browser.finish(&finish);

        for len in [0usize, 1, 15, 16, 17, 4096, MAX_PLAINTEXT] {
            let plain: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
            // browser (snow) -> daemon (ours)
            let f = browser.seal(&plain);
            assert_eq!(f.payload.len(), len + 16, "{suite:?} {len}");
            assert_eq!(&*session.open(&f).unwrap(), &plain[..], "{suite:?} {len}: ours failed to open snow's");
            // daemon (ours) -> browser (snow)
            let r = session.seal(&plain).unwrap();
            assert_eq!(browser.open(&r), plain, "{suite:?} {len}: snow failed to open ours");
        }
        // Nonces far apart: low 32 bits equal, high bits differ.
        browser.send_nonce = (1u64 << 40) - 1;
        let f = browser.seal(b"high nonce");
        assert_eq!(f.nonce, 1u64 << 40);
        assert_eq!(&*session.open(&f).unwrap(), b"high nonce", "{suite:?}: nonce layout");

        // One past the largest frame is refused, not truncated or panicking.
        assert!(matches!(session.seal(&vec![0u8; MAX_PLAINTEXT + 1]), Err(IpcError::TooLarge)));
    }
}

/// The scalar-safe RNG is used on every handshake: hundreds of P-256
/// responder handshakes all produce a valid uncompressed point and finish.
#[test]
fn many_p256_handshakes_finish() {
    for _ in 0..200 {
        let (mut browser, start) = Initiator::start(CipherSuite::Noise_NN_P256_AESGCM_SHA256);
        let (finish, mut session) = respond(&start).unwrap();
        assert_eq!(finish.noise_frame.len(), 65 + 16, "e, then the empty payload under ee");
        assert_eq!(finish.noise_frame[0], 4);
        browser.finish(&finish);
        assert_eq!(&*session.open(&browser.seal(b"x")).unwrap(), b"x");
    }
}
