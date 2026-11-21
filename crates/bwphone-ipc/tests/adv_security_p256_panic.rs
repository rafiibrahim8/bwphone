//! Adversarial: every `HandshakeStart` on the default P-256 suite makes
//! the daemon generate an ephemeral with snow 0.10's P256 `generate`, which
//! takes 32 random bytes as the scalar and calls
//! `p256::SecretKey::from_bytes(..).unwrap()` (`snow/src/resolvers/default.rs:256`).
//! Bytes that are zero or >= the group order n (probability ~2^-32 per
//! handshake) panic instead of erroring; in release (`panic = "abort"`)
//! that kills the daemon.
//!
//! This test runs snow's responder path with an RNG that produces such
//! bytes and records that snow still panics: the bug is upstream. bwphone
//! does not depend on it being fixed: `noise::respond` gives snow an RNG
//! that redraws any 32-byte value outside [1, n) (`fill_scalar_safe`,
//! unit-tested in `noise::tests::out_of_range_draws_are_redrawn`), so
//! snow never sees one. If snow ever errors instead of panicking, this
//! test fails and the workaround can go.
//!
//! `cargo test -p bwphone-ipc --features browser --test adv_security_p256_panic`

use bwphone_ipc::{frame::CipherSuite, noise::initiator::Initiator};
use snow::{
    params::{CipherChoice, DHChoice, HashChoice},
    resolvers::{CryptoResolver, DefaultResolver},
    types::{Cipher, Dh, Hash, Random},
};

struct AllOnes;
impl Random for AllOnes {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        dest.fill(0xff); // >= n: one of the ~2^224 values the OS RNG can also produce
        Ok(())
    }
}

struct Unlucky;
impl CryptoResolver for Unlucky {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(AllOnes))
    }
    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        DefaultResolver.resolve_dh(choice)
    }
    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        DefaultResolver.resolve_hash(choice)
    }
    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        DefaultResolver.resolve_cipher(choice)
    }
}

#[test]
fn snow_still_panics_on_an_out_of_range_p256_ephemeral() {
    let (_browser, start) = Initiator::start(CipherSuite::Noise_NN_P256_AESGCM_SHA256);
    let outcome = std::panic::catch_unwind(|| {
        let params = start.ciphersuite.name().parse().unwrap();
        let mut state = snow::Builder::with_resolver(params, Box::new(Unlucky)).build_responder().map_err(|_| ())?;
        let mut buf = vec![0u8; 65535];
        state.read_message(&start.noise_frame, &mut buf).map_err(|_| ())?;
        state.write_message(&[], &mut buf).map_err(|_| ()).map(|_| ())
    });
    assert!(outcome.is_err(), "snow no longer panics on an out-of-range P-256 scalar: the redraw workaround in noise.rs can go");
}
