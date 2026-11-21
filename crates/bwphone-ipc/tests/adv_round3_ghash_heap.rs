//! Round 3: SPECIFICATION.md §3 says "The transport AEAD keys live in
//! `aes-gcm` / `chacha20poly1305`, which wipe them on drop" (noise.rs:17-18,
//! 97: "Both wipe their key schedule on drop").
//!
//! `bwphone-ipc` enables `aes/zeroize` and `aes-gcm/zeroize`, which wipe the
//! AES round keys. But AES-GCM's second key, the GHASH subkey
//! H = AES_K(0^128), lives in `ghash`/`polyval`, whose `zeroize` feature is
//! not enabled anywhere in the workspace (`cargo tree -e features -i ghash`).
//! `aes-gcm`'s own `zeroize` feature only wipes the stack temporary it
//! builds H in (aes-gcm 0.10.3 `src/lib.rs:239`). So a dropped
//! `Box<Aes256Gcm>` (noise.rs `Aead::AesGcm`) goes back to the allocator
//! with H (as POLYVAL's `mulX(rev(H))`) still in it.
//!
//! A spying allocator copies every block freed while armed; the test drops
//! exactly the boxed AEAD noise.rs builds and looks for the key and for H.
//!
//! Not fixed yet: a temporary limitation, SPECIFICATION.md §15 "GHASH
//! subkey left in freed memory". polyval 0.6's runtime-dispatched backend
//! never drops (so never wipes) its state whatever features are on, and
//! wiping the allocation from bwphone would take `unsafe`. The first test
//! is the fix's target and is ignored until then; the second records that
//! the crates still leave H, and fails once they stop (time to un-ignore).
//!
//! `cargo test -p bwphone-ipc --all-features --test adv_round3_ghash_heap`

use std::{
    alloc::{GlobalAlloc, Layout, System},
    sync::{
        Mutex,
        atomic::{AtomicBool, Ordering::SeqCst},
    },
};

use aes::cipher::{BlockEncrypt as _, KeyInit as _};
use aes_gcm::Aes256Gcm;

static ARMED: AtomicBool = AtomicBool::new(false);
static FREED: Mutex<Vec<u8>> = Mutex::new(Vec::new());

struct Spy;

unsafe impl GlobalAlloc for Spy {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.swap(false, SeqCst) {
            // Disarmed while copying, so the Vec's own growth is not recorded.
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            FREED.lock().unwrap().extend_from_slice(block);
            ARMED.store(true, SeqCst);
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Spy = Spy;

/// POLYVAL's mulX (RFC 8452 appendix A), as `ghash` applies it to rev(H).
fn mulx(block: [u8; 16]) -> [u8; 16] {
    let mut v = u128::from_le_bytes(block);
    let hi = v >> 127;
    v <<= 1;
    v ^= hi ^ (hi << 127) ^ (hi << 126) ^ (hi << 121);
    v.to_le_bytes()
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

/// H = AES_K(0^128) and the two forms the GHASH/POLYVAL code keeps it in.
fn h_forms(key: &[u8; 32]) -> [[u8; 16]; 3] {
    let mut h = aes::Block::default();
    aes::Aes256::new(key.into()).encrypt_block(&mut h);
    let h: [u8; 16] = h.into();
    let mut rev = h;
    rev.reverse();
    [h, rev, mulx(rev)]
}

/// Drops `value` with the spy armed; returns every byte freed meanwhile.
fn freed_by<T>(value: T) -> Vec<u8> {
    FREED.lock().unwrap().clear();
    FREED.lock().unwrap().reserve(1 << 16);
    ARMED.store(true, SeqCst);
    drop(value);
    ARMED.store(false, SeqCst);
    FREED.lock().unwrap().clone()
}

static SERIAL: Mutex<()> = Mutex::new(());

#[test]
#[ignore = "temporary limitation, SPECIFICATION.md §15: GHASH subkey left in freed memory; must pass once fixed"]
fn a_dropped_aes_gcm_session_key_leaves_no_key_material_in_freed_memory() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let key = [0x5au8; 32];
    // Exactly what noise.rs `Aead::new` builds for the AES-GCM suites.
    let freed = freed_by(Box::new(Aes256Gcm::new(&key.into())));
    assert!(!freed.is_empty(), "the spy saw the box freed");
    assert!(!contains(&freed, &key[..16]), "the AES key is left in freed memory");
    for form in h_forms(&key) {
        assert!(!contains(&freed, &form), "the GHASH subkey of a dropped session is left in freed memory");
    }
}

/// The crates still leave H behind (the limitation's cause). Fails once an
/// upgrade stops it: then un-ignore the test above and drop the §15 entry.
#[test]
fn the_bare_aes_gcm_crate_still_leaves_the_ghash_subkey() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let key = [0x5au8; 32];
    let freed = freed_by(Box::new(Aes256Gcm::new(&key.into())));
    let leaked = h_forms(&key).iter().any(|form| contains(&freed, form));
    assert!(leaked, "aes-gcm/polyval now wipe the GHASH subkey: un-ignore the test above and remove the SPECIFICATION.md §15 entry");
}
