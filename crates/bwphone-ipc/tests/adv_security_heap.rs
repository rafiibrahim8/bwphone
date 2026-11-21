//! Adversarial: secrets left behind in freed heap memory.
//!
//! A spying global allocator scans every block as it is freed (with the
//! default `realloc`, which moves: alloc, copy, dealloc, as glibc does
//! whenever it cannot grow in place) for a needle, while armed.
//!
//! `cargo test -p bwphone-ipc --features browser --test adv_security_heap`

use std::{
    alloc::{GlobalAlloc, Layout, System},
    cell::UnsafeCell,
    sync::{
        Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering::SeqCst},
    },
};

use bwphone_ipc::{
    frame::{CipherSuite, Frame},
    noise::initiator::Initiator,
    peer::{Event, Peer},
    rpc::{self, Response},
};
use serde_json::json;
use zeroize::Zeroizing;

/// 64 bytes of user key, base64: 88 characters, distinctive.
const USER_KEY_B64: &str = "VVNFUktFWS1VU0VSS0VZLVVTRVJLRVktVVNFUktFWS1VU0VSS0VZLVVTRVJLRVktVVNFUktFWS1VU0VSS0VZLTEyMzQ1Njc4OTA=";
const NEEDLE: &[u8] = b"VVNFUktFWS1VU0VSS0VZLVVTRVJLRVkt";

static ARMED: AtomicBool = AtomicBool::new(false);
static HIT: AtomicBool = AtomicBool::new(false);
/// While armed, copies of every freed 32-byte block (snow's boxed AEAD is exactly its key).
static RECORD_32: AtomicBool = AtomicBool::new(false);
struct Slots(UnsafeCell<[[u8; 32]; 4096]>);
unsafe impl Sync for Slots {}
static SLOTS: Slots = Slots(UnsafeCell::new([[0; 32]; 4096]));
static NSLOTS: AtomicUsize = AtomicUsize::new(0);
static SERIAL: Mutex<()> = Mutex::new(());

struct Spy;

unsafe impl GlobalAlloc for Spy {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        unsafe { System.alloc(layout) }
    }

    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        if ARMED.load(SeqCst) {
            let block = unsafe { std::slice::from_raw_parts(ptr, layout.size()) };
            if block.windows(NEEDLE.len()).any(|w| w == NEEDLE) {
                HIT.store(true, SeqCst);
            }
            if RECORD_32.load(SeqCst) && layout.size() == 32 {
                let i = NSLOTS.fetch_add(1, SeqCst);
                if i < 4096 {
                    unsafe { (&mut (*SLOTS.0.get()))[i].copy_from_slice(block) };
                }
            }
        }
        unsafe { System.dealloc(ptr, layout) }
    }
}

#[global_allocator]
static GLOBAL: Spy = Spy;

fn env(payload: &[u8], topic: Option<&str>) -> Vec<u8> {
    serde_json::to_vec(&json!({"type": "bitwarden-ipc-message", "message": {
        "destination": "DesktopRenderer", "payload": payload, "topic": topic
    }}))
    .unwrap()
}

fn established() -> (Peer, Initiator) {
    let mut peer = Peer::new();
    let (mut browser, start) = Initiator::start(CipherSuite::Noise_NN_P256_AESGCM_SHA256);
    let Event::Send(reply) = peer.receive(&env(&Frame::HandshakeStart(start).to_cbor(), None)).unwrap() else { panic!() };
    let v: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    let payload: Vec<u8> = serde_json::from_value(v["message"]["payload"].clone()).unwrap();
    let Frame::HandshakeFinish(finish) = Frame::from_cbor(&payload).unwrap() else { panic!() };
    browser.finish(&finish);
    (peer, browser)
}

/// Daemon side of one unlock answer for a request with this raw JSON request_id.
fn answer_unlock_with_request_id(request_id_json: &str) -> bool {
    let (mut peer, mut browser) = established();
    let body = format!(
        r#"{{"request":{{"user_id":"u"}},"request_id":{request_id_json},"request_type":"UnlockBiometrics","response_topic":"RpcResponseMessage:x"}}"#
    );
    let frame = env(&Frame::TransportFrame(browser.seal(body.as_bytes())).to_cbor(), Some(rpc::REQUEST_TOPIC));
    let Event::Call { to, id, .. } = peer.receive(&frame).unwrap() else { panic!() };
    let response = Response::Unlock(Some(Zeroizing::new(USER_KEY_B64.to_owned())));
    HIT.store(false, SeqCst);
    ARMED.store(true, SeqCst);
    let out = peer.answer(to, &id, &response);
    drop(response);
    ARMED.store(false, SeqCst);
    assert!(out.is_ok());
    HIT.load(SeqCst)
}

/// Control: with the extension's real request_id (a UUID) nothing leaks,
/// which also shows the spy has no false positives.
#[test]
fn honest_request_id_leaves_no_user_key_in_freed_memory() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    assert!(!answer_unlock_with_request_id(r#""6e5f3b2a-0c1d-4e8f-9a7b-112233445566""#));
}

/// serde_json escapes each control character in `request_id` to six bytes
/// (`\u0001`), and `request_id` is written *after* `result` (the key). If
/// `rpc::encode`'s buffer reallocated, the old block, holding the base64
/// user key, would go back to the allocator un-zeroised. Ids are capped at
/// `rpc::MAX_ID_LEN` and the buffer is sized for that cap fully escaped.
#[test]
fn escaped_request_id_reallocates_the_key_buffer_unzeroised() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    // The worst id still accepted: every byte a control character.
    let hostile = format!("\"{}\"", r"\u0001".repeat(rpc::MAX_ID_LEN));
    assert!(
        !answer_unlock_with_request_id(&hostile),
        "the base64 user key was found in a freed, un-zeroised heap block after rpc::encode reallocated"
    );
    // One byte longer is refused before it gets near the key.
    let too_long = format!("{{\"request\":null,\"request_id\":\"{}\",\"request_type\":\"UnlockBiometrics\",\"response_topic\":\"t\"}}", "x".repeat(rpc::MAX_ID_LEN + 1));
    assert!(rpc::parse(too_long.as_bytes()).is_err());
}

/// `Session` keeps its keys in `Zeroizing`, but every `open`/`seal` copies
/// the key into a fresh `Box<dyn snow::types::Cipher>` (snow 0.10 never
/// zeroises), which is freed with the key still in it.
#[test]
fn session_keys_are_not_left_in_freed_memory() {
    let _g = SERIAL.lock().unwrap_or_else(|e| e.into_inner());
    let (mut peer, mut browser) = established();
    let probe = browser.seal(b"probe");
    let body = br#"{"request":null,"request_id":"a","request_type":"DiscoverRequest","response_topic":"t"}"#;
    let frame = env(&Frame::TransportFrame(browser.seal(body)).to_cbor(), Some(rpc::REQUEST_TOPIC));
    NSLOTS.store(0, SeqCst);
    RECORD_32.store(true, SeqCst);
    ARMED.store(true, SeqCst);
    let _ = peer.receive(&frame);
    ARMED.store(false, SeqCst);
    RECORD_32.store(false, SeqCst);
    let n = NSLOTS.load(SeqCst).min(4096);
    let slots: Vec<[u8; 32]> = unsafe { (&(*SLOTS.0.get()))[..n].to_vec() };
    use snow::resolvers::{CryptoResolver as _, DefaultResolver};
    let found = slots.iter().any(|k| {
        let mut c = DefaultResolver.resolve_cipher(&snow::params::CipherChoice::AESGCM).unwrap();
        c.set(k);
        let mut out = vec![0u8; probe.payload.len()];
        c.decrypt(probe.nonce, &[], &probe.payload, &mut out).is_ok()
    });
    assert!(!found, "the browser→daemon session key was recovered from a freed heap block ({n} 32-byte blocks freed)");
}
