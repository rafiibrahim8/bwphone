//! Adversarial: hostile frame content must never panic (release is
//! `panic = "abort"`, so a panic kills the daemon) and must not blow the
//! stack of a tokio worker thread (2 MiB).
//!
//! `cargo test -p bwphone-ipc --features browser --test adv_security_fuzz`

use bwphone_ipc::{
    envelope::{self, Us},
    frame::{CipherSuite, Frame, HandshakeStart, TransportFrame},
    noise::{self, initiator::Initiator},
    peer::{Event, Peer},
    rpc,
};
use serde_json::json;

const TOKIO_WORKER_STACK: usize = 2 * 1024 * 1024;

fn on_worker_stack<F: FnOnce() + Send + 'static>(f: F) {
    std::thread::Builder::new().stack_size(TOKIO_WORKER_STACK).spawn(f).unwrap().join().unwrap();
}

fn env(to: &str, payload: &[u8], topic: Option<&str>) -> Vec<u8> {
    serde_json::to_vec(&json!({"type": "bitwarden-ipc-message", "message": {
        "destination": to, "payload": payload, "topic": topic
    }}))
    .unwrap()
}

fn cbor_text(s: &str) -> Vec<u8> {
    assert!(s.len() < 24);
    let mut v = vec![0x60 | s.len() as u8];
    v.extend_from_slice(s.as_bytes());
    v
}

/// {"HandshakeStart": {"ciphersuite": "...P256...", "noise_frame": [], "x": <extra>}}
fn handshake_start_with_extra(extra: &[u8]) -> Vec<u8> {
    let mut v = vec![0xa1];
    v.extend(cbor_text("HandshakeStart"));
    v.push(0xa3);
    v.extend(cbor_text("ciphersuite"));
    v.push(0x78);
    v.push(27);
    v.extend_from_slice(b"Noise_NN_P256_AESGCM_SHA256");
    v.extend(cbor_text("noise_frame"));
    v.push(0x80);
    v.extend(cbor_text("x"));
    v.extend_from_slice(extra);
    v
}

fn established() -> (Peer, Initiator) {
    let mut peer = Peer::new();
    let (mut browser, start) = Initiator::start(CipherSuite::Noise_NN_P256_AESGCM_SHA256);
    let Event::Send(reply) = peer.receive(&env("DesktopRenderer", &Frame::HandshakeStart(start).to_cbor(), None)).unwrap()
    else {
        panic!()
    };
    let v: serde_json::Value = serde_json::from_slice(&reply).unwrap();
    let payload: Vec<u8> = serde_json::from_value(v["message"]["payload"].clone()).unwrap();
    let Frame::HandshakeFinish(finish) = Frame::from_cbor(&payload).unwrap() else { panic!() };
    browser.finish(&finish);
    (peer, browser)
}

#[test]
fn deeply_nested_cbor_in_an_ignored_field_fits_a_worker_stack() {
    on_worker_stack(|| {
        for depth in [200usize, 254, 255, 256, 300, 100_000] {
            for (open, close) in [(vec![0x81u8], vec![]), (vec![0xa1, 0x00], vec![]), (vec![0xc6], vec![]), (vec![0x9f], vec![0xff])]
            {
                let mut extra = Vec::new();
                for _ in 0..depth {
                    extra.extend_from_slice(&open);
                }
                extra.push(0x00);
                for _ in 0..depth {
                    extra.extend_from_slice(&close);
                }
                let frame = handshake_start_with_extra(&extra);
                let _ = Frame::from_cbor(&frame);
                let _ = Peer::new().receive(&env("DesktopRenderer", &frame, None));
            }
        }
    });
}

#[test]
fn deeply_nested_json_envelope_fits_a_worker_stack() {
    on_worker_stack(|| {
        for depth in [127usize, 128, 129, 10_000] {
            let dest = format!("{}1{}", "[".repeat(depth), "]".repeat(depth));
            let frame = format!(r#"{{"type":"bitwarden-ipc-message","message":{{"destination":{dest},"payload":[]}}}}"#);
            let _ = bwphone_ipc::is_ipc(frame.as_bytes());
            let _ = Peer::new().receive(frame.as_bytes());
            let rpc = format!(r#"{{"request":{dest},"request_id":"a","request_type":"UnlockBiometrics","response_topic":"t"}}"#);
            let _ = rpc::parse(rpc.as_bytes());
        }
    });
}

#[test]
fn hostile_noise_frames_never_panic() {
    let suites = [
        CipherSuite::Noise_NN_P256_AESGCM_SHA256,
        CipherSuite::Noise_NN_25519_AESGCM_SHA256,
        CipherSuite::Noise_NN_25519_ChaChaPoly_BLAKE2s,
    ];
    let mut frames: Vec<Vec<u8>> = vec![vec![], vec![4], vec![0; 32], vec![0; 64], vec![0; 65], vec![0xff; 65], vec![0; 65535], vec![0; 65536]];
    let mut p = vec![4u8];
    p.extend([0xffu8; 64]);
    frames.push(p);
    let mut p = vec![2u8];
    p.extend([0x11u8; 64]);
    frames.push(p);
    // x25519 low-order points.
    let mut one = [0u8; 32];
    one[0] = 1;
    frames.push(one.to_vec());
    frames.push(
        [
            0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a, 0xda, 0x09, 0x8d, 0xeb,
            0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00,
        ]
        .to_vec(),
    );
    for suite in suites {
        for f in &frames {
            let _ = noise::respond(&HandshakeStart { ciphersuite: suite, noise_frame: f.clone() });
        }
    }
}

#[test]
fn transport_payload_sizes_and_nonces_never_panic() {
    let (mut peer, mut browser) = established();
    let mut sizes: Vec<usize> = (0..=40).collect();
    sizes.extend([65534, 65535, 65536, 65551, 65552, 200_000]);
    for len in sizes {
        for nonce in [0u64, 1, 2, u64::MAX - 1, u64::MAX] {
            let t = TransportFrame { payload: vec![0xaa; len].into(), nonce };
            let _ = peer.receive(&env("DesktopRenderer", &Frame::TransportFrame(t).to_cbor(), Some(rpc::REQUEST_TOPIC)));
        }
    }
    // An honest frame at u64::MAX opens; the channel is then dead until a re-handshake.
    browser.send_nonce = u64::MAX - 1;
    let body = br#"{"request":null,"request_id":"a","request_type":"DiscoverRequest","response_topic":"t"}"#;
    let frame = env("DesktopRenderer", &Frame::TransportFrame(browser.seal(body)).to_cbor(), Some(rpc::REQUEST_TOPIC));
    assert!(matches!(peer.receive(&frame), Ok(Event::Call { .. })));
    // Bignum-tagged and absurd nonces in CBOR.
    let mut v = vec![0xa1];
    v.extend(cbor_text("TransportFrame"));
    v.push(0xa2);
    v.extend(cbor_text("payload"));
    v.push(0x40);
    v.extend(cbor_text("nonce"));
    for nonce in [vec![0xc2, 0x50].into_iter().chain([0xff; 16]).collect::<Vec<_>>(), vec![0xc2, 0x51].into_iter().chain([0xff; 17]).collect(), vec![0xc3, 0x41, 0x05], vec![0x3b, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff]] {
        let mut f = v.clone();
        f.extend(nonce);
        let _ = Frame::from_cbor(&f);
        let _ = peer.receive(&env("DesktopRenderer", &f, Some(rpc::REQUEST_TOPIC)));
    }
}

#[test]
fn huge_declared_cbor_lengths_do_not_allocate_or_panic() {
    // Array / bytes / text / map declaring u64::MAX elements, with nothing behind them.
    for head in [0x9bu8, 0x5b, 0x7b, 0xbb] {
        let mut extra = vec![head];
        extra.extend([0xff; 8]);
        let _ = Frame::from_cbor(&handshake_start_with_extra(&extra));
        // As the noise_frame itself (a Vec<u8> via serde's seq visitor).
        let mut v = vec![0xa1];
        v.extend(cbor_text("HandshakeStart"));
        v.push(0xa2);
        v.extend(cbor_text("ciphersuite"));
        v.push(0x78);
        v.push(27);
        v.extend_from_slice(b"Noise_NN_P256_AESGCM_SHA256");
        v.extend(cbor_text("noise_frame"));
        v.extend(&extra);
        let _ = Frame::from_cbor(&v);
    }
}

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n.max(1) as u64) as usize
    }
}

const INTERESTING: [u8; 16] = [0x00, 0xff, 0x1b, 0x9f, 0xbf, 0x5f, 0x7f, 0xc2, 0xc3, 0xc6, 0xf7, 0xf9, 0xfa, 0xfb, 0x18, 0x80];

fn mutate(rng: &mut Rng, seed: &[u8]) -> Vec<u8> {
    let mut v = seed.to_vec();
    for _ in 0..=rng.below(4) {
        match rng.below(5) {
            0 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] ^= 1 << rng.below(8);
            }
            1 if !v.is_empty() => {
                let i = rng.below(v.len());
                v[i] = INTERESTING[rng.below(INTERESTING.len())];
            }
            2 => {
                let i = rng.below(v.len() + 1);
                v.insert(i, INTERESTING[rng.below(INTERESTING.len())]);
            }
            3 if !v.is_empty() => {
                let i = rng.below(v.len());
                v.truncate(i);
            }
            _ if !v.is_empty() => {
                let i = rng.below(v.len());
                v.remove(i);
            }
            _ => {}
        }
    }
    v
}

#[test]
fn mutated_frames_never_panic() {
    on_worker_stack(|| {
        let (mut peer, mut browser) = established();
        let (_, start) = Initiator::start(CipherSuite::Noise_NN_P256_AESGCM_SHA256);
        let (_, start25519) = Initiator::start(CipherSuite::Noise_NN_25519_ChaChaPoly_BLAKE2s);
        let body = br#"{"request":{"user_id":"u"},"request_id":"a","request_type":"UnlockBiometrics","response_topic":"t"}"#;
        let seeds = [
            Frame::HandshakeStart(start).to_cbor(),
            Frame::HandshakeStart(start25519).to_cbor(),
            Frame::TransportFrame(browser.seal(body)).to_cbor(),
            Frame::CryptoInvalidated.to_cbor(),
            Frame::TransportFrame(TransportFrame { payload: vec![1; 20].into(), nonce: 5 }).to_cbor(),
        ];
        let mut rng = Rng(0x9e37_79b9_7f4a_7c15);
        for i in 0..60_000 {
            let seed = &seeds[i % seeds.len()];
            let m = mutate(&mut rng, seed);
            let _ = Frame::from_cbor(&m);
            let _ = peer.receive(&env(if i % 2 == 0 { "DesktopRenderer" } else { "DesktopMain" }, &m, Some(rpc::REQUEST_TOPIC)));
            // Keep a live session so transport frames reach decryption.
            if i % 1000 == 0 {
                (peer, _) = established();
            }
        }
        // RPC plaintext and envelopes.
        let rpc_seeds: [&[u8]; 3] = [
            body,
            br#"{"request":null,"request_id":"a","request_type":"DiscoverRequest","response_topic":"t"}"#,
            br#"{"type":"bitwarden-ipc-message","message":{"destination":"DesktopRenderer","payload":[1,2,3],"topic":"RpcRequestMessage"}}"#,
        ];
        for i in 0..60_000 {
            let m = mutate(&mut rng, rpc_seeds[i % 3]);
            let _ = rpc::parse(&m);
            let _ = bwphone_ipc::is_ipc(&m);
            let _ = envelope::parse(&m);
            let _ = Peer::new().receive(&m);
        }
        // Answers with hostile ids never panic.
        let (mut peer, mut browser) = established();
        let weird = r#"{"request":{"user_id":"u"},"request_id":"\u0000\ud800","request_type":"UnlockBiometrics","response_topic":"\u0001"}"#;
        let r = peer.receive(&env("DesktopRenderer", &Frame::TransportFrame(browser.seal(weird.as_bytes())).to_cbor(), Some(rpc::REQUEST_TOPIC)));
        if let Ok(Event::Call { id, to, .. }) = r {
            let _ = peer.answer(to, &id, &rpc::Response::Unlock(Some(zeroize::Zeroizing::new("x".into()))));
        }
        let _ = peer.answer(Us::DesktopMain, &rpc::CallId { request_id: "a".repeat(70_000), request_type: "b".into(), response_topic: "c".into() }, &rpc::Response::Bool(true));
    });
}
