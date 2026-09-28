# bwphone-android

`bwphone-transport` for the phone, through [uniffi](https://mozilla.github.io/uniffi-rs/).
Both devices run one Noise implementation; the phone never reimplements a
byte of the protocol. See the crate docs in `src/lib.rs` for why the surface
is sans-I/O and what stays native in Kotlin.

## Generate the Kotlin

    ./crates/bwphone-android/gen-kotlin.sh

Writes `out/kotlin/uniffi/bwphone_android/bwphone_android.kt`. Copy it into
the app's source set; it needs `net.java.dev.jna:jna:5.x@aar` at runtime.

## Build the `.so` for the phone

    cargo install cargo-ndk
    rustup target add aarch64-linux-android
    export ANDROID_NDK_HOME=~/Android/Sdk/ndk/26.3.11579264
    cargo ndk -t arm64-v8a -o app/src/main/jniLibs build --release -p bwphone-android

The app loads it as `libbwphone_android.so`. Regenerate the Kotlin whenever
the Rust surface changes; the two must come from the same build.

## Using it from Kotlin, in outline

```kotlin
val key = StaticKey.fromPrivate(prefs.phonePrivate)          // or generate() at pairing
val hs = Handshake.kkResponder(key, prefs.pcPublic, prefs.pairingId)
val decoder = FrameDecoder()
while (!hs.isFinished()) {
    if (hs.isMyTurn()) socket.write(frameEncode(hs.writeMessage()))
    else hs.readMessage(nextFrame(socket, decoder))        // 5 s pre-auth timeout around this
}
val t = hs.intoTransport()
val req = parseRequest(t.open(nextFrame(socket, decoder)))  // refuse anything that fails, silently
val unwrap = req.request as PhoneRequest.Unwrap
// pin check first, then the emoji: our nonce is chosen only now that the PC's is committed
val myNonce = phoneNonce()
val real = emojiIndex(t.handshakeHash(), unwrap.nonce, myNonce)
val choices = phoneChoices(real)                              // the real one plus four decoys, shuffled
socket.write(frameEncode(t.seal(encodeResponse(req.reqId, PhoneStatus.PROMPT_POSTED, myNonce, null, null, null))))
// emoji pick → BiometricPrompt(CryptoObject(cipher)) → OK with K_wrap
```
