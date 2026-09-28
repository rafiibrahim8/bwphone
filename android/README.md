# bwphone for Android

The phone half of the phone-gated Bitwarden unlock. Everything that must
agree with the PC byte for byte comes from `bwphone-transport` through
uniffi; this app owns the Keystore key, the `BiometricPrompt`, the UI and the
Wi-Fi socket. Target: Android 9 (API 28) and up.

## Build

1. Build the Rust library for the phone (from the repo root):

       cargo install cargo-ndk
       rustup target add aarch64-linux-android
       export ANDROID_NDK_HOME=~/Android/Sdk/ndk/26.3.11579264
       cargo ndk -t arm64-v8a -o android/app/src/main/jniLibs build --release -p bwphone-android

2. Regenerate the Kotlin binding whenever the Rust surface changes and copy
   it over the checked-in copy:

       ./crates/bwphone-android/gen-kotlin.sh
       cp crates/bwphone-android/out/kotlin/uniffi/bwphone_android/bwphone_android.kt \
          android/app/src/main/java/uniffi/bwphone_android/

3. Build the APK. It needs the Android SDK with platform 37.2 and
   build-tools 37.0.0 (`sdkmanager "platforms;android-37.2" "build-tools;37.0.0"`)
   and JDK 17 or newer; the wrapper fetches Gradle 9.8.0:

       cd android && ./gradlew assembleDebug      # or assembleRelease

   Every version (the SDK levels, AGP, Kotlin, the Compose BOM, each library) is in
   `gradle/libs.versions.toml`. The UI is Jetpack Compose with Material 3
   Expressive, which ships only in material3 1.5, so the build uses the
   Compose alpha BOM and compileSdk 37.2; targetSdk is 36 (Android 16 behaviour).

   Debug builds add `GalleryActivity`, every screen with sample data and no
   PC, for checking the design in light and dark:

       adb shell am start -n me.ibrahimrafi.bwphone/.GalleryActivity --es screen unlock --ez dark true

   `screen` is one of home, home-new, unlock, unlock-warn, pair, pair-wait,
   enrol, enrol-compare, enrol-test, enrol-done, revoke.

## On the phone, once

1. Install and open. Home lists two **Setup checks**:
   - **Unlock notifications** — needed; without them a request can't reach
     you while the phone is locked.
   - **Answer while the phone sleeps** (the battery optimisation exemption) —
     optional. With it the phone answers from your pocket. Without it Doze
     cuts the app's network while the screen has been off a while, so wake
     the phone (a screen unlock is enough) before unlocking the vault; a
     request that finds it asleep falls back to the password within 5 s. If
     the phone maker's battery manager stops the listener, opening the app
     starts it again.
2. **Pair with PC**: scan the QR from `bwphone pair`, confirm the six
   words on both screens.
3. **Enrol an account**: open the Enrol screen (or just have the app open;
   the PC's request brings the Enrol screen up), run
   `bwphone enroll --label <name>` on the PC, compare the key fingerprint
   shown on both, then let the PC's self-test unlock run (emoji pick +
   fingerprint). The account's name is the PC's `--label`; the phone
   shows it and cannot change it, so both sides always agree.

While the app is open, an unlock request opens the emoji pick by itself,
without the heads-up. Opening the app while a request waits does the same,
so the notification doesn't have to be tapped.

**Revoke** an account or **Revoke all** works with no PC present; it
destroys the Keystore key, so every copy of that `vault.blob` is unopenable
at once.

## Layout

| File | Owns |
|---|---|
| `Prefs.kt` | Keystore-sealed preferences (`SealedPrefs.kt`, replaces the deprecated security-crypto): channel key, pairing values, per-account label/pin/counts, rate-limit state, history |
| `Keystore.kt` | The RSA-2048 unwrap key per account (exact spec flags), the OAEP decrypt cipher with explicit SHA-256 MGF1, invalidation probing |
| `ListenerService.kt` | Foreground service; Wi-Fi-only listener that rebinds on network change; the unlock notification; the wake lock |
| `Session.kt` | One connection: handshake, one request, pin check, busy/rate/invalidation, the prompt bridge, enrol and set_pin |
| `PendingRequest.kt` | The request in flight, shared between the socket thread and the screen; observable, so an open screen jumps to the pick |
| `AppState.kt` | Whether a screen is in front, a change signal for the screens, the listener's status |
| `BaseActivity.kt` | Every screen: opens the unlock or Enrol screen when a request arrives while it is showing |
| `UnlockActivity.kt` | Emoji pick, then `BiometricPrompt(CryptoObject(cipher))` |
| `PairActivity.kt` | QR scan, `Noise_NKpsk0`, PairHello, six words, mutual confirm, commit |
| `EnrolActivity.kt` / `EnrolState.kt` | The Enrol screen and the window that gates `enrol_begin`/`set_pin`, with its progress |
| `ui/` | Compose: `Theme.kt` (colours, Roboto Flex), `Components.kt`, and one file per screen |
| `Hello.kt` | mDNS query for the PC's rotating name, then the encrypted UDP hello |
| `Net.kt` | Wi-Fi network selection and its IPv4 address |
| `RateLimit.kt` | Per-hour caps, overall and per account |
| `MainActivity.kt` | Status, setup checks, Revoke, history |
| `BootReceiver.kt` | `BOOT_COMPLETED` and `MY_PACKAGE_REPLACED` |
