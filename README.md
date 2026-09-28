# bwphone

Unlock the Bitwarden browser extension with your phone's fingerprint.

bwphone replaces the Bitwarden desktop app on a Linux PC. When the
extension asks to "unlock with biometrics", the PC shows an emoji in a
notification, your phone (running **BW Phone**) shows five, you tap the one
the PC shows and touch the fingerprint sensor. Only then does the phone
release the key the PC needs to open your vault.

The vault key is never stored in the clear: the PC keeps it wrapped to a
fingerprint-gated RSA key that lives in the phone's secure hardware and never
leaves it. How it all works, message by message, is in
[SPECIFICATION.md](SPECIFICATION.md).

- [What you need](#what-you-need)
- [Install](#install)
- [Pair the phone](#pair-the-phone-once)
- [Enrol an account](#enrol-an-account)
- [Unlocking, day to day](#unlocking-day-to-day)
- [Settings](#settings)
- [Managing accounts and the pairing](#managing-accounts-and-the-pairing)
- [Troubleshooting](#troubleshooting)
- [Build from source](#build-from-source)

## What you need

- **A Linux PC** with a systemd user session and a Secret Service wallet
  that unlocks at login (KWallet's `ksecretd` or GNOME Keyring). The PC's
  Noise key lives in that wallet, never in a file.
- **The Bitwarden extension** in Chrome, Chromium, Brave, Edge, Vivaldi or Firefox,
  installed as a normal package. Flatpak and Snap browsers can't reach a
  native-messaging host outside their sandbox.
- **The Bitwarden CLI** (`bw`), only for enrolment.
- **An Android 9 or later phone** with a fingerprint sensor and a screen lock.
- **One Wi-Fi network** for both, without client isolation (many hotel and
  guest networks block device-to-device traffic). Mobile data, a full-tunnel
  VPN or an isolated network just means you type your master password as
  before.

## Install

### PC

From a release (every `v*` tag publishes these):

| Asset | What |
|---|---|
| `bwphone-<tag>-linux-x86_64.tar.gz` | `bwphone` (daemon and CLI), `bwphone-proxy`, `bwphone-hello`, the systemd user units, man pages, bash/zsh/fish completions, `install.sh` |
| `bwphone-<tag>.apk` | BW Phone, arm64-v8a, release-signed |
| `SHA256SUMS` | Checksums of the above |

```sh
sha256sum -c SHA256SUMS --ignore-missing
tar xzf bwphone-<tag>-linux-x86_64.tar.gz
cd bwphone-<tag>-linux-x86_64
./install.sh                         # per user, under ~/.local, no root
# or system-wide binaries:  PREFIX=/usr sudo ./install.sh
#   then, as each user:     systemctl --user enable --now bwphone bwphone-hello
```

Or from a checkout: `./install.sh` builds a release and installs it the same
way. Only `bwphone` goes on `PATH`; `bwphone-proxy` (spawned by the browsers)
and `bwphone-hello` (a service) live in `<prefix>/lib/bwphone/`.

Check it is running:

```sh
systemctl --user is-active bwphone bwphone-hello     # active, active
bwphone status                                       # "paired": false for now
```

If a firewall runs on the PC, allow in **UDP 8732** (the phone's
encrypted hello), **UDP 5353** (mDNS queries from the phone) and, while
pairing, the TCP port `bwphone pair` prints (pin it with `--pair-port`). The
phone listens on TCP 8731; the PC connects out to it.

### Phone

Install `bwphone-<tag>.apk` (open it on the phone, or `adb install
bwphone-<tag>.apk`), then open **BW Phone**. Home lists two setup checks:

- **Unlock notifications allowed** — needed. Without them a request can't
  reach you while the phone is locked. Tap **Allow** if it isn't ticked.
- **Answer while the phone sleeps** — optional. It exempts BW Phone from
  battery optimisation so the phone answers from your pocket. Without it,
  Android cuts the app's network while the screen has been off a while: wake
  the phone before you unlock the vault (a screen unlock is enough).

If a release was signed with a throwaway key (no signing secrets in CI),
uninstall the previous build before installing a newer one. That destroys
the phone's keys, so pair and enrol again afterwards.

## Pair the phone (once)

Pairing makes the PC and the phone trust each other: they exchange keys
over a QR code and you confirm six words on both screens, so nobody on the
network can slip in between.

1. Put the PC and the phone on the same Wi-Fi.
2. On the PC:

   ```sh
   bwphone pair
   ```

   It prints the address it listens on and a QR code:

   ```text
   Scan this on the phone within 120s. Listening on 192.168.1.23:40127; hellos will arrive on port 8732.

   ██▀▀▀▀▀██ ▄▀ ▀▄ ██▀▀▀▀▀██
   ...
   ```

3. On the phone, open BW Phone, tap **Pair with PC** and scan the code.
   Allow the camera the first time.
4. Both screens show six words:

   ```text
   Phone: SM-M315F (192.168.1.42)

       orbit  velvet  canyon  timber  lunar  harvest

   Do these six words match the phone's screen? [y/N]
   ```

   Compare them, in order. If they match, answer `y` on the PC and tap
   **They match** on the phone. If they don't, answer `n`, tap **They don't
   match**, and run `bwphone pair` again — don't retry the same one.
5. The PC prints `Paired with SM-M315F. Next: enrol an account.` and
   restarts `bwphone` and `bwphone-hello` itself. The phone's Home now says
   **Listening on Wi-Fi**.

Check it:

```sh
bwphone status        # "paired": true, and the phone's address under "phone"
```

The QR code is a one-time secret while it is on screen; don't leave it up
longer than needed, and don't share a screenshot of it.

Pairing again (a new phone, a reset app): tap **Revoke all** on the old phone
if you still have it, then `bwphone pair --replace`. Replacing a pairing
removes every enrolled account on the PC, since their vault files can't
open with the new phone; enrol them again.

## Enrol an account

Enrolment puts one Bitwarden account's key in reach of the phone. The phone
creates a new key for it, you compare that key's fingerprint on both screens,
the PC wraps your vault key to it, and a test unlock proves the whole path
works before anything is thrown away.

You need the Bitwarden CLI for this step only. Install it (`pacman -S
bitwarden-cli`, `npm install -g @bitwarden/cli`, or your distribution's
package). For a self-hosted server, run `bw config server https://…` first.

1. Keep the CLI's files in RAM, never on disk, for the whole step:

   ```sh
   # bash / zsh
   export BITWARDENCLI_APPDATA_DIR=$(mktemp -d -p /dev/shm bwcli.XXXXXX)
   ```
   ```fish
   # fish
   set -x BITWARDENCLI_APPDATA_DIR (mktemp -d -p /dev/shm bwcli.XXXXXX)
   ```

2. Log in once (email, master password, two-step login):

   ```sh
   bw login
   ```

3. On the phone, open BW Phone and keep it on screen, unlocked. You can tap
   **Enrol an account** first, but you don't have to: the PC's request
   opens the Enrol screen by itself while the app is in front.

4. On the PC, choose a name for the account and run:

   ```sh
   bw unlock --raw | bwphone enroll --label Work --from-stdin
   ```

   `bw` asks for your master password. Its session key goes straight through
   the pipe into `bwphone`, so it never lands in your shell history, an
   environment variable or another process's command line.

5. Compare the key fingerprint. The PC prints

   ```text
   The phone created a key for "Work":

       3f9a 7c21 e0b4 91d6 58c3

   Does this fingerprint match the phone's screen? [y/N]
   ```

   and the phone's Enrol screen shows the same groups under **Compare
   fingerprint**. Answer `y` only if they match.

6. Run the self-test. The PC prints

   ```text
   Self-test: pick  🍩  on the phone, then your fingerprint.
   ```

   and the phone opens the pick screen. Tap that emoji, then touch the
   fingerprint sensor.

7. Done. The PC prints the account and a fingerprint of your user key —
   record it; `bwphone unlock --label Work` prints the same one later:

   ```text
   Enrolled Work for Bitwarden account 0b1c…
   User key fingerprint (record this): 9d4e…
   ```

   The phone shows **Work is enrolled** and lists it on Home.

8. Clean up the CLI, so nothing of the session is left behind:

   ```sh
   bw logout
   rm -rf "$BITWARDENCLI_APPDATA_DIR"
   unset BITWARDENCLI_APPDATA_DIR        # fish: set -e BITWARDENCLI_APPDATA_DIR
   ```

9. Once, after the first enrolment, point the browsers at bwphone:

   ```sh
   bwphone manifests write
   ```

   Then, in each browser's Bitwarden extension: **Settings → Account
   security → Unlock with biometrics**. Restart the browser if the option
   doesn't take.

About names and timing:

- The name is the `--label` you pass, and it is final. The phone shows it and
  can't change it, so the PC, the phone and every prompt agree.
- The phone refuses a name it already has (ignoring case); `bwphone enroll`
  then says `the phone already has an account named "Work"`.
- Opening the Enrol screen gives the PC three minutes to start. Back
  leaves the screen without stopping anything; **Cancel enrolment** stops it
  and removes whatever it made on the phone.
- The phone refuses to start an enrolment while it is locked or while an
  unlock request is waiting on it.

More accounts: repeat steps 1–8 with a fresh CLI directory and a different
`--label`, then enable biometric unlock in that account's browser or profile.
Each account has its own key on the phone and costs its own fingerprint.

## Unlocking, day to day

1. In the Bitwarden extension, choose **Unlock with biometrics**.
2. The PC shows a notification, `Unlock Work · 🍩`, with a **Use password**
   action, and the tray icon turns into 🍩 (hover it for the account).
3. The phone shows a notification (or, if BW Phone is on screen, the pick
   screen straight away). Tap it; it opens over the lock screen.
4. Tap the emoji the PC shows, then touch the fingerprint sensor. The
   vault opens.

If the phone asks and you didn't, tap **None of these**. The PC then
warns that someone else asked, and the attempt shows in the phone's Recent
activity. A request you ignore expires after 45 seconds.

Only a fingerprint works; the phone's PIN can never release the vault key.
After five failed reads Android locks the sensor for 30 seconds. Whenever the
phone path doesn't work — asleep without the battery exemption, another
network, fingerprints locked — the extension falls back to your master
password, as it does today.

The PC can show the emoji in the system tray as well as (or instead of)
the notification; see [Settings](#settings).

To test the whole path without a browser:

```sh
bwphone unlock --label Work     # pick and fingerprint on the phone; prints the user key's fingerprint, never the key
```

## Settings

The daemon reads `~/.config/bwphone/config.toml` when it starts. Every key is
optional; without the file you get the defaults below.

```toml
[indicator]
# The desktop notification with the emoji and a Use password action.
notification = true
# An icon in the system tray (next to Wi-Fi and battery). During an unlock it
# turns into the emoji to pick, and its tooltip says which account and which
# emoji; the rest of the time it's a keyhole.
tray = true
# Between unlocks: "shown" keeps the keyhole in the panel, "hidden" tucks it
# into the tray's overflow (the ^) until a request brings it out.
tray_idle = "shown"
```

For example, to see only the tray icon and no notification:

```sh
mkdir -p ~/.config/bwphone
printf '[indicator]\nnotification = false\ntray = true\n' > ~/.config/bwphone/config.toml
systemctl --user restart bwphone
```

After any change, restart the daemon: `systemctl --user restart bwphone`. A
file with a typo or an unknown key is ignored as a whole (the daemon logs why
in `~/.local/state/bwphone/log` and uses the defaults). Warnings, such as
"someone else asked your phone to unlock", always come as notifications.

The tray icon works in Plasma's panel, and in GNOME with the AppIndicator
extension. Plasma's own per-icon setting (Configure System Tray → Entries)
overrides `tray_idle` if you set one there.

## Managing accounts and the pairing

| Task | PC | Phone |
|---|---|---|
| See the state | `bwphone status` | Home |
| List accounts | `bwphone account list` | Home → Accounts |
| Remove one account | `bwphone account remove Work` | Home → **Revoke an account** → Work |
| Remove everything and unpair | `bwphone pair --replace` when pairing again | Home → **Revoke all** |
| Browser manifests | `bwphone manifests check`, `bwphone manifests write` | — |

**Revoke** on the phone destroys that account's key in the phone's secure
hardware: every copy of its vault file becomes unopenable at once, backups
included, and it works with no PC around. Do it first if the PC is
lost or stolen. It does not take back a key someone already extracted; only
rotating your Bitwarden account key (in the web vault) does that.

Adding a fingerprint to the phone, or removing its screen lock, destroys
every account's key by design. Home then marks the accounts **Key
invalidated**: revoke them and enrol again.

## Troubleshooting

| Symptom | Likely cause and fix |
|---|---|
| The extension shows the password box straight away | The phone wasn't reachable within 5 s: asleep without the battery exemption, on another network, or the Wi-Fi isolates devices. Wake the phone and try again. |
| It fails on a network you just joined | If the PC joined after the phone, the phone hasn't told it where it is yet. Unlock the phone's screen once: it looks the PC up and announces itself. |
| `bwphone pair` times out | Both on the same Wi-Fi? A PC firewall blocking the pairing port? Pass `--ip` if the PC has several addresses. |
| `the phone refused to start an enrolment` | Unlock the phone and open BW Phone (or its Enrol screen); make sure no unlock request is waiting on it. |
| `the phone already has an account named …` | Revoke that account on the phone, or use another `--label`. |
| An account is listed as `retired vault.blob 0x03` | It was enrolled with an older format that phones below Android 14 can't open. `bwphone account remove <name>`, revoke it on the phone, enrol again. |
| `a browser manifest no longer points at bwphone-proxy` | The real Bitwarden desktop app (or an update) overwrote them. `bwphone manifests write`. |
| Hellos refused as stale | `bwphone hello-reset`. |
| Nothing works after the phone rebooted | Unlock the phone once: its keys are unavailable until the first unlock after a boot. |

Logs: `~/.local/state/bwphone/log` on the PC; `adb logcat -s
bwphone.session bwphone.service` on the phone.

## Build from source

```sh
./install.sh                                  # PC side, release build; PREFIX=/usr sudo ./install.sh for /usr/bin
./crates/bwphone-android/gen-kotlin.sh        # Kotlin binding
# phone side: see crates/bwphone-android/README.md and android/README.md
```

Tests: `cargo test --workspace` (the end-to-end ones run against
`bwphone-fakephone`, a phone with no Android in it).

## Layout

| Crate | Role |
|---|---|
| `bwphone-transport` | Noise KK / NKpsk0, framing, messages, emoji, pairing words, hello, mDNS name — shared by both devices |
| `bwphone-wrap` | `vault.blob` 0x04: an RSA-OAEP-wrapped `K_wrap` over an AES-GCM-sealed user key |
| `bwphone-nm` | The extension's native-messaging protocol |
| `bwphone` | The daemon and CLI: sockets, wallet, notifications, the two-phase unlock, pairing, enrolment |
| `bwphone-proxy` | Stdio ↔ socket relay the browsers spawn |
| `bwphone-hello` | Receives the phone's encrypted address; answers its rotating mDNS name |
| `bwphone-android` | The transport crate for Kotlin, through uniffi |
| `bwphone-fakephone` | A phone with no Android in it, for the tests |
| `android/` | BW Phone, the Kotlin app |

The full design — protocols, formats, what each side stores and enforces, the
threat model — is in [SPECIFICATION.md](SPECIFICATION.md).

## License

MIT; see [LICENSE](LICENSE). Two bundled fonts keep their own licence, the
SIL Open Font License 1.1: the emoji icons in the PC's tray are rendered
from Noto Color Emoji ([crates/bwphone/assets/emoji/LICENSE](crates/bwphone/assets/emoji/LICENSE)),
and BW Phone bundles Roboto Flex ([android/licenses/RobotoFlex-OFL.txt](android/licenses/RobotoFlex-OFL.txt)).
