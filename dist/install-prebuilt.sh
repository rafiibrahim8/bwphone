#!/bin/sh
# Installs the three PC binaries and the two user units.
#
#   ./install.sh                  per-user: ~/.local/{bin,lib/bwphone} and ~/.config/systemd/user, enabled now
#   PREFIX=/usr sudo ./install.sh system-wide: /usr/bin, /usr/lib/bwphone and /usr/lib/systemd/user;
#                                 each user then runs `systemctl --user enable --now bwphone bwphone-hello`
#
# Only `bwphone` (the command) goes on PATH. bwphone-proxy (spawned by the
# browsers) and bwphone-hello (a service) are not commands; they live in the
# package's private lib directory, which the units and manifests point at.
#
# The daemon is always a per-user process: it needs that user's session bus
# (wallet, notifications) and keeps that user's state under $HOME and
# $XDG_RUNTIME_DIR. Installing system-wide only changes where the code lives.
#
# --from DIR: where the binaries are (default: this directory, the tarball layout).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
from="$here"
if [ "${1:-}" = "--from" ]; then from="$(cd "$2" && pwd)"; fi
# Next to this script: the tarball's systemd/, or dist/systemd/ in the source tree.
units="$here/systemd"

for b in bwphone bwphone-proxy bwphone-hello; do
  [ -x "$from/$b" ] || { echo "missing $from/$b" >&2; exit 1; }
done

if [ -n "${PREFIX:-}" ]; then
  bindir="$PREFIX/bin"
  libdir="$PREFIX/lib/bwphone"
  unitdir="$PREFIX/lib/systemd/user"
  mandir="$PREFIX/share/man/man1"
  bashdir="$PREFIX/share/bash-completion/completions"
  zshdir="$PREFIX/share/zsh/site-functions"
  fishdir="$PREFIX/share/fish/vendor_completions.d"
  system=1
else
  bindir="$HOME/.local/bin"
  libdir="$HOME/.local/lib/bwphone"
  unitdir="$HOME/.config/systemd/user"
  mandir="$HOME/.local/share/man/man1"
  bashdir="$HOME/.local/share/bash-completion/completions"
  zshdir="$HOME/.local/share/zsh/site-functions"
  fishdir="$HOME/.config/fish/completions"
  system=0
fi

mkdir -p "$bindir" "$libdir" "$unitdir"
# The daemon's directories, so the unit's ReadWritePaths resolve on first start.
[ "$system" = 1 ] || mkdir -p "$HOME/.local/share/bwphone" "$HOME/.local/state/bwphone"
install -m 0755 "$from/bwphone" "$bindir/"
install -m 0755 "$from/bwphone-proxy" "$from/bwphone-hello" "$libdir/"
# Leftovers from an older layout that put the helpers on PATH.
rm -f "$bindir/bwphone-proxy" "$bindir/bwphone-hello"
# The unit templates use the per-user paths; rewrite them for this layout.
for u in bwphone bwphone-hello; do
  sed -e "s|%h/.local/bin/|$bindir/|" -e "s|%h/.local/lib/bwphone/|$libdir/|" "$units/$u.service" > "$unitdir/$u.service"
  chmod 0644 "$unitdir/$u.service"
done

mkdir -p "$mandir" "$bashdir" "$zshdir" "$fishdir"
"$bindir/bwphone" manpages "$mandir"
"$bindir/bwphone" completions bash > "$bashdir/bwphone"
"$bindir/bwphone" completions zsh  > "$zshdir/_bwphone"
"$bindir/bwphone" completions fish > "$fishdir/bwphone.fish"

if [ "$system" = 1 ]; then
  cat <<EOF
Installed to $bindir; units in $unitdir.
Each user who wants it:
  systemctl --user daemon-reload
  systemctl --user enable --now bwphone bwphone-hello
Then, as that user:
  bwphone pair                              # QR on this screen, scan it with BW Phone
  bw unlock --raw | bwphone enroll --label Work --from-stdin
                                            # BITWARDENCLI_APPDATA_DIR on /dev/shm, \`bw login\` done
  bwphone manifests write                   # manifests point at $libdir/bwphone-proxy
EOF
else
  systemctl --user daemon-reload
  systemctl --user enable bwphone bwphone-hello
  cat <<EOF
Installed to $bindir; units enabled for $USER. Next:
  bwphone pair                              # QR on this screen, scan it with BW Phone
  bw unlock --raw | bwphone enroll --label Work --from-stdin
                                            # BITWARDENCLI_APPDATA_DIR on /dev/shm, \`bw login\` done
  bwphone manifests write                   # manifests point at $libdir/bwphone-proxy
  systemd-analyze --user security bwphone
Man pages: $mandir (add it to MANPATH if 'man bwphone' does not find them).
Completions: fish active now; bash via bash-completion; zsh after fpath+=$zshdir.
EOF
fi
