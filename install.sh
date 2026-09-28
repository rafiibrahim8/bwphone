#!/bin/sh
# Build the PC side in release mode and install it.
#
#   ./install.sh                  per-user: ~/.local/bin, ~/.config/systemd/user, enabled for you
#   PREFIX=/usr sudo ./install.sh system-wide binaries in /usr/bin, units in /usr/lib/systemd/user;
#                                 the daemon still runs per user: each user then runs
#                                 `systemctl --user enable --now bwphone bwphone-hello`
#
# Everything stateful (wallet items, ~/.local/share/bwphone, the sockets) is
# per user wherever the binaries live.
set -eu
cd "$(dirname "$0")"

cargo build --release -p bwphone -p bwphone-proxy -p bwphone-hello
exec sh dist/install-prebuilt.sh --from target/release
