#!/bin/sh
# Generate the Kotlin side of the uniffi binding into out/kotlin/, from the
# metadata embedded in a host build of the library. No NDK needed for this
# step; the .so for the phone is built separately (see README.md).
set -eu
cd "$(dirname "$0")/../.."
cargo build -p bwphone-android
cargo run -q -p bwphone-bindgen -- generate \
  --library target/debug/libbwphone_android.so \
  --language kotlin \
  --out-dir crates/bwphone-android/out/kotlin
echo "Kotlin written to crates/bwphone-android/out/kotlin/"
