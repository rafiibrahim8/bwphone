//! `cargo run -p bwphone-bindgen -- generate --library <libbwphone_android.so> --language kotlin --out-dir <dir>`
//! See `crates/bwphone-android/gen-kotlin.sh`.
fn main() {
    uniffi::uniffi_bindgen_main()
}
