//! Verifies an updater package as the app's updater does before installing it: its minisign
//! signature against a public key, with `minisign-verify`, the crate the updater plugin uses.
//! The release workflow runs it on the package it built, so a signing key that does not match
//! the public key in `tauri.conf.json` fails the release, not every user's update.
//!
//! Usage: `verify_update <package> <signature> <public key>`, where the signature and the key
//! are the minisign files Tauri wraps in base64 (the `.sig` file, and `plugins.updater.pubkey`)
//! after decoding. Prints the signature's trusted comment, which names the signed version.

use std::env;
use std::error::Error;
use std::fs;

use minisign_verify::PublicKey;
use minisign_verify::Signature;

#[expect(
    clippy::print_stdout,
    reason = "a command-line check: its output is the trusted comment"
)]
fn main() -> Result<(), Box<dyn Error>> {
    let args: Vec<String> = env::args().collect();
    let [_, package, signature, key] = &args[..] else {
        return Err("usage: verify_update <package> <signature> <public key>".into());
    };
    let bytes = fs::read(package).map_err(|e| format!("cannot read {package}: {e}"))?;
    let signature = Signature::from_file(signature)
        .map_err(|e| format!("cannot read the signature {signature}: {e}"))?;
    let key = PublicKey::from_file(key).map_err(|e| format!("cannot read the key {key}: {e}"))?;
    // `true` allows minisign's legacy, not prehashed, form, as the updater does.
    key.verify(&bytes, &signature, true)
        .map_err(|e| format!("{package} does not verify with this key: {e}"))?;
    println!("{}", signature.trusted_comment());
    Ok(())
}
