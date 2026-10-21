use std::path::Path;
use std::process::ExitCode;

use anyhow::Result;
use ed25519_dalek::VerifyingKey;

use crate::archive::format::{self, Verification};
use crate::keys::{self, KeyPaths};

/// Exit codes: 0 verified, 2 verification failed, 1 could not run.
pub fn run(path: &Path, pubkey: Option<&str>) -> Result<ExitCode> {
    let key = resolve_pubkey(pubkey)?;

    let (parsed, outcome) = match format::verify(path, &key) {
        Ok(v) => v,
        Err(e) => {
            println!("FAIL: {e:#}");
            return Ok(ExitCode::from(2));
        }
    };

    let os = &parsed.header.os;
    println!("file       : {}", path.display());
    println!("created    : {}", parsed.header.created_at);
    println!(
        "os         : {} {} ({}, {})",
        os.os_id, os.os_version, os.os_family, os.kernel_arch
    );
    println!("pkg manager: {}", os.package_manager);
    println!("signer     : {}", keys::to_hex(key.as_bytes()));

    match failure_reason(&outcome) {
        None => {
            println!("PASS: signature valid, payload hash matches");
            Ok(ExitCode::SUCCESS)
        }
        Some(why) => {
            println!("FAIL: {why}");
            Ok(ExitCode::from(2))
        }
    }
}

/// Why verification failed, or `None` if it passed.
pub fn failure_reason(outcome: &Verification) -> Option<&'static str> {
    match outcome {
        Verification::Pass => None,
        Verification::SignatureInvalid => {
            Some("signature mismatch (tampered, or wrong public key)")
        }
        Verification::PayloadHashMismatch => Some("payload hash mismatch (tampered or corrupted)"),
        Verification::ManifestMalformed => Some("signed manifest is malformed"),
    }
}

/// `--pubkey` is a hex string or a file containing one; default is our own signing key.
pub fn resolve_pubkey(arg: Option<&str>) -> Result<VerifyingKey> {
    match arg {
        Some(v) => {
            keys::parse_verifying_key(&std::fs::read_to_string(v).unwrap_or_else(|_| v.to_string()))
        }
        None => Ok(keys::load_signing_key(&KeyPaths::new()?)?.verifying_key()),
    }
}
