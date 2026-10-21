use std::path::{Path, PathBuf};
use std::process::ExitCode;

use anyhow::{bail, Result};
use dialoguer::Confirm;
use ed25519_dalek::VerifyingKey;

use crate::apps::str_list;
use crate::archive::format::{self, Manifest, SignedSections};
use crate::archive::restore::{self, Options, Plan, Report, Staging, State};
use crate::discovery::human_size;
use crate::keys::{self, KeyPaths};
use crate::os_detect::{self, OsInfo};

const EXIT_FAILED: u8 = 1;
const EXIT_INTEGRITY: u8 = 2;

enum Stop {
    Refused(u8),
    Error(anyhow::Error),
}

impl From<anyhow::Error> for Stop {
    fn from(e: anyhow::Error) -> Self {
        Stop::Error(e)
    }
}

fn refuse<T>(code: u8, msg: impl std::fmt::Display) -> Result<T, Stop> {
    println!("REFUSED: {msg}");
    Err(Stop::Refused(code))
}

// Exit codes: 0 = everything restored, 1 = refused / could not run / some steps failed, 2 = integrity verification failed (never overridable).
pub fn run(
    path: &Path,
    force: bool,
    target_root: Option<PathBuf>,
    skip_packages: bool,
    pubkey: Option<&str>,
) -> Result<ExitCode> {
    let opts = Options {
        target_root,
        skip_packages,
    };
    match restore_file(path, force, &opts, pubkey) {
        Ok(code) => Ok(code),
        Err(Stop::Refused(code)) => Ok(ExitCode::from(code)),
        Err(Stop::Error(e)) => Err(e),
    }
}

fn restore_file(
    path: &Path,
    force: bool,
    opts: &Options,
    pubkey: Option<&str>,
) -> Result<ExitCode, Stop> {
    let here = os_detect::detect()?;

    println!("[pre-flight]");
    let sections = match format::read_signed_sections(path) {
        Ok(s) => s,
        Err(e) => return refuse(EXIT_INTEGRITY, format!("{e:#}")),
    };
    check_compat(&sections, &here, force)?;

    let key = super::verify::resolve_pubkey(pubkey)?;
    if pubkey.is_some() {
        confirm_foreign_key(&key)?;
    }
    let sections = verify_integrity(path, &key)?;
    let manifest: Manifest =
        serde_json::from_slice(&sections.manifest).map_err(anyhow::Error::from)?;

    let identity = match keys::load_identity(&KeyPaths::new()?) {
        Ok(i) => i,
        Err(e) => return refuse(EXIT_FAILED, format!("{e:#}")),
    };
    let staging = Staging::create()?;
    let members = match restore::extract(path, sections.payload_offset, &identity, &staging.dir) {
        Ok(m) => m,
        Err(e) => return refuse(EXIT_FAILED, format!("{e:#}")),
    };
    println!(
        "  decrypted {} payload files to a private staging dir",
        members.len()
    );
    let plan = restore::build_plan(manifest, members, opts);

    print_plan(&plan, opts);
    if !Confirm::new()
        .with_prompt("Apply this restore?")
        .default(false)
        .interact()
        .map_err(anyhow::Error::from)?
    {
        println!("Aborted; nothing was written.");
        return Ok(ExitCode::from(EXIT_FAILED));
    }

    let report = restore::apply(&plan, &here.package_manager, opts);
    print_report(&report);
    Ok(if report.failed.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(EXIT_FAILED)
    })
}

fn check_compat(sections: &SignedSections, here: &OsInfo, force: bool) -> Result<(), Stop> {
    let backup = &sections.header.os;
    println!(
        "  backup  : {} {} ({}) {} [{}], created {}",
        backup.os_id,
        backup.os_version,
        backup.os_family,
        backup.kernel_arch,
        backup.package_manager,
        sections.header.created_at
    );
    println!(
        "  machine : {} {} ({}) {} [{}]",
        here.os_id, here.os_version, here.os_family, here.kernel_arch, here.package_manager
    );
    match restore::check_compat(backup, here, force) {
        Ok(warnings) => {
            for w in warnings {
                println!("  WARNING: {w}");
            }
            Ok(())
        }
        Err(e) => refuse(EXIT_FAILED, format!("{e:#}")),
    }
}

/// `--pubkey` trusts a key that isn't the user's own, so everything restored is only as trustworthy as that key's owner.
fn confirm_foreign_key(key: &VerifyingKey) -> Result<()> {
    let is_default = keys::load_signing_key(&KeyPaths::new()?)
        .is_ok_and(|signing| signing.verifying_key() == *key);
    if is_default {
        return Ok(());
    }
    println!();
    println!("  ⚠⚠⚠  --pubkey does not match your own signing key.");
    println!("       signer: {}", keys::to_hex(key.as_bytes()));
    println!("       Everything this restore writes or installs is only as trustworthy");
    println!("       as whoever controls that key. If this wasn't deliberate, stop now.");
    println!();
    let proceed = Confirm::new()
        .with_prompt("Continue restoring with this non-default public key?")
        .default(false)
        .interact()?;
    if !proceed {
        bail!("aborted: --pubkey does not match the local default signing key");
    }
    Ok(())
}

/// Integrity failures are final: --force deliberately has no effect here.
fn verify_integrity(path: &Path, key: &VerifyingKey) -> Result<SignedSections, Stop> {
    let (sections, outcome) = format::verify(path, key)?;
    let Some(why) = super::verify::failure_reason(&outcome) else {
        println!("  integrity: signature valid, payload hash matches");
        return Ok(sections);
    };
    println!("REFUSED: integrity check failed: {why}");
    println!("         This cannot be overridden with --force.");
    Err(Stop::Refused(EXIT_INTEGRITY))
}

fn print_plan(plan: &Plan, opts: &Options) {
    println!("\n[restore plan]");
    if let Some(r) = &opts.target_root {
        println!(
            "  target root : {} (all paths are remapped under it)",
            r.display()
        );
    }
    let skipped = if opts.skip_packages || opts.target_root.is_some() {
        " (will be SKIPPED)"
    } else {
        ""
    };
    println!(
        "  packages    : {} to install{skipped}",
        plan.packages.len()
    );
    let count = |cat: &str| plan.files.iter().filter(|f| f.category == cat).count();
    println!("  dotfiles    : {} file(s) to write", count("dotfile"));
    println!("  env files   : {} file(s) to write", count("env"));
    println!(
        "  compose     : {} file(s) to write (not started)",
        count("compose")
    );
    println!("  repos       : {} to clone/restore", plan.repos.len());
    print_software(plan);
    print_personal(plan);

    for f in plan
        .files
        .iter()
        .filter(|f| f.category != "personal" && f.state != State::New)
    {
        let (tag, note) = match f.state {
            State::Differs => (
                "REPLACE",
                " (existing file will be saved as .husk-backup-<timestamp>)",
            ),
            _ => ("same   ", ""),
        };
        println!("    {tag} {}{note}", f.target.display());
    }
    for r in &plan.repos {
        let how = if r.exists {
            "exists, restore in place".to_string()
        } else if let Some(u) = &r.record.remote_url {
            format!("clone {u}")
        } else {
            "local-only repo: CANNOT be cloned".to_string()
        };
        println!(
            "    repo {}  [{}]  {} untracked, {} binary, patch: {}  -- {how}",
            r.target.display(),
            r.record.branch,
            r.untracked.len(),
            r.binary.len(),
            if r.patch.is_some() { "yes" } else { "no" }
        );
    }
    for w in &plan.warnings {
        println!("  WARNING: {w}");
    }
}

fn print_software(plan: &Plan) {
    if plan.software.is_empty() {
        return;
    }
    println!("  software    : {} app(s)", plan.software.len());
    for s in &plan.software {
        let detail = if s.record.app == "vscode" {
            format!(
                "{} extension(s), {} file(s)",
                str_list(&s.record.data, "extensions").len(),
                s.record.files.len()
            )
        } else {
            format!(
                "{} file(s)",
                s.record.files.len() + s.record.generated.len()
            )
        };
        println!("    {}  ({detail})", s.record.app);
    }
}

fn print_personal(plan: &Plan) {
    let personal: Vec<_> = plan
        .files
        .iter()
        .filter(|f| f.category == "personal")
        .collect();
    if personal.is_empty() {
        return;
    }
    let total: u64 = personal.iter().map(|f| f.size).sum();
    let differ = personal
        .iter()
        .filter(|f| f.state == State::Differs)
        .count();
    let same = personal
        .iter()
        .filter(|f| f.state == State::Identical)
        .count();
    println!();
    println!("  PERSONAL FILES (whole-file copies)");
    println!("    {} file(s), {}", personal.len(), human_size(total));
    println!(
        "    {} new, {same} already identical, {differ} would REPLACE an existing different file",
        personal.len() - differ - same
    );
    if differ > 0 {
        println!("    (replaced files are first saved as <path>.husk-backup-<timestamp>)");
    }
    println!(
        "    staged decrypted copy needs ~{} free in {} (set TMPDIR to use another disk)",
        human_size(total),
        std::env::temp_dir().display()
    );
    println!();
}

fn print_report(report: &Report) {
    println!("\n==== restore report ====");
    println!("succeeded : {}", report.ok.len());
    println!("failed    : {}", report.failed.len());
    for f in &report.failed {
        println!("  - {f}");
    }
    if !report.manual.is_empty() {
        println!("needs manual follow-up:");
        for m in &report.manual {
            println!("  - {m}");
        }
    }
    if !report.compose_commands.is_empty() {
        println!("docker compose files restored but NOT started (husk never auto-starts containers). To start:");
        for c in &report.compose_commands {
            println!("  {c}");
        }
    }
}
