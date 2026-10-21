use std::env;
use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{bail, Context, Result};
use dialoguer::{Confirm, Input, MultiSelect};

use crate::archive::format::{self, Selection};
use crate::config::{self, Categories, Config, Resolved, CATEGORY_NAMES};
use crate::discovery::{self, human_size, AssetCatalog, DiscoveryOptions};
use crate::keys::{self, KeyPaths};
use crate::os_detect::{self, OsInfo};
use crate::personal::{self, FolderScan};

const WARN: &str = "[warn]";

pub struct Args {
    pub interactive: bool,
    pub configure: bool,
    pub output: Option<PathBuf>,
}

pub fn home_dir() -> Result<PathBuf> {
    Ok(PathBuf::from(
        env::var_os("HOME").context("$HOME is not set")?,
    ))
}

struct PersonalPlan {
    scans: Vec<FolderScan>,
    totals: personal::Capped,
    include: bool,
    error: Option<String>,
}

pub fn run(args: Args) -> Result<()> {
    let os = os_detect::detect()?;
    let key_paths = KeyPaths::new()?;
    let signing_key = keys::load_signing_key(&key_paths)?;
    let recipient = keys::load_recipient(&key_paths)?;
    let home = home_dir()?;

    if args.configure {
        super::configure::run()?;
    }

    let loaded = Config::load()?;
    let first_run = loaded.is_none();
    let interactive = args.interactive || first_run;
    let cfg = loaded.unwrap_or_default();
    let resolved = cfg.resolve(&home)?;
    check_can_prompt(&cfg, interactive, first_run)?;

    let catalog = discover(&resolved, &cfg, &os, &home, interactive)?;
    print_summary(&catalog, cfg.behavior.warn_on_duplicate_clones);
    print_software(&catalog.software, &cfg);

    let mut personal = plan_personal(&cfg, &resolved);
    let chosen = choose_categories(&catalog, &cfg, interactive, first_run)?;

    let software = if chosen[5] {
        capture_software(&catalog.software, &cfg)
    } else {
        Vec::new()
    };
    let mut selection = Selection {
        packages: if chosen[0] {
            catalog.packages.packages
        } else {
            Vec::new()
        },
        dotfiles: if chosen[1] {
            catalog.dotfiles
        } else {
            Vec::new()
        },
        repos: if chosen[2] {
            catalog.git_repos
        } else {
            Vec::new()
        },
        compose_files: if chosen[3] {
            catalog.docker_compose
        } else {
            Vec::new()
        },
        env_files: if chosen[4] {
            catalog.env_files
        } else {
            Vec::new()
        },
        excludes: resolved.excludes.clone(),
        personal: Vec::new(),
        software,
    };

    // With auto_confirm the user already accepted whole-file copies in `husk configure`.
    if personal.include && !cfg.behavior.auto_confirm {
        personal.include = confirm_personal(&personal.totals)?;
    }
    if personal.include {
        selection.personal =
            personal::select_files(&personal.scans, cfg.personal_files.max_file_bytes);
    }

    // `managed`: a timestamped file under output.default_path; only those are ever pruned.
    let (out_path, managed) = pick_output(args.output.as_deref(), first_run, &resolved, &home)?;
    confirm_write(&out_path, &cfg, interactive)?;
    config::ensure_parent(&out_path)?;

    let report = format::write(&out_path, &os, &selection, &signing_key, &recipient)?;
    print_report(&out_path, &report);

    if managed && cfg.output.keep_last_n > 0 {
        prune_old(&resolved, cfg.output.keep_last_n);
    }
    if personal.include {
        eprintln!(
            "  personal files: {} files, {} (whole-file copies)",
            selection.personal.len(),
            human_size(selection.personal.iter().map(|p| p.size_bytes).sum())
        );
    }
    if first_run {
        offer_save_config(chosen)?;
    }

    // The backup is written and valid; still exit non-zero so cron notices.
    match personal.error {
        Some(msg) => bail!("{msg}"),
        None => Ok(()),
    }
}

fn check_can_prompt(cfg: &Config, interactive: bool, first_run: bool) -> Result<()> {
    let tty = std::io::stdin().is_terminal();
    if interactive && !tty {
        bail!(
            "interactive mode needs a terminal. {}",
            if first_run {
                "No config exists yet: run `husk configure` in a terminal once to create one."
            } else {
                "Drop --interactive to use the saved config."
            }
        );
    }
    if !interactive && !cfg.behavior.auto_confirm && !tty {
        bail!(
            "stdin is not a terminal and behavior.auto_confirm is false, so there is nobody to \
             confirm the backup. Set `auto_confirm = true` in {} for unattended runs.",
            config::config_path()?.display()
        );
    }
    Ok(())
}

fn plan_personal(cfg: &Config, resolved: &Resolved) -> PersonalPlan {
    let cap = cfg.personal_files.max_file_bytes;
    let ceiling = cfg.personal_files.max_total_bytes;
    let mut scans = Vec::new();
    if cfg.personal_files.enabled {
        eprintln!("Measuring personal files (full directory walk) ...");
        for folder in &resolved.personal_folders {
            if folder.is_dir() {
                scans.push(personal::scan_folder(folder, &resolved.personal_excludes));
            } else {
                eprintln!(
                    "{WARN} personal folder {} does not exist; skipped",
                    folder.display()
                );
            }
        }
        print_personal(&scans, cap, ceiling);
    }

    let totals = personal::sum_capped(&scans, cap);
    let mut include = !scans.is_empty();
    let mut error = None;
    if include && ceiling > 0 && totals.bytes > ceiling {
        include = false;
        let msg = format!(
            "personal files are {} but personal_files.max_total_bytes is {}; they were NOT \
             backed up this run. Re-run `husk configure` to review and raise the ceiling.",
            human_size(totals.bytes),
            human_size(ceiling)
        );
        eprintln!("{WARN} {msg}");
        error = Some(msg);
    }
    PersonalPlan {
        scans,
        totals,
        include,
        error,
    }
}

fn choose_categories(
    catalog: &AssetCatalog,
    cfg: &Config,
    interactive: bool,
    first_run: bool,
) -> Result<[bool; 6]> {
    let saved = cfg.categories.to_array();
    if interactive {
        return select_categories(catalog, if first_run { [true; 6] } else { saved });
    }
    let names: Vec<&str> = CATEGORY_NAMES
        .iter()
        .zip(saved)
        .filter(|(_, on)| *on)
        .map(|(n, _)| *n)
        .collect();
    eprintln!("Using saved config; categories: {}", names.join(", "));
    Ok(saved)
}

fn confirm_personal(totals: &personal::Capped) -> Result<bool> {
    eprintln!(
        "\n{WARN}{WARN}{WARN}  This backup will include {} of PERSONAL FILES ({} files).",
        human_size(totals.bytes),
        totals.files
    );
    let include = Confirm::new()
        .with_prompt("Include personal files in this backup? (No = back up everything else only)")
        .default(false)
        .interact()?;
    if !include {
        eprintln!("Personal files left out of this run.");
    }
    Ok(include)
}

/// Returns the output path and whether it is a managed (timestamped, prunable) file.
fn pick_output(
    explicit: Option<&Path>,
    first_run: bool,
    resolved: &Resolved,
    home: &Path,
) -> Result<(PathBuf, bool)> {
    if let Some(p) = explicit {
        return Ok((config::expand_tilde(&p.to_string_lossy(), home), false));
    }
    if first_run {
        let input: String = Input::new()
            .with_prompt("Output path")
            .default("./backup.husk".to_string())
            .interact_text()?;
        return Ok((config::expand_tilde(&input, home), false));
    }
    // Never overwrite an earlier backup: if this second is taken, use the next free one.
    let mut now = chrono::Local::now();
    let mut path = config::timestamped_path(&resolved.output_default, now);
    while path.exists() {
        now += chrono::Duration::seconds(1);
        path = config::timestamped_path(&resolved.output_default, now);
    }
    Ok((path, true))
}

fn confirm_write(out_path: &Path, cfg: &Config, interactive: bool) -> Result<()> {
    let unattended = cfg.behavior.auto_confirm && !interactive;
    if !interactive && !cfg.behavior.auto_confirm {
        let go = Confirm::new()
            .with_prompt(format!(
                "Create {} with the plan above?",
                out_path.display()
            ))
            .default(false)
            .interact()?;
        if !go {
            bail!("aborted; nothing was written");
        }
    }
    if !out_path.exists() {
        return Ok(());
    }
    if unattended {
        eprintln!("Overwriting existing {} (auto_confirm)", out_path.display());
        return Ok(());
    }
    let overwrite = Confirm::new()
        .with_prompt(format!("{} exists. Overwrite?", out_path.display()))
        .default(false)
        .interact()?;
    if !overwrite {
        bail!("not overwriting {}", out_path.display());
    }
    Ok(())
}

fn print_report(out_path: &Path, report: &format::WriteReport) {
    eprintln!("\n== Wrote {} ==", out_path.display());
    eprintln!("  total on disk : {}", human_size(report.total_bytes));
    eprintln!("  header        : {}", human_size(report.header_bytes));
    eprintln!("  manifest      : {}", human_size(report.manifest_bytes));
    eprintln!("  signature     : {}", human_size(report.signature_bytes));
    eprintln!(
        "  payload       : {} ({} tar members, {} uncompressed)",
        human_size(report.payload_bytes),
        report.members,
        human_size(report.uncompressed_bytes)
    );
    for w in &report.warnings {
        eprintln!("  {WARN} {w}");
    }
}

/// A prune failure only warns: the new backup is already safely written.
fn prune_old(resolved: &Resolved, keep: u32) {
    match config::prune(&resolved.output_default, keep) {
        Ok(removed) => {
            for p in removed {
                eprintln!("  pruned old backup {}", p.display());
            }
        }
        Err(e) => eprintln!("  {WARN} could not prune old backups: {e:#}"),
    }
}

fn offer_save_config(chosen: [bool; 6]) -> Result<()> {
    let save = Confirm::new()
        .with_prompt("Save these choices as your default config?")
        .default(true)
        .interact()?;
    if save {
        let cfg = Config {
            categories: Categories::from_array(chosen),
            ..Config::default()
        };
        let path = cfg.save()?;
        eprintln!("Saved {} (edit with `husk configure`)", path.display());
    }
    Ok(())
}

/// Scan dev roots plus configured extras; prompts for a root only when interactive.
pub fn discover(
    resolved: &Resolved,
    cfg: &Config,
    os: &OsInfo,
    home: &Path,
    interactive: bool,
) -> Result<AssetCatalog> {
    let mut roots = discovery::dev_roots(home);
    for extra in &resolved.extra_scan_roots {
        if extra.is_dir() {
            if !roots.contains(extra) {
                roots.push(extra.clone());
            }
        } else {
            eprintln!(
                "{WARN} extra_scan_roots entry {} is not a directory; skipped",
                extra.display()
            );
        }
    }
    if roots.is_empty() {
        if interactive {
            eprintln!(
                "None of the common dev directories exist under {}.",
                home.display()
            );
            let input: String = Input::new()
                .with_prompt("Path to scan for repos, compose files and .env files")
                .interact_text()?;
            let path = config::expand_tilde(&input, home);
            if !path.is_dir() {
                bail!("{} is not a directory", path.display());
            }
            roots.push(path);
        } else {
            eprintln!("{WARN} no dev directories found to scan (only $HOME depth 1 is checked)");
        }
    }

    eprintln!(
        "Scanning {} ...",
        roots
            .iter()
            .map(|r| r.display().to_string())
            .collect::<Vec<_>>()
            .join(", ")
    );
    let opts = DiscoveryOptions {
        exclude_repos: resolved.exclude_repos.clone(),
        excludes: resolved.excludes.clone(),
        extra_dotfiles: resolved.extra_dotfiles.clone(),
        skip_repos: !cfg.categories.git_repos && !interactive,
    };
    Ok(discovery::discover_assets(home, os, &roots, &opts))
}

pub fn select_categories(catalog: &AssetCatalog, defaults: [bool; 6]) -> Result<[bool; 6]> {
    let dirty = catalog
        .git_repos
        .iter()
        .filter(|r| r.has_uncommitted_changes)
        .count();
    let git_label = if dirty > 0 {
        format!("Git repos ({} {WARN} with uncommitted changes)", dirty)
    } else {
        "Git repos".to_string()
    };
    let labels = [
        format!("Packages ({} explicit)", catalog.packages.explicit_count),
        format!("Dotfiles ({})", catalog.dotfiles.len()),
        format!("{git_label} [{}]", catalog.git_repos.len()),
        format!("Docker compose files ({})", catalog.docker_compose.len()),
        format!("Env files ({})", catalog.env_files.len()),
        format!(
            "Software config ({} app(s): {})",
            catalog.software.len(),
            if catalog.software.is_empty() {
                "none found".to_string()
            } else {
                catalog
                    .software
                    .iter()
                    .map(|s| s.id.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        ),
    ];
    let chosen = MultiSelect::new()
        .with_prompt("Select categories to include (space to toggle, enter to confirm)")
        .items(&labels)
        .defaults(&defaults)
        .interact()?;
    Ok(to_flags(chosen))
}

pub fn to_flags(chosen: Vec<usize>) -> [bool; 6] {
    let mut flags = [false; 6];
    for i in chosen {
        flags[i] = true;
    }
    flags
}

pub fn print_software(found: &[crate::apps::SoftwareFound], cfg: &Config) {
    eprintln!("== SOFTWARE CONFIG ==");
    if found.is_empty() {
        eprintln!("  (no supported apps found)");
    }
    for f in found {
        let on = cfg.software_enabled(&f.id);
        eprintln!("  [{}] {:<15} {}", if on { "x" } else { " " }, f.id, f.name);
    }
    for k in cfg.unknown_software_keys() {
        eprintln!("  {WARN} [software] key {k:?} matches no known app handler (typo?)");
    }
    eprintln!();
}

/// Capture each enabled app; a failing handler is reported and skipped.
fn capture_software(
    found: &[crate::apps::SoftwareFound],
    cfg: &Config,
) -> Vec<crate::apps::AppConfigEntry> {
    let mut out = Vec::new();
    for f in found {
        if !cfg.software_enabled(&f.id) {
            eprintln!("  software {}: disabled in [software], skipped", f.id);
            continue;
        }
        let Some(handler) = crate::apps::find(&f.id) else {
            continue;
        };
        match handler.capture() {
            Ok(entry) => out.push(entry),
            Err(e) => eprintln!("  {WARN} software {}: capture failed: {e:#}", f.id),
        }
    }
    out
}

pub fn print_personal(scans: &[FolderScan], max_file_bytes: u64, ceiling: u64) {
    eprintln!("== PERSONAL FILES (opt-in, whole-file copy) ==");
    for s in scans {
        let c = s.capped(max_file_bytes);
        eprintln!(
            "  {}  {} files, {}{}",
            s.folder.display(),
            c.files,
            human_size(c.bytes),
            if c.skipped_files > 0 {
                format!(
                    "  ({} files / {} skipped by size cap)",
                    c.skipped_files,
                    human_size(c.skipped_bytes)
                )
            } else {
                String::new()
            }
        );
        if !s.repo_roots.is_empty() {
            eprintln!(
                "      {WARN} contains {} git repo(s) holding {} - also covered by the git category",
                s.repo_roots.len(),
                human_size(s.repo_bytes)
            );
        }
        if s.unreadable > 0 {
            eprintln!("      {WARN} {} entries could not be read", s.unreadable);
        }
    }
    let t = personal::sum_capped(scans, max_file_bytes);
    eprintln!(
        "  TOTAL personal files: {} files, {}",
        t.files,
        human_size(t.bytes)
    );
    if ceiling > 0 {
        eprintln!("  ceiling (max_total_bytes): {}", human_size(ceiling));
    }
    eprintln!();
}

pub fn print_summary(c: &AssetCatalog, show_duplicates: bool) {
    eprintln!("\n== Discovered assets ==");

    match &c.packages.error {
        Some(err) => eprintln!("Packages ({}): query failed: {err}", c.packages.manager),
        None => eprintln!(
            "Packages ({}): {} explicitly installed",
            c.packages.manager, c.packages.explicit_count
        ),
    }

    let dot_total: u64 = c.dotfiles.iter().map(|d| d.size_bytes).sum();
    eprintln!(
        "Dotfiles: {} found, {}",
        c.dotfiles.len(),
        human_size(dot_total)
    );
    for d in &c.dotfiles {
        eprintln!("    {}  ({})", d.path.display(), human_size(d.size_bytes));
    }

    let repo_total: u64 = c.git_repos.iter().map(|r| r.size_bytes).sum();
    let dirty = c
        .git_repos
        .iter()
        .filter(|r| r.has_uncommitted_changes)
        .count();
    eprintln!(
        "Git repos: {} found, {} ({} with uncommitted changes)",
        c.git_repos.len(),
        human_size(repo_total),
        dirty
    );
    for r in &c.git_repos {
        let marker = if r.has_uncommitted_changes { WARN } else { " " };
        eprintln!(
            "  {marker} {}  [{}]  {}  {}",
            r.path.display(),
            r.branch,
            r.remote_url.as_deref().unwrap_or("(no remote)"),
            human_size(r.size_bytes)
        );
        if show_duplicates {
            for other in &r.duplicate_of {
                eprintln!("        duplicate of {}", other.display());
            }
        }
    }

    eprintln!("Docker compose files: {}", c.docker_compose.len());
    for p in &c.docker_compose {
        eprintln!("    {}", p.display());
    }

    let env_total: u64 = c.env_files.iter().map(|f| f.size_bytes).sum();
    eprintln!(
        "Env files: {} found, {}",
        c.env_files.len(),
        human_size(env_total)
    );
    for f in &c.env_files {
        eprintln!("    {}  ({})", f.path.display(), human_size(f.size_bytes));
    }
    eprintln!();
}
