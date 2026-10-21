use std::io::IsTerminal;
use std::path::{Path, PathBuf};

use anyhow::{bail, Result};
use dialoguer::{Confirm, Input, MultiSelect, Select};

use crate::config::{expand_tilde, Categories, Config, Excludes, CATEGORY_NAMES};
use crate::discovery::human_size;
use crate::keys::KeyPaths;
use crate::os_detect;
use crate::personal::{self, FolderScan};

use super::backup;

pub fn run() -> Result<()> {
    if !std::io::stdin().is_terminal() {
        bail!("`husk configure` is interactive and needs a terminal");
    }
    KeyPaths::new()?; // fail early if $HOME is unset
    let home = backup::home_dir()?;

    match Config::load()? {
        None => {
            println!("No config yet - running discovery to create one.");
            let os = os_detect::detect()?;
            let mut cfg = Config::default();
            let resolved = cfg.resolve(&home)?;
            let catalog = backup::discover(&resolved, &cfg, &os, &home, true)?;
            backup::print_summary(&catalog, true);
            let chosen = backup::select_categories(&catalog, [true; 6])?;
            cfg.categories = Categories::from_array(chosen);
            if Confirm::new()
                .with_prompt("Edit paths / output / behavior settings now?")
                .default(false)
                .interact()?
            {
                edit_menu(&mut cfg)?;
            }
            validate_and_save(&cfg)?;
        }
        Some(mut cfg) => {
            println!("Current settings:\n\n{}", cfg.render());
            if edit_menu(&mut cfg)? {
                validate_and_save(&cfg)?;
            } else {
                println!("No changes saved.");
            }
        }
    }
    Ok(())
}

fn validate_and_save(cfg: &Config) -> Result<()> {
    cfg.resolve(&backup::home_dir()?)?;
    let path = cfg.save()?;
    println!("Saved {}", path.display());
    Ok(())
}

#[derive(Clone, Copy)]
enum Menu {
    Categories,
    ScanRoots,
    Dotfiles,
    ExcludeRepos,
    ExcludePatterns,
    Output,
    Behavior,
    Personal,
    PersonalExcludes,
    Save,
    Quit,
}

impl Menu {
    const ALL: [Menu; 11] = [
        Menu::Categories,
        Menu::ScanRoots,
        Menu::Dotfiles,
        Menu::ExcludeRepos,
        Menu::ExcludePatterns,
        Menu::Output,
        Menu::Behavior,
        Menu::Personal,
        Menu::PersonalExcludes,
        Menu::Save,
        Menu::Quit,
    ];

    fn label(self) -> &'static str {
        match self {
            Menu::Categories => "Categories (what to back up)",
            Menu::ScanRoots => "Extra scan roots",
            Menu::Dotfiles => "Extra dotfiles",
            Menu::ExcludeRepos => "Excluded repos",
            Menu::ExcludePatterns => "Exclude patterns (globs)",
            Menu::Output => "Output (default path, keep last N)",
            Menu::Behavior => "Behavior (auto_confirm, duplicate warnings)",
            Menu::Personal => "Personal files (opt-in whole-file backup: Pictures, Documents, ...)",
            Menu::PersonalExcludes => "Personal files: exclude patterns (globs)",
            Menu::Save => "Save and exit",
            Menu::Quit => "Quit without saving",
        }
    }
}

/// Returns true if the user chose to save.
fn edit_menu(cfg: &mut Config) -> Result<bool> {
    let labels = Menu::ALL.map(Menu::label);
    let save_index = Menu::ALL
        .iter()
        .position(|m| matches!(m, Menu::Save))
        .unwrap_or(0);
    loop {
        let pick = Select::new()
            .with_prompt("Configure")
            .items(&labels)
            .default(save_index)
            .interact()?;
        match Menu::ALL[pick] {
            Menu::Categories => {
                let names: Vec<&str> = CATEGORY_NAMES.to_vec();
                let chosen = MultiSelect::new()
                    .with_prompt("Categories to include")
                    .items(&names)
                    .defaults(&cfg.categories.to_array())
                    .interact()?;
                cfg.categories = Categories::from_array(backup::to_flags(chosen));
            }
            Menu::ScanRoots => edit_list("extra_scan_roots", &mut cfg.paths.extra_scan_roots)?,
            Menu::Dotfiles => edit_list("extra_dotfiles", &mut cfg.paths.extra_dotfiles)?,
            Menu::ExcludeRepos => edit_list("exclude_repos", &mut cfg.paths.exclude_repos)?,
            Menu::ExcludePatterns => {
                edit_list("exclude_patterns", &mut cfg.paths.exclude_patterns)?
            }
            Menu::Output => edit_output(cfg)?,
            Menu::Behavior => edit_behavior(cfg)?,
            Menu::Personal => edit_personal(cfg, &backup::home_dir()?)?,
            Menu::PersonalExcludes => edit_list(
                "personal_files.exclude_patterns",
                &mut cfg.personal_files.exclude_patterns,
            )?,
            Menu::Save => return Ok(true),
            Menu::Quit => return Ok(false),
        }
    }
}

fn edit_output(cfg: &mut Config) -> Result<()> {
    cfg.output.default_path = Input::new()
        .with_prompt("output.default_path (~ allowed)")
        .with_initial_text(cfg.output.default_path.clone())
        .interact_text()?;
    cfg.output.keep_last_n = Input::new()
        .with_prompt("output.keep_last_n (0 = keep all)")
        .default(cfg.output.keep_last_n)
        .interact_text()?;
    Ok(())
}

fn edit_behavior(cfg: &mut Config) -> Result<()> {
    cfg.behavior.auto_confirm = Confirm::new()
        .with_prompt("auto_confirm: write backups without asking (needed for cron)?")
        .default(cfg.behavior.auto_confirm)
        .interact()?;
    cfg.behavior.warn_on_duplicate_clones = Confirm::new()
        .with_prompt("warn_on_duplicate_clones?")
        .default(cfg.behavior.warn_on_duplicate_clones)
        .interact()?;
    Ok(())
}

fn edit_list(name: &str, list: &mut Vec<String>) -> Result<()> {
    loop {
        println!(
            "{name}: {}",
            if list.is_empty() {
                "(empty)".to_string()
            } else {
                list.join(", ")
            }
        );
        let pick = Select::new()
            .with_prompt(name.to_string())
            .items(&["Add an entry", "Remove entries", "Done"])
            .default(2)
            .interact()?;
        match pick {
            0 => {
                let v: String = Input::new()
                    .with_prompt(format!("Add to {name}"))
                    .interact_text()?;
                let v = v.trim().to_string();
                if !v.is_empty() && !list.contains(&v) {
                    list.push(v);
                }
            }
            1 if !list.is_empty() => {
                let gone = MultiSelect::new()
                    .with_prompt("Select entries to remove")
                    .items(list)
                    .interact()?;
                *list = list
                    .iter()
                    .enumerate()
                    .filter(|(i, _)| !gone.contains(i))
                    .map(|(_, v)| v.clone())
                    .collect();
            }
            1 => println!("(nothing to remove)"),
            _ => return Ok(()),
        }
    }
}

fn edit_personal(cfg: &mut Config, home: &Path) -> Result<()> {
    let excludes = Excludes::new(&cfg.personal_files.exclude_patterns)?;

    let configured: Vec<_> = cfg
        .personal_files
        .folders
        .iter()
        .map(|f| expand_tilde(f, home))
        .collect();
    let candidates = gather_candidates(home, &configured)?;
    if candidates.is_empty() {
        println!(
            "No Pictures/Documents/Videos/Music/Desktop folders found under {}.",
            home.display()
        );
        return Ok(());
    }

    println!("Measuring folder sizes (full directory walk, this can take a while) ...");
    let scans: Vec<FolderScan> = candidates
        .iter()
        .map(|c| personal::scan_folder(c, &excludes))
        .collect();
    let labels: Vec<String> = scans.iter().map(scan_label).collect();
    let defaults: Vec<bool> = scans
        .iter()
        .map(|s| configured.contains(&s.folder))
        .collect();

    let chosen = MultiSelect::new()
        .with_prompt(
            "Personal folders to back up (space to toggle; nothing is selected by default)",
        )
        .items(&labels)
        .defaults(&defaults)
        .interact()?;

    if chosen.is_empty() {
        cfg.personal_files.enabled = false;
        cfg.personal_files.folders.clear();
        cfg.personal_files.max_total_bytes = 0;
        println!("No personal folders selected: personal files backup is OFF.");
        return Ok(());
    }

    let picked: Vec<FolderScan> = chosen.iter().map(|&i| scans[i].clone()).collect();
    let total = personal::sum_capped(&picked, 0);
    println!(
        "\nSelected: {} folder(s), {} files, {}",
        picked.len(),
        total.files,
        human_size(total.bytes)
    );
    let go = Confirm::new()
        .with_prompt(format!(
            "This will add {} to your backup. Continue?",
            human_size(total.bytes)
        ))
        .default(false)
        .interact()?;
    if !go {
        println!("Personal files settings unchanged.");
        return Ok(());
    }

    let cap = ask_size_cap(cfg.personal_files.max_file_bytes)?;
    let capped = personal::sum_capped(&picked, cap);
    if cap > 0 {
        println!(
            "With the cap: {} files, {} ({} files / {} skipped)",
            capped.files,
            human_size(capped.bytes),
            capped.skipped_files,
            human_size(capped.skipped_bytes)
        );
    }

    cfg.personal_files.enabled = true;
    cfg.personal_files.folders = picked
        .iter()
        .map(|s| s.folder.display().to_string())
        .collect();
    cfg.personal_files.max_file_bytes = cap;
    cfg.personal_files.max_total_bytes = capped.bytes + capped.bytes / 4;
    println!(
        "Personal files ON: {} folder(s), ceiling {} per run.",
        cfg.personal_files.folders.len(),
        human_size(cfg.personal_files.max_total_bytes)
    );
    Ok(())
}

fn gather_candidates(home: &Path, configured: &[PathBuf]) -> Result<Vec<PathBuf>> {
    let mut candidates = personal::candidate_folders(home);
    for p in configured {
        if p.is_dir() && !candidates.contains(p) {
            candidates.push(p.clone());
        }
    }
    loop {
        let extra: String = Input::new()
            .with_prompt("Another folder to consider (absolute path, blank to continue)")
            .allow_empty(true)
            .interact_text()?;
        let extra = extra.trim();
        if extra.is_empty() {
            return Ok(candidates);
        }
        let p = expand_tilde(extra, home);
        if !p.is_dir() {
            println!("  {} is not a directory", p.display());
        } else if !candidates.contains(&p) {
            candidates.push(p);
        }
    }
}

fn scan_label(s: &FolderScan) -> String {
    let repo_note = if s.repo_roots.is_empty() {
        String::new()
    } else {
        format!(
            "  [contains {} git repo(s), {} - already covered by git category]",
            s.repo_roots.len(),
            human_size(s.repo_bytes)
        )
    };
    format!(
        "{}  {}  ({} files){repo_note}",
        s.folder.display(),
        human_size(s.total_bytes),
        s.files.len()
    )
}

fn ask_size_cap(current: u64) -> Result<u64> {
    const MB: u64 = 1024 * 1024;
    let wants_cap = Confirm::new()
        .with_prompt("Skip individual files above a size limit (e.g. huge video exports)?")
        .default(current > 0)
        .interact()?;
    if !wants_cap {
        return Ok(0);
    }
    let default_mb = if current > 0 { current / MB } else { 500 };
    let mb: u64 = Input::new()
        .with_prompt("Largest file to include, in MB")
        .default(default_mb)
        .interact_text()?;
    Ok(mb.saturating_mul(MB))
}
