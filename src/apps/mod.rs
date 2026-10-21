//! Per-app handlers: detect, capture, restore. Register new ones in `registry`.
//!
//! `AppConfigEntry::data` goes in the manifest (signed, not encrypted): no secrets there.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

use crate::archive::restore::{self, Placed, Source};

pub mod cron;
pub mod devtools;
pub mod flatpak;
pub mod generic;
pub mod gnome;
pub mod shell;
pub mod vscode;

#[derive(Debug, Clone)]
pub struct GeneratedFile {
    pub name: String,
    pub contents: Vec<u8>,
}

#[derive(Debug, Clone)]
pub struct AppConfigEntry {
    pub app: String,
    pub data: serde_json::Value,
    pub files: Vec<PathBuf>,
    pub generated: Vec<GeneratedFile>,
}

#[derive(Debug, Default)]
pub struct AppRestoreReport {
    pub ok: Vec<String>,
    pub failed: Vec<String>,
    pub manual: Vec<String>,
}

pub struct RestoreCtx<'a> {
    pub(crate) staged: &'a HashMap<PathBuf, (Source, u32)>,
    pub(crate) generated: &'a HashMap<String, PathBuf>,
    pub(crate) target_root: Option<&'a Path>,
    pub allow_external: bool,
    pub(crate) ts: &'a str,
}

impl RestoreCtx<'_> {
    pub fn map(&self, original: &Path) -> PathBuf {
        restore::map_target(self.target_root, original)
    }

    pub fn generated_bytes(&self, name: &str) -> Option<Vec<u8>> {
        self.generated.get(name).and_then(|p| std::fs::read(p).ok())
    }

    pub fn place_file(&self, original: &Path, report: &mut AppRestoreReport) {
        let Some((src, mode)) = self.staged.get(original) else {
            report
                .failed
                .push(format!("{}: not found in the payload", original.display()));
            return;
        };
        let target = self.map(original);
        match restore::place(src, &target, *mode, true, self.ts) {
            Ok(Placed::Written) => report.ok.push(format!("wrote {}", target.display())),
            Ok(Placed::Unchanged) => report
                .ok
                .push(format!("{} already identical", target.display())),
            Ok(Placed::BackedUp(b)) => report.ok.push(format!(
                "wrote {} (previous version saved as {})",
                target.display(),
                b.display()
            )),
            Err(e) => report.failed.push(format!("{}: {e:#}", target.display())),
        }
    }

    pub fn timestamp(&self) -> &str {
        self.ts
    }
}

pub trait AppHandler {
    fn id(&self) -> &str;
    fn name(&self) -> &str;
    fn default_enabled(&self) -> bool {
        true
    }
    fn is_present(&self) -> bool;
    fn capture(&self) -> Result<AppConfigEntry>;
    fn restore(&self, entry: &AppConfigEntry, ctx: &RestoreCtx) -> Result<AppRestoreReport>;
}

pub fn registry() -> Vec<Box<dyn AppHandler>> {
    let mut all: Vec<Box<dyn AppHandler>> = vec![
        Box::new(vscode::VsCode),
        Box::new(shell::ShellPlugins),
        Box::new(flatpak::Flatpak),
        Box::new(devtools::DevTools),
        Box::new(gnome::GnomeSettings),
        Box::new(cron::Crontab),
    ];
    let taken: std::collections::HashSet<String> = all.iter().map(|h| h.id().to_string()).collect();
    all.extend(
        generic::handlers()
            .into_iter()
            .filter(|h| !taken.contains(h.id())),
    );
    all
}

pub fn find(id: &str) -> Option<Box<dyn AppHandler>> {
    registry().into_iter().find(|h| h.id() == id)
}

pub fn default_toggles() -> std::collections::BTreeMap<String, bool> {
    registry()
        .iter()
        .map(|h| (h.id().to_string(), h.default_enabled()))
        .collect()
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SoftwareFound {
    pub id: String,
    pub name: String,
    pub default_enabled: bool,
}

pub fn detect_present() -> Vec<SoftwareFound> {
    registry()
        .iter()
        .filter(|h| h.is_present())
        .map(|h| SoftwareFound {
            id: h.id().to_string(),
            name: h.name().to_string(),
            default_enabled: h.default_enabled(),
        })
        .collect()
}

pub fn home_dir() -> Result<PathBuf> {
    Ok(PathBuf::from(
        std::env::var_os("HOME").context("$HOME is not set")?,
    ))
}

pub fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
}

pub fn run(bin: &str, args: &[&str]) -> Result<String> {
    let out = Command::new(bin)
        .args(args)
        .output()
        .with_context(|| format!("cannot run `{bin}`"))?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!(
            "`{bin} {}` failed: {}",
            args.join(" "),
            err.trim().lines().last().unwrap_or("no output")
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}

pub fn str_list(data: &serde_json::Value, key: &str) -> Vec<String> {
    data.get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| x.as_str().map(String::from))
                .collect()
        })
        .unwrap_or_default()
}

pub fn data_home(data: &serde_json::Value) -> PathBuf {
    data.get("home")
        .and_then(|v| v.as_str())
        .map(PathBuf::from)
        .unwrap_or_default()
}
