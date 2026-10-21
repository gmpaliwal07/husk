//! Config-driven handler for simple apps: detect, copy config files, hint how to install.
//! Entries come from the built-in catalog.toml plus ~/.config/husk/apps.toml (user wins by id).
//! install_hint is only ever printed; this module never spawns a process.

use std::collections::{BTreeSet, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use anyhow::{bail, Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use serde_json::json;

use super::{home_dir, on_path, AppConfigEntry, AppHandler, AppRestoreReport, RestoreCtx};
use crate::config::expand_tilde;

const BUILTIN: &str = include_str!("catalog.toml");

const MAX_FILE_BYTES: u64 = 5 * 1024 * 1024;
const MAX_FILES: usize = 1000;

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct CatalogEntry {
    pub id: String,
    pub display_name: String,
    #[serde(default)]
    pub detect_binary: Option<String>,
    #[serde(default)]
    pub detect_paths: Vec<String>,
    #[serde(default)]
    pub capture_files: Vec<String>,
    #[serde(default)]
    pub capture_globs: Vec<String>,
    #[serde(default)]
    pub exclude_globs: Vec<String>,
    #[serde(default)]
    pub install_hint: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogFile {
    #[serde(default)]
    app: Vec<CatalogEntry>,
}

pub fn parse_catalog(text: &str) -> Result<Vec<CatalogEntry>> {
    let file: CatalogFile = toml::from_str(text).context("invalid catalog TOML")?;
    let mut seen = HashSet::new();
    for e in &file.app {
        let valid_id = !e.id.is_empty()
            && e.id
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_' || b == b'-');
        if !valid_id {
            bail!("catalog entry id {:?} must match [a-z0-9_-]+", e.id);
        }
        if !seen.insert(e.id.clone()) {
            bail!("catalog entry id {:?} appears twice", e.id);
        }
        if e.detect_binary.as_deref().unwrap_or("").is_empty() && e.detect_paths.is_empty() {
            bail!("catalog entry {:?} needs detect_binary or detect_paths, or it could never be found", e.id);
        }
        for g in e
            .capture_globs
            .iter()
            .chain(&e.exclude_globs)
            .chain(&e.detect_paths)
        {
            glob::Pattern::new(g).with_context(|| format!("entry {:?}: bad glob {g:?}", e.id))?;
        }
    }
    Ok(file.app)
}

pub fn merge(builtin: Vec<CatalogEntry>, user: Vec<CatalogEntry>) -> Vec<CatalogEntry> {
    let mut out = builtin;
    for u in user {
        match out.iter_mut().find(|e| e.id == u.id) {
            Some(slot) => *slot = u,
            None => out.push(u),
        }
    }
    out
}

pub fn user_catalog_path() -> Option<PathBuf> {
    Some(home_dir().ok()?.join(".config/husk/apps.toml"))
}

pub fn catalog() -> &'static [CatalogEntry] {
    static CATALOG: OnceLock<Vec<CatalogEntry>> = OnceLock::new();
    CATALOG.get_or_init(|| {
        let builtin = parse_catalog(BUILTIN).expect("built-in catalog.toml must be valid");
        let user = match user_catalog_path().filter(|p| p.is_file()) {
            None => Vec::new(),
            Some(p) => match fs::read_to_string(&p)
                .map_err(anyhow::Error::from)
                .and_then(|t| parse_catalog(&t))
            {
                Ok(u) => u,
                Err(e) => {
                    eprintln!("warning: ignoring {}: {e:#}", p.display());
                    Vec::new()
                }
            },
        };
        merge(builtin, user)
    })
}

pub fn handlers() -> Vec<Box<dyn AppHandler>> {
    catalog()
        .iter()
        .cloned()
        .map(|entry| Box::new(GenericApp { entry }) as Box<dyn AppHandler>)
        .collect()
}

pub struct GenericApp {
    pub entry: CatalogEntry,
}

fn build_set(patterns: &[String]) -> Result<GlobSet> {
    let mut b = GlobSetBuilder::new();
    for p in patterns {
        b.add(Glob::new(p)?);
    }
    Ok(b.build()?)
}

fn has_glob_chars(s: &str) -> bool {
    s.contains(['*', '?', '['])
}

/// Hard backstop against a wrong or malicious catalog entry smuggling out credentials,
fn deny_set() -> &'static GlobSet {
    static DENY: OnceLock<GlobSet> = OnceLock::new();
    DENY.get_or_init(|| {
        build_set(&[
            "**/.ssh/**".into(),
            "**/.gnupg/**".into(),
            "**/id_rsa*".into(),
            "**/id_dsa*".into(),
            "**/id_ecdsa*".into(),
            "**/id_ed25519*".into(),
            "**/*.pem".into(),
            "**/*.pfx".into(),
            "**/*.kdbx".into(),
            "**/known_hosts".into(),
            "**/*password*".into(),
            "**/*passwd*".into(),
            "**/*secret*".into(),
            "**/*token*".into(),
            "**/*cookies*".into(),
            "**/Cookies".into(),
            "**/Login Data".into(),
        ])
        .expect("deny patterns are valid globs")
    })
}

impl GenericApp {
    fn present_with(&self, home: &Path, map: &dyn Fn(&Path) -> PathBuf) -> bool {
        if let Some(bin) = self
            .entry
            .detect_binary
            .as_deref()
            .filter(|b| !b.is_empty())
        {
            if on_path(bin) {
                return true;
            }
        }
        self.entry.detect_paths.iter().any(|raw| {
            let p = map(&expand_tilde(raw, home));
            if has_glob_chars(raw) {
                glob::glob(&p.to_string_lossy()).is_ok_and(|mut it| it.any(|m| m.is_ok()))
            } else {
                p.exists()
            }
        })
    }

    fn resolve(&self, home: &Path) -> Result<(Vec<PathBuf>, Vec<String>)> {
        let exclude = build_set(&self.entry.exclude_globs)?;
        let deny = deny_set();
        let mut found: BTreeSet<PathBuf> = BTreeSet::new();
        let mut skipped = Vec::new();

        let mut consider = |p: PathBuf| {
            if deny.is_match(&p) || exclude.is_match(&p) {
                return;
            }
            let Ok(meta) = fs::symlink_metadata(&p) else {
                return;
            };
            if meta.is_file() && meta.len() > MAX_FILE_BYTES {
                skipped.push(format!(
                    "{} (larger than {} MiB)",
                    p.display(),
                    MAX_FILE_BYTES >> 20
                ));
            } else if meta.is_file() || meta.file_type().is_symlink() {
                found.insert(p);
            }
        };

        for f in &self.entry.capture_files {
            consider(expand_tilde(f, home));
        }
        for g in &self.entry.capture_globs {
            let pattern = expand_tilde(g, home);
            let Ok(paths) = glob::glob(&pattern.to_string_lossy()) else {
                continue;
            };
            for p in paths.filter_map(Result::ok).take(MAX_FILES) {
                consider(p);
            }
        }
        Ok((found.into_iter().take(MAX_FILES).collect(), skipped))
    }
}

impl AppHandler for GenericApp {
    fn id(&self) -> &str {
        &self.entry.id
    }
    fn name(&self) -> &str {
        &self.entry.display_name
    }

    fn is_present(&self) -> bool {
        home_dir().is_ok_and(|home| self.present_with(&home, &|p| p.to_path_buf()))
    }

    fn capture(&self) -> Result<AppConfigEntry> {
        let home = home_dir()?;
        let (files, skipped) = self.resolve(&home)?;
        Ok(AppConfigEntry {
            app: self.entry.id.clone(),
            data: json!({
                "id": self.entry.id,
                "home": home,
                "files_captured": files,
                "skipped": skipped,
            }),
            files,
            generated: vec![],
        })
    }

    fn restore(&self, entry: &AppConfigEntry, ctx: &RestoreCtx) -> Result<AppRestoreReport> {
        let mut rep = AppRestoreReport::default();
        let home = super::data_home(&entry.data);

        let present = match self
            .entry
            .detect_binary
            .as_deref()
            .filter(|b| !b.is_empty())
        {
            Some(bin) => on_path(bin),
            None => self.present_with(&home, &|p| ctx.map(p)),
        };

        for f in &entry.files {
            ctx.place_file(f, &mut rep);
        }
        if !present && !self.entry.install_hint.trim().is_empty() {
            rep.manual.push(format!(
                "{} does not appear to be installed here. Hint: {}",
                self.entry.display_name, self.entry.install_hint
            ));
        }
        Ok(rep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(id: &str, path: &str) -> String {
        format!("[[app]]\nid = \"{id}\"\ndisplay_name = \"{id}\"\ndetect_paths = [\"{path}\"]\ncapture_files = [\"{path}\"]\n")
    }

    #[test]
    fn builtin_catalog_is_valid_and_has_the_expected_apps() {
        let apps = parse_catalog(BUILTIN).unwrap();
        assert!(apps.len() >= 15, "got {}", apps.len());
        let ids: Vec<&str> = apps.iter().map(|a| a.id.as_str()).collect();
        for want in [
            "tmux",
            "alacritty",
            "kitty",
            "wezterm",
            "jetbrains_idea",
            "ranger",
            "neofetch",
            "fastfetch",
            "htop",
            "btop",
            "zellij",
            "lazygit",
            "direnv",
        ] {
            assert!(ids.contains(&want), "missing {want}");
        }
        for custom in [
            "vscode",
            "shell_plugins",
            "flatpak",
            "dev_tools",
            "gnome_settings",
            "crontab",
        ] {
            assert!(!ids.contains(&custom));
        }
    }

    #[test]
    fn user_entry_overrides_builtin_and_new_apps_are_appended() {
        let builtin = parse_catalog(BUILTIN).unwrap();
        let tmux_before = builtin.iter().find(|a| a.id == "tmux").unwrap().clone();
        let n = builtin.len();

        let user_text = format!(
            "{}{}",
            e("tmux", "~/dotfiles/tmux.conf"),
            e("myapp", "~/.myapprc")
        );
        let merged = merge(builtin, parse_catalog(&user_text).unwrap());

        assert_eq!(merged.len(), n + 1, "one override + one new app");
        let tmux = merged.iter().find(|a| a.id == "tmux").unwrap();
        assert_ne!(*tmux, tmux_before);
        assert_eq!(
            tmux.capture_files,
            vec!["~/dotfiles/tmux.conf"],
            "user path wins"
        );
        assert!(
            tmux.install_hint.is_empty(),
            "override replaces the whole entry"
        );
        assert_eq!(merged.last().unwrap().id, "myapp");
        assert_eq!(merged.iter().position(|a| a.id == "tmux"), Some(0));
    }

    #[test]
    fn validation_rejects_bad_catalogs() {
        assert!(parse_catalog(
            "[[app]]\nid = \"Bad Id\"\ndisplay_name = \"x\"\ndetect_binary = \"x\"\n"
        )
        .is_err());
        assert!(parse_catalog(&format!("{}{}", e("a", "~/x"), e("a", "~/y"))).is_err());
        assert!(parse_catalog("[[app]]\nid = \"nodetect\"\ndisplay_name = \"x\"\n").is_err());
        assert!(parse_catalog("[[app]]\nid = \"a\"\ndisplay_name = \"x\"\ndetect_binary = \"x\"\ncapture_globs = [\"[\"]\n").is_err());
        assert!(parse_catalog(
            "[[app]]\nid = \"a\"\ndisplay_name = \"x\"\ndetect_binary = \"x\"\ntypo = 1\n"
        )
        .is_err());
    }

    #[test]
    fn capture_resolves_files_and_globs_and_honours_excludes() {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("husk-generic-{nanos}"));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join(".config/app/themes")).unwrap();
        fs::write(dir.join(".config/app/main.conf"), "a").unwrap();
        fs::write(dir.join(".config/app/themes/one.theme"), "b").unwrap();
        fs::write(dir.join(".config/app/themes/token.theme"), "secret").unwrap();

        let app = GenericApp {
            entry: CatalogEntry {
                id: "app".into(),
                display_name: "App".into(),
                detect_binary: None,
                detect_paths: vec!["~/.config/app".into()],
                capture_files: vec![
                    "~/.config/app/main.conf".into(),
                    "~/.config/app/missing.conf".into(),
                ],
                capture_globs: vec!["~/.config/app/themes/*.theme".into()],
                exclude_globs: vec!["**/*token*".into()],
                install_hint: String::new(),
            },
        };
        let (files, skipped) = app.resolve(&dir).unwrap();
        let names: Vec<String> = files
            .iter()
            .map(|p| p.strip_prefix(&dir).unwrap().to_string_lossy().into_owned())
            .collect();
        assert_eq!(
            names,
            vec![".config/app/main.conf", ".config/app/themes/one.theme"]
        );
        assert!(skipped.is_empty());
        assert!(app.present_with(&dir, &|p| p.to_path_buf()));
        assert!(!app.present_with(&dir.join("nowhere"), &|p| p.to_path_buf()));
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn module_never_spawns_processes() {
        let src = include_str!("generic.rs");
        let needle = ["Command", "::"].concat();
        assert!(
            !src.contains(&needle),
            "generic.rs must not spawn processes"
        );
        assert!(!src.contains(&["std::", "process"].concat()));
    }
}
