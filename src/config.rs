//! Persistent backup configuration at ~/.config/husk/backup.toml.
use std::collections::BTreeMap;
use std::env;
use std::fs;
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::{Deserialize, Serialize};

pub const CATEGORY_NAMES: [&str; 6] = [
    "packages",
    "dotfiles",
    "git_repos",
    "docker_compose",
    "env_files",
    "software",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Config {
    pub categories: Categories,
    pub paths: Paths,
    pub output: Output,
    pub behavior: Behavior,
    pub personal_files: PersonalFiles,
    pub software: BTreeMap<String, bool>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct PersonalFiles {
    pub enabled: bool,
    pub folders: Vec<String>,
    /// Safety ceiling for one run (bytes). Set by `husk configure` to the confirmed size
    pub max_total_bytes: u64,
    /// Files larger than this are skipped (bytes, 0 = no cap).
    pub max_file_bytes: u64,
    pub exclude_patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Categories {
    pub packages: bool,
    pub dotfiles: bool,
    pub git_repos: bool,
    pub docker_compose: bool,
    pub env_files: bool,
    pub software: bool,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Paths {
    pub extra_scan_roots: Vec<String>,
    pub extra_dotfiles: Vec<String>,
    pub exclude_repos: Vec<String>,
    pub exclude_patterns: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Output {
    pub default_path: String,
    /// 0 disables pruning.
    pub keep_last_n: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Behavior {
    pub auto_confirm: bool,
    pub warn_on_duplicate_clones: bool,
}

impl Default for Categories {
    fn default() -> Self {
        Categories {
            packages: true,
            dotfiles: true,
            git_repos: true,
            docker_compose: true,
            env_files: true,
            software: true,
        }
    }
}
impl Default for Output {
    fn default() -> Self {
        Output {
            default_path: "~/husk-backups/backup.husk".into(),
            keep_last_n: 7,
        }
    }
}
impl Default for Behavior {
    fn default() -> Self {
        Behavior {
            auto_confirm: false,
            warn_on_duplicate_clones: true,
        }
    }
}
impl Default for Config {
    fn default() -> Self {
        Config {
            categories: Categories::default(),
            paths: Paths::default(),
            output: Output::default(),
            behavior: Behavior::default(),
            personal_files: PersonalFiles::default(),
            software: crate::apps::default_toggles(),
        }
    }
}

impl Categories {
    pub fn to_array(&self) -> [bool; 6] {
        [
            self.packages,
            self.dotfiles,
            self.git_repos,
            self.docker_compose,
            self.env_files,
            self.software,
        ]
    }

    pub fn from_array(
        [packages, dotfiles, git_repos, docker_compose, env_files, software]: [bool; 6],
    ) -> Self {
        Self {
            packages,
            dotfiles,
            git_repos,
            docker_compose,
            env_files,
            software,
        }
    }
}

pub fn config_path() -> Result<PathBuf> {
    let home = env::var_os("HOME").context("$HOME is not set")?;
    Ok(PathBuf::from(home).join(".config/husk/backup.toml"))
}

fn toml_key(k: &str) -> String {
    if !k.is_empty()
        && k.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
    {
        k.to_string()
    } else {
        toml::Value::String(k.to_string()).to_string()
    }
}

pub fn expand_tilde(value: &str, home: &Path) -> PathBuf {
    let value = value.trim();

    match value {
        "~" => home.to_path_buf(),
        _ if value.starts_with("~/") => home.join(&value[2..]),
        _ => PathBuf::from(value),
    }
}

impl Config {
    pub fn software_enabled(&self, id: &str) -> bool {
        self.software
            .get(id)
            .copied()
            .unwrap_or_else(|| crate::apps::find(id).is_some_and(|h| h.default_enabled()))
    }

    /// `[software]` keys that match no registered handler (usually typos).
    pub fn unknown_software_keys(&self) -> Vec<String> {
        let known = crate::apps::default_toggles();
        self.software
            .keys()
            .filter(|k| !known.contains_key(*k))
            .cloned()
            .collect()
    }

    /// `Ok(None)` when no config file exists yet.
    pub fn load() -> Result<Option<Config>> {
        Self::load_from(&config_path()?)
    }

    pub fn load_from(path: &Path) -> Result<Option<Config>> {
        let text = match fs::read_to_string(path) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e).with_context(|| format!("cannot read {}", path.display())),
        };
        let cfg: Config =
            toml::from_str(&text).with_context(|| format!("invalid config {}", path.display()))?;
        Ok(Some(cfg))
    }

    pub fn save(&self) -> Result<PathBuf> {
        let path = config_path()?;
        self.save_to(&path)?;
        Ok(path)
    }

    pub fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::DirBuilder::new()
                .recursive(true)
                .mode(0o700)
                .create(dir)?;
        }
        let mut tmp = path.as_os_str().to_owned();
        tmp.push(".tmp");
        let tmp = PathBuf::from(tmp);
        let _ = fs::remove_file(&tmp);
        let mut f = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(self.render().as_bytes())?;
        f.sync_all()?;
        fs::rename(&tmp, path)?;
        if let Some(dir) = path.parent() {
            if let Ok(dirf) = fs::File::open(dir) {
                let _ = dirf.sync_all();
            }
        }
        Ok(())
    }

    /// A complete, commented TOML document. Rendered by hand so comments survive edits.
    pub fn render(&self) -> String {
        let s = |v: &str| toml::Value::String(v.to_string()).to_string();
        let arr = |v: &[String]| {
            format!(
                "[{}]",
                v.iter().map(|x| s(x)).collect::<Vec<_>>().join(", ")
            )
        };
        let c = &self.categories;
        let p = &self.paths;
        format!(
            "# husk backup configuration. Written by `husk configure`; safe to hand-edit.\n\
             \n\
             [categories]\n\
             packages = {}\n\
             dotfiles = {}\n\
             git_repos = {}\n\
             docker_compose = {}\n\
             env_files = {}\n\
             # Per-app software configuration (see the [software] table below).\n\
             software = {}\n\
             \n\
             [paths]\n\
             # Extra directories scanned (depth 4) for repos, compose and .env files,\n\
             # in addition to ~/code ~/dev ~/projects ~/Documents ~/src and $HOME depth 1.\n\
             extra_scan_roots = {}\n\
             # Extra files or directories always included as dotfiles.\n\
             extra_dotfiles = {}\n\
             # Repos (or directories containing repos) that are never backed up.\n\
             exclude_repos = {}\n\
             # Globs excluded from untracked-file and .env discovery, e.g. \"*.log\", \"node_modules/**\".\n\
             exclude_patterns = {}\n\
             \n\
             [output]\n\
             # `~` is expanded. Each run writes <name>-<timestamp>.<ext> next to this path.\n\
             default_path = {}\n\
             # Timestamped backups kept in that directory; older ones are deleted. 0 = keep all.\n\
             keep_last_n = {}\n\
             \n\
             [behavior]\n\
             # true: do not ask before writing (required for cron). The plan is still printed.\n\
             auto_confirm = {}\n\
             warn_on_duplicate_clones = {}\n\
             \n\
             [personal_files]\n\
             # Opt-in whole-file backup (NOT diff-based; can be very large). Set up with\n\
             # `husk configure`; never enabled by default.\n\
             enabled = {}\n\
             # Absolute folder paths to include.\n\
             folders = {}\n\
             # Ceiling for one run, in bytes. If the folders have grown past this, personal\n\
             # files are skipped for that run (and the run reports an error). 0 = no ceiling.\n\
             max_total_bytes = {}\n\
             # Skip individual files larger than this many bytes. 0 = no cap.\n\
             max_file_bytes = {}\n\
             # Globs excluded inside the chosen folders, e.g. \"*.iso\", \"node_modules/**\".\n\
             exclude_patterns = {}\n",
            c.packages, c.dotfiles, c.git_repos, c.docker_compose, c.env_files, c.software,
            arr(&p.extra_scan_roots), arr(&p.extra_dotfiles), arr(&p.exclude_repos),
            arr(&p.exclude_patterns),
            s(&self.output.default_path), self.output.keep_last_n,
            self.behavior.auto_confirm, self.behavior.warn_on_duplicate_clones,
            self.personal_files.enabled, arr(&self.personal_files.folders),
            self.personal_files.max_total_bytes, self.personal_files.max_file_bytes,
            arr(&self.personal_files.exclude_patterns),
        ) + &self.render_software()
    }

    fn render_software(&self) -> String {
        let mut out = String::from(
            "\n[software]\n# Per-app capture/restore handlers. crontab is off by default because \
             restoring it\n# replaces your live crontab.\n",
        );
        let mut written = std::collections::BTreeSet::new();
        for h in crate::apps::registry() {
            out.push_str(&format!(
                "{} = {}  # {}\n",
                toml_key(h.id()),
                self.software_enabled(h.id()),
                h.name()
            ));
            written.insert(h.id().to_string());
        }
        for (k, v) in &self.software {
            if !written.contains(k) {
                out.push_str(&format!("{} = {v}\n", toml_key(k)));
            }
        }
        out
    }

    /// Expand paths and compile globs. Fails (before any scanning) on a bad pattern.
    pub fn resolve(&self, home: &Path) -> Result<Resolved> {
        let paths = |v: &[String]| v.iter().map(|x| expand_tilde(x, home)).collect::<Vec<_>>();
        let mut exclude_repos = paths(&self.paths.exclude_repos);
        // Also match through symlinks.
        let canon: Vec<PathBuf> = exclude_repos
            .iter()
            .filter_map(|p| fs::canonicalize(p).ok())
            .collect();
        exclude_repos.extend(canon);
        Ok(Resolved {
            extra_scan_roots: paths(&self.paths.extra_scan_roots),
            extra_dotfiles: paths(&self.paths.extra_dotfiles),
            exclude_repos,
            excludes: Excludes::new(&self.paths.exclude_patterns)?,
            output_default: expand_tilde(&self.output.default_path, home),
            personal_folders: paths(&self.personal_files.folders),
            personal_excludes: Excludes::new(&self.personal_files.exclude_patterns)?,
        })
    }
}

pub struct Resolved {
    pub extra_scan_roots: Vec<PathBuf>,
    pub extra_dotfiles: Vec<PathBuf>,
    pub exclude_repos: Vec<PathBuf>,
    pub excludes: Excludes,
    pub output_default: PathBuf,
    pub personal_folders: Vec<PathBuf>,
    pub personal_excludes: Excludes,
}

#[derive(Clone, Default)]
pub struct Excludes {
    set: Option<GlobSet>,
}

impl Excludes {
    pub fn new(patterns: &[String]) -> Result<Self> {
        if patterns.is_empty() {
            return Ok(Self::default());
        }
        let mut b = GlobSetBuilder::new();
        for p in patterns {
            let g = Glob::new(p).with_context(|| format!("invalid exclude pattern {p:?}"))?;
            b.add(g);
            if !p.starts_with('/') && !p.starts_with("**") {
                b.add(
                    Glob::new(&format!("**/{p}"))
                        .with_context(|| format!("invalid exclude pattern {p:?}"))?,
                );
            }
        }
        Ok(Self {
            set: Some(b.build()?),
        })
    }

    /// `rel` is relative to the repo / scan root; `full` is the absolute path.
    pub fn matches(&self, relative: &Path, full: &Path) -> bool {
        self.set.as_ref().is_some_and(|set| {
            set.is_match(relative)
                || set.is_match(full)
                || full
                    .file_name()
                    .is_some_and(|name| set.is_match(Path::new(name)))
        })
    }
}

// output files

const TS_FORMAT: &str = "%Y-%m-%dT%H%M%S";

/// `dir/name.ext` -> `dir/name-<timestamp>.ext`.
pub fn timestamped_path(base: &Path, now: chrono::DateTime<chrono::Local>) -> PathBuf {
    let ts = now.format(TS_FORMAT).to_string();
    let (stem, ext) = split_name(base);
    let name = match ext {
        Some(e) => format!("{stem}-{ts}.{e}"),
        None => format!("{stem}-{ts}"),
    };
    base.with_file_name(name)
}

fn split_name(base: &Path) -> (String, Option<String>) {
    let stem = base
        .file_stem()
        .map_or_else(|| "backup".into(), |s| s.to_string_lossy().into_owned());
    let ext = base.extension().map(|e| e.to_string_lossy().into_owned());
    (stem, ext)
}

pub fn prune(base: &Path, keep: u32) -> Result<Vec<PathBuf>> {
    if keep == 0 {
        return Ok(vec![]);
    }
    let dir = base
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let (stem, ext) = split_name(base);
    let prefix = format!("{stem}-");
    let suffix = ext.map(|e| format!(".{e}")).unwrap_or_default();

    let mut found: Vec<(String, PathBuf)> = Vec::new();
    for entry in fs::read_dir(dir).with_context(|| format!("cannot read {}", dir.display()))? {
        let entry = entry?;
        let name = entry.file_name().to_string_lossy().into_owned();
        let Some(mid) = name
            .strip_prefix(&prefix)
            .and_then(|n| n.strip_suffix(&suffix))
        else {
            continue;
        };
        if is_timestamp(mid) && entry.file_type()?.is_file() {
            found.push((mid.to_string(), entry.path()));
        }
    }
    found.sort();
    let excess = found.len().saturating_sub(keep as usize);
    let mut removed = Vec::new();
    for (_, path) in found.into_iter().take(excess) {
        fs::remove_file(&path).with_context(|| format!("cannot delete {}", path.display()))?;
        removed.push(path);
    }
    Ok(removed)
}

/// `YYYY-MM-DDTHHMMSS`
fn is_timestamp(s: &str) -> bool {
    let b = s.as_bytes();
    b.len() == 17
        && b.iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b'T',
            _ => c.is_ascii_digit(),
        })
}

pub fn ensure_parent(path: &Path) -> Result<()> {
    if let Some(dir) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)
            .with_context(|| format!("cannot create {}", dir.display()))?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn render_round_trips() {
        let mut c = Config::default();
        c.categories.packages = false;
        c.paths.extra_scan_roots = vec!["~/work".into(), "/odd \"dir\"".into()];
        c.paths.exclude_patterns = vec!["*.log".into()];
        c.output.keep_last_n = 2;
        c.behavior.auto_confirm = true;
        c.personal_files = PersonalFiles {
            enabled: true,
            folders: vec!["/home/u/Pictures".into()],
            max_total_bytes: 123,
            max_file_bytes: 456,
            exclude_patterns: vec!["*.iso".into()],
        };
        let back: Config = toml::from_str(&c.render()).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn empty_and_partial_files_get_defaults() {
        let c: Config = toml::from_str("[categories]\npackages = false\n").unwrap();
        assert!(!c.categories.packages && c.categories.dotfiles);
        assert_eq!(c.output.keep_last_n, 7);
        assert!(
            !c.personal_files.enabled,
            "personal files must default to off"
        );
        assert!(
            toml::from_str::<Config>("[categorys]\n").is_err(),
            "typos must be rejected"
        );
    }

    #[test]
    fn exclude_globs() {
        let e = Excludes::new(&["*.log".into(), "node_modules/**".into()]).unwrap();
        let root = Path::new("/r/repo");
        assert!(e.matches(Path::new("a/b/x.log"), &root.join("a/b/x.log")));
        assert!(e.matches(
            Path::new("node_modules/p/i.js"),
            &root.join("node_modules/p/i.js")
        ));
        assert!(e.matches(
            Path::new("web/node_modules/p/i.js"),
            &root.join("web/node_modules/p/i.js")
        ));
        assert!(!e.matches(Path::new("src/main.rs"), &root.join("src/main.rs")));
        assert!(Excludes::new(&["[".into()]).is_err());
    }

    #[test]
    fn exclude_globs_absolute_and_empty() {
        assert!(!Excludes::new(&[])
            .unwrap()
            .matches(Path::new("x"), Path::new("/r/x")));
        let e = Excludes::new(&["/r/repo/vendor/**".into()]).unwrap();
        let root = Path::new("/r/repo");
        assert!(e.matches(Path::new("vendor/pkg/a.go"), &root.join("vendor/pkg/a.go")));
        // Same leaf name nested somewhere unrelated must not match an absolute-rooted pattern.
        assert!(!e.matches(
            Path::new("other/vendor/pkg/a.go"),
            Path::new("/r/other/vendor/pkg/a.go")
        ));
    }

    #[test]
    fn software_keys_round_trip_even_when_not_bare_toml_keys() {
        let mut c = Config::default();
        c.software.insert("my custom handler".into(), true);
        let back: Config = toml::from_str(&c.render()).unwrap();
        assert_eq!(back, c);
    }

    #[test]
    fn timestamp_and_prune() {
        let dir = std::env::temp_dir().join(format!("husk-prune-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let base = dir.join("backup.husk");
        for ts in [
            "2026-10-10T020000",
            "2026-10-11T020000",
            "2026-10-12T020000",
            "2026-10-13T020000",
        ] {
            fs::write(dir.join(format!("backup-{ts}.husk")), b"x").unwrap();
        }
        fs::write(dir.join("backup.husk"), b"keep me").unwrap();
        fs::write(dir.join("backup-notes.husk"), b"keep me").unwrap();
        fs::write(dir.join("other-2026-10-01T020000.husk"), b"keep me").unwrap();
        let removed = prune(&base, 2).unwrap();
        assert_eq!(removed.len(), 2);
        let mut left: Vec<_> = fs::read_dir(&dir)
            .unwrap()
            .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
            .collect();
        left.sort();
        assert_eq!(
            left,
            vec![
                "backup-2026-10-12T020000.husk",
                "backup-2026-10-13T020000.husk",
                "backup-notes.husk",
                "backup.husk",
                "other-2026-10-01T020000.husk",
            ]
        );
        fs::remove_dir_all(&dir).unwrap();
    }
}
