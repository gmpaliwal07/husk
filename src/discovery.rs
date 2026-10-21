use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde::Serialize;
use walkdir::{DirEntry, WalkDir};

use crate::config::Excludes;
use crate::os_detect::OsInfo;

const DEV_DIR_NAMES: &[&str] = &["code", "dev", "projects", "Documents", "src"];

const MAX_DEPTH: usize = 4;

pub(crate) const SKIP_DIRS: [&str; 6] = [
    "node_modules",
    "target",
    ".venv",
    "__pycache__",
    "vendor",
    ".git",
];

const HOME_NOISE_EXTRA: [&str; 9] = [
    "Downloads",
    "Desktop",
    "Music",
    "Pictures",
    "Videos",
    "Public",
    "Templates",
    "snap",
    "go",
];

/// Cap on entries visited when estimating a single directory's size.
const SIZE_ENTRY_CAP: usize = 100_000;

const KNOWN_DOTFILES: [&str; 8] = [
    ".bashrc",
    ".zshrc",
    ".gitconfig",
    ".ssh/config",
    ".config/nvim",
    ".config/fish",
    ".vimrc",
    ".tmux.conf",
];

const COMPOSE_NAMES: [&str; 4] = [
    "docker-compose.yml",
    "docker-compose.yaml",
    "compose.yml",
    "compose.yaml",
];

#[derive(Debug, Serialize)]
pub struct AssetCatalog {
    pub packages: PackageSummary,
    pub dotfiles: Vec<DotfileEntry>,
    pub git_repos: Vec<GitRepoEntry>,
    pub docker_compose: Vec<PathBuf>,
    pub env_files: Vec<FileEntry>,
    pub software: Vec<crate::apps::SoftwareFound>,
}

#[derive(Debug, Serialize)]
pub struct PackageSummary {
    pub manager: String,
    pub explicit_count: usize,
    pub packages: Vec<String>,
    pub error: Option<String>,
}

#[derive(Debug, Serialize)]
pub struct DotfileEntry {
    pub path: PathBuf,
    pub size_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct GitRepoEntry {
    pub path: PathBuf,
    pub branch: String,
    pub has_uncommitted_changes: bool,
    pub remote_url: Option<String>,
    pub size_bytes: u64,
    pub duplicate_of: Vec<PathBuf>,
}

/// Path and size only;
#[derive(Debug, Serialize)]
pub struct FileEntry {
    pub path: PathBuf,
    pub size_bytes: u64,
}

/// Existing common dev directories under `home`.
pub fn dev_roots(home: &Path) -> Vec<PathBuf> {
    DEV_DIR_NAMES
        .iter()
        .map(|name| home.join(name))
        .filter(|p| p.is_dir())
        .collect()
}

#[derive(Default)]
pub struct DiscoveryOptions {
    pub exclude_repos: Vec<PathBuf>,
    /// Globs excluded from untracked-file and .env discovery.
    pub excludes: Excludes,
    pub extra_dotfiles: Vec<PathBuf>,
    pub skip_repos: bool,
}

impl DiscoveryOptions {
    fn repo_excluded(&self, path: &Path) -> bool {
        self.exclude_repos.iter().any(|x| path.starts_with(x))
    }
}

/// Canonicalizes a path, falling back to the path itself if that fails.
fn canonical_or_self(path: &Path) -> PathBuf {
    fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
}

pub fn discover_assets(
    home: &Path,
    os: &OsInfo,
    scan_roots: &[PathBuf],
    opts: &DiscoveryOptions,
) -> AssetCatalog {
    let mut git_repos = Vec::new();
    let mut docker_compose = Vec::new();
    let mut env_files = Vec::new();
    let seen_roots = scan_unique_roots(
        scan_roots,
        opts,
        &mut git_repos,
        &mut docker_compose,
        &mut env_files,
    );

    if !opts.skip_repos {
        scan_home_level(home, &seen_roots, opts, &mut git_repos);
    }

    git_repos.sort_by(|a, b| a.path.cmp(&b.path));
    mark_duplicates(&mut git_repos);
    docker_compose.sort();
    env_files.sort_by(|a, b| a.path.cmp(&b.path));

    AssetCatalog {
        packages: discover_packages(&os.package_manager),
        dotfiles: discover_dotfiles(home, &opts.extra_dotfiles),
        git_repos,
        docker_compose,
        env_files,
        software: crate::apps::detect_present(),
    }
}

fn scan_unique_roots(
    scan_roots: &[PathBuf],
    opts: &DiscoveryOptions,
    git_repos: &mut Vec<GitRepoEntry>,
    docker_compose: &mut Vec<PathBuf>,
    env_files: &mut Vec<FileEntry>,
) -> Vec<PathBuf> {
    let mut seen_roots: Vec<PathBuf> = Vec::new();
    for root in scan_roots {
        let canonical = canonical_or_self(root);
        if seen_roots.iter().any(|s| canonical.starts_with(s)) {
            continue;
        }
        seen_roots.push(canonical);
        scan_root(root, opts, git_repos, docker_compose, env_files);
    }
    seen_roots
}

fn scan_home_level(
    home: &Path,
    scanned_roots: &[PathBuf],
    opts: &DiscoveryOptions,
    repos: &mut Vec<GitRepoEntry>,
) {
    let Ok(entries) = fs::read_dir(home) else {
        return;
    };
    for entry in entries.filter_map(Result::ok) {
        let name = entry.file_name().to_string_lossy().into_owned();
        if !entry.file_type().is_ok_and(|t| t.is_dir())
            || name.starts_with('.')
            || SKIP_DIRS.contains(&name.as_str())
            || HOME_NOISE_EXTRA.contains(&name.as_str())
        {
            continue;
        }
        let path = entry.path();
        let canonical = canonical_or_self(&path);
        let already_covered = scanned_roots.iter().any(|r| canonical.starts_with(r))
            || repos.iter().any(|r| r.path == path);
        if !already_covered && !opts.repo_excluded(&path) && path.join(".git").exists() {
            repos.push(inspect_repo(&path, &opts.excludes));
        }
    }
}

pub(crate) fn is_skipped(entry: &DirEntry) -> bool {
    entry.file_type().is_dir()
        && entry
            .file_name()
            .to_str()
            .is_some_and(|name| SKIP_DIRS.contains(&name))
}

fn scan_root(
    root: &Path,
    opts: &DiscoveryOptions,
    repos: &mut Vec<GitRepoEntry>,
    compose: &mut Vec<PathBuf>,
    env_files: &mut Vec<FileEntry>,
) {
    let walker = WalkDir::new(root)
        .max_depth(MAX_DEPTH)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_skipped(e) && !opts.repo_excluded(e.path()));

    for entry in walker.filter_map(Result::ok) {
        if entry.file_type().is_dir() {
            if !opts.skip_repos && entry.path().join(".git").exists() {
                repos.push(inspect_repo(entry.path(), &opts.excludes));
            }
            continue;
        }
        if !entry.file_type().is_file() {
            continue;
        }

        let name = entry.file_name().to_string_lossy();
        if COMPOSE_NAMES.contains(&name.as_ref()) {
            compose.push(entry.path().to_path_buf());
            continue;
        }
        if !is_env_file(&name) {
            continue;
        }

        let rel = entry.path().strip_prefix(root).unwrap_or(entry.path());
        if opts.excludes.matches(rel, entry.path()) {
            continue;
        }
        let size_bytes = entry.metadata().map(|m| m.len()).unwrap_or(0);
        env_files.push(FileEntry {
            path: entry.path().to_path_buf(),
            size_bytes,
        });
    }
}

fn is_env_file(name: &str) -> bool {
    if name == ".env" {
        return true;
    }
    name.starts_with(".env.")
        && !["example", "sample", "template", "dist"]
            .iter()
            .any(|suffix| name.ends_with(suffix))
}

fn discover_packages(package_manager: &str) -> PackageSummary {
    let (program, args): (&str, &[&str]) = match package_manager {
        "apt" => ("apt-mark", &["showmanual"]),
        "pacman" => ("pacman", &["-Qeq"]),
        other => {
            return PackageSummary {
                manager: other.to_string(),
                explicit_count: 0,
                packages: vec![],
                error: Some(format!("unknown package manager {other:?}")),
            }
        }
    };

    match Command::new(program).args(args).output() {
        Ok(out) if out.status.success() => {
            let packages: Vec<String> = String::from_utf8_lossy(&out.stdout)
                .lines()
                .map(str::trim)
                .filter(|l| !l.is_empty())
                .map(String::from)
                .collect();
            PackageSummary {
                manager: package_manager.to_string(),
                explicit_count: packages.len(),
                packages,
                error: None,
            }
        }
        Ok(out) => PackageSummary {
            manager: package_manager.to_string(),
            explicit_count: 0,
            packages: vec![],
            error: Some(format!("{program} exited with {}", out.status)),
        },
        Err(e) => PackageSummary {
            manager: package_manager.to_string(),
            explicit_count: 0,
            packages: vec![],
            error: Some(format!("failed to run {program}: {e}")),
        },
    }
}

fn discover_dotfiles(home: &Path, extra: &[PathBuf]) -> Vec<DotfileEntry> {
    let mut paths: Vec<PathBuf> = KNOWN_DOTFILES.iter().map(|rel| home.join(rel)).collect();
    for p in extra {
        if !paths.contains(p) {
            paths.push(p.clone());
        }
    }
    paths
        .into_iter()
        .filter(|p| p.exists())
        .map(|path| {
            let size_bytes = dir_or_file_size(&path);
            DotfileEntry { path, size_bytes }
        })
        .collect()
}

fn dir_or_file_size(path: &Path) -> u64 {
    WalkDir::new(path)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| !is_skipped(e))
        .filter_map(Result::ok)
        .take(SIZE_ENTRY_CAP)
        .filter(|e| e.file_type().is_file())
        .filter_map(|e| e.metadata().ok())
        .map(|m| m.len())
        .sum()
}

pub(crate) fn git_raw(repo: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new("git")
        .arg("-C")
        .arg(repo)
        .args(["-c", "core.fsmonitor=false"])
        .args(args)
        .output()
        .ok()?;
    out.status.success().then_some(out.stdout)
}

fn git(repo: &Path, args: &[&str]) -> Option<String> {
    git_raw(repo, args).map(|b| String::from_utf8_lossy(&b).trim().to_string())
}

pub(crate) fn untracked_paths(status_z: &[u8]) -> Vec<PathBuf> {
    use std::ffi::OsStr;
    use std::os::unix::ffi::OsStrExt;

    let mut tokens = status_z.split(|&b| b == 0).filter(|t| !t.is_empty());
    let mut paths = Vec::new();

    while let Some(tok) = tokens.next() {
        if let Some(rel) = tok.strip_prefix(b"?? ") {
            paths.push(PathBuf::from(OsStr::from_bytes(rel)));
        } else if is_rename_or_copy(tok) {
            tokens.next();
        }
    }
    paths
}

/// XY status code: either column is 'R' (rename) or 'C' (copy).
fn is_rename_or_copy(tok: &[u8]) -> bool {
    tok.len() >= 2 && (tok[0] == b'R' || tok[0] == b'C' || tok[1] == b'R' || tok[1] == b'C')
}

fn untracked_bytes(repo: &Path, status_z: &[u8], excludes: &Excludes) -> u64 {
    untracked_paths(status_z)
        .into_iter()
        .filter(|rel| !excludes.matches(rel, &repo.join(rel)))
        .take(SIZE_ENTRY_CAP)
        .map(|rel| fs::symlink_metadata(repo.join(rel)).map_or(0, |m| m.len()))
        .sum()
}

fn repo_branch(path: &Path) -> String {
    git(path, &["branch", "--show-current"])
        .filter(|b| !b.is_empty())
        .unwrap_or_else(|| "(detached or unborn)".to_string())
}

fn repo_backup_size(path: &Path, status: Option<&[u8]>, excludes: &Excludes) -> u64 {
    let diff_bytes = |extra: &[&str]| {
        let mut args = vec!["diff", "--no-ext-diff", "--no-textconv"];
        args.extend_from_slice(extra);
        git_raw(path, &args).map_or(0, |d| d.len() as u64)
    };
    status.map_or(0, |s| untracked_bytes(path, s, excludes))
        + diff_bytes(&[])
        + diff_bytes(&["--cached"])
}

fn repo_remote_url(path: &Path) -> Option<String> {
    git(path, &["remote", "get-url", "origin"])
        .or_else(|| {
            let first = git(path, &["remote"])?.lines().next()?.to_string();
            git(path, &["remote", "get-url", &first])
        })
        .filter(|u| !u.is_empty())
}

fn inspect_repo(path: &Path, excludes: &Excludes) -> GitRepoEntry {
    let branch = repo_branch(path);
    let status = git_raw(
        path,
        &[
            "status",
            "--porcelain",
            "-z",
            "--ignored=no",
            "--untracked-files=all",
        ],
    );
    let has_uncommitted_changes = status.as_ref().is_none_or(|s| !s.is_empty());
    let size_bytes = repo_backup_size(path, status.as_deref(), excludes);
    let remote_url = repo_remote_url(path);

    GitRepoEntry {
        path: path.to_path_buf(),
        branch,
        has_uncommitted_changes,
        remote_url,
        size_bytes,
        duplicate_of: vec![],
    }
}

/// Link clones that share a remote URL and branch. Repos without a remote are never grouped.
fn mark_duplicates(repos: &mut [GitRepoEntry]) {
    let infos: Vec<(PathBuf, Option<(String, String)>)> = repos
        .iter()
        .map(|r| {
            (
                r.path.clone(),
                r.remote_url.clone().map(|u| (u, r.branch.clone())),
            )
        })
        .collect();
    for (i, repo) in repos.iter_mut().enumerate() {
        let Some(key) = &infos[i].1 else { continue };
        repo.duplicate_of = infos
            .iter()
            .enumerate()
            .filter(|(j, (_, k))| *j != i && k.as_ref() == Some(key))
            .map(|(_, (path, _))| path.clone())
            .collect();
    }
}

pub fn human_size(bytes: u64) -> String {
    const UNITS: [&str; 5] = ["B", "KiB", "MiB", "GiB", "TiB"];
    let mut value = bytes as f64;
    let mut unit = 0;
    while value >= 1024.0 && unit < UNITS.len() - 1 {
        value /= 1024.0;
        unit += 1;
    }
    if unit == 0 {
        format!("{bytes} B")
    } else {
        format!("{value:.1} {}", UNITS[unit])
    }
}
