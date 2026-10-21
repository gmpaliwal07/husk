//! Opt-in "personal files" category: whole-file backup of user-chosen folders, size-aware.
use std::path::{Path, PathBuf};
use walkdir::WalkDir;

use crate::config::Excludes;

/// Folders under $HOME offered by `husk configure`.
pub const CANDIDATE_NAMES: [&str; 5] = ["Pictures", "Documents", "Videos", "Music", "Desktop"];

pub fn candidate_folders(home: &Path) -> Vec<PathBuf> {
    CANDIDATE_NAMES
        .iter()
        .map(|n| home.join(n))
        .filter(|p| p.is_dir())
        .collect()
}

#[derive(Debug, Clone)]
pub struct ScanFile {
    pub rel: PathBuf,
    pub size_bytes: u64,
}

/// Result of walking one folder.
#[derive(Debug, Clone)]
pub struct FolderScan {
    pub folder: PathBuf,
    pub files: Vec<ScanFile>,
    pub total_bytes: u64,
    pub repo_roots: Vec<PathBuf>,
    pub repo_bytes: u64,
    pub unreadable: usize,
}

/// Walk `folder`, recording symlinks as zero-byte files and matching relative excludes.
pub fn scan_folder(folder: &Path, excludes: &Excludes) -> FolderScan {
    let mut files = Vec::new();
    let mut repo_roots = Vec::new();
    let mut unreadable = 0;

    let walker = WalkDir::new(folder)
        .follow_links(false)
        .into_iter()
        .filter_entry(|e| {
            if !e.file_type().is_dir() || e.depth() == 0 {
                return true;
            }
            // Prune matching directories without enumerating their contents.
            let rel = e.path().strip_prefix(folder).unwrap_or(e.path());
            !excludes.matches(&rel.join("_"), &e.path().join("_"))
        });

    for entry in walker {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => {
                unreadable += 1;
                continue;
            }
        };
        let ft = entry.file_type();
        if ft.is_dir() {
            if entry.path().join(".git").exists() {
                repo_roots.push(entry.path().to_path_buf());
            }
            continue;
        }
        if !ft.is_file() && !ft.is_symlink() {
            continue; // sockets, fifos, devices
        }
        let rel = entry
            .path()
            .strip_prefix(folder)
            .unwrap_or(entry.path())
            .to_path_buf();
        if excludes.matches(&rel, entry.path()) {
            continue;
        }
        let size_bytes = if ft.is_file() {
            match entry.metadata() {
                Ok(m) => m.len(),
                Err(_) => {
                    unreadable += 1;
                    continue;
                }
            }
        } else {
            0
        };
        files.push(ScanFile { rel, size_bytes });
    }

    let total_bytes = files.iter().map(|f| f.size_bytes).sum();
    let repo_bytes = files
        .iter()
        .filter(|f| {
            let full = folder.join(&f.rel);
            repo_roots.iter().any(|r| full.starts_with(r))
        })
        .map(|f| f.size_bytes)
        .sum();

    FolderScan {
        folder: folder.to_path_buf(),
        files,
        total_bytes,
        repo_roots,
        repo_bytes,
        unreadable,
    }
}

/// Totals after applying a per-file size cap (`0` = no cap).
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Capped {
    pub files: usize,
    pub bytes: u64,
    pub skipped_files: usize,
    pub skipped_bytes: u64,
}

impl FolderScan {
    pub fn capped(&self, max_file_bytes: u64) -> Capped {
        let mut c = Capped::default();
        for f in &self.files {
            if max_file_bytes > 0 && f.size_bytes > max_file_bytes {
                c.skipped_files += 1;
                c.skipped_bytes += f.size_bytes;
            } else {
                c.files += 1;
                c.bytes += f.size_bytes;
            }
        }
        c
    }
}

pub fn sum_capped(scans: &[FolderScan], max_file_bytes: u64) -> Capped {
    scans.iter().fold(Capped::default(), |mut acc, s| {
        let c = s.capped(max_file_bytes);
        acc.files += c.files;
        acc.bytes += c.bytes;
        acc.skipped_files += c.skipped_files;
        acc.skipped_bytes += c.skipped_bytes;
        acc
    })
}

/// Files that survive the cap, as (folder, rel, size) records for the writer.
pub fn select_files(
    scans: &[FolderScan],
    max_file_bytes: u64,
) -> Vec<crate::archive::format::PersonalFile> {
    let mut out = Vec::new();
    for s in scans {
        for f in &s.files {
            if max_file_bytes > 0 && f.size_bytes > max_file_bytes {
                continue;
            }
            out.push(crate::archive::format::PersonalFile {
                folder: s.folder.clone(),
                rel: f.rel.clone(),
                size_bytes: f.size_bytes,
            });
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn scan_cap_and_excludes() {
        let dir = std::env::temp_dir().join(format!("husk-personal-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("a/node_modules/p")).unwrap();
        fs::create_dir_all(dir.join("repo/.git")).unwrap();
        fs::write(dir.join("small.txt"), vec![0u8; 100]).unwrap();
        fs::write(dir.join("big.bin"), vec![0u8; 5000]).unwrap();
        fs::write(dir.join("a/skip.iso"), vec![0u8; 700]).unwrap();
        fs::write(dir.join("a/node_modules/p/x.js"), b"x").unwrap();
        fs::write(dir.join("repo/code.rs"), vec![0u8; 40]).unwrap();

        let ex = Excludes::new(&["*.iso".into(), "node_modules/**".into()]).unwrap();
        let scan = scan_folder(&dir, &ex);
        let names: Vec<String> = scan
            .files
            .iter()
            .map(|f| f.rel.to_string_lossy().into_owned())
            .collect();
        assert!(
            !names
                .iter()
                .any(|n| n.ends_with(".iso") || n.contains("node_modules")),
            "{names:?}"
        );
        assert_eq!(scan.total_bytes, 100 + 5000 + 40);
        assert_eq!(scan.repo_roots.len(), 1);
        assert_eq!(scan.repo_bytes, 40);

        let capped = scan.capped(1000);
        assert_eq!(capped.skipped_files, 1);
        assert_eq!(capped.skipped_bytes, 5000);
        assert_eq!(capped.bytes, 140);
        assert_eq!(scan.capped(0).skipped_files, 0);
        fs::remove_dir_all(&dir).unwrap();
    }
}
