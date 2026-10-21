//! Restore engine: compat check, extract to private staging, plan, apply.

use std::collections::HashMap;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{self, Seek};
use std::os::unix::fs::{symlink, DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{anyhow, bail, Context, Result};

use crate::archive::format::{unsanitize_path, Manifest, RepoRecord};
use crate::os_detect::OsInfo;

pub struct Options {
    pub target_root: Option<PathBuf>,
    pub skip_packages: bool,
}

pub fn check_compat(backup: &OsInfo, here: &OsInfo, force: bool) -> Result<Vec<String>> {
    let mut warnings = Vec::new();
    if backup.os_family != here.os_family {
        bail!(
            "OS family mismatch: backup is '{}', this machine is '{}'. Refusing; --force does not override this.",
            backup.os_family, here.os_family
        );
    }
    if backup.kernel_arch != here.kernel_arch {
        bail!(
            "architecture mismatch: backup is '{}', this machine is '{}'. Refusing; --force does not override this.",
            backup.kernel_arch, here.kernel_arch
        );
    }
    if backup.os_id != here.os_id {
        let msg = format!(
            "distro differs: backup is '{}', this machine is '{}' (same family '{}')",
            backup.os_id, here.os_id, here.os_family
        );
        if !force {
            bail!("{msg}. Re-run with --force to restore anyway.");
        }
        warnings.push(format!("{msg} - continuing because of --force"));
    }
    if backup.package_manager != here.package_manager {
        warnings.push(format!(
            "package manager differs: backup used '{}', this machine uses '{}'; package names may not map 1:1",
            backup.package_manager, here.package_manager
        ));
    }
    let binary = match here.package_manager.as_str() {
        "apt" => "apt-get",
        other => other,
    };
    if !on_path(binary) {
        warnings.push(format!(
            "'{binary}' not found on PATH; package installation will fail and be reported"
        ));
    }
    Ok(warnings)
}

fn on_path(bin: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(bin).is_file()))
}

pub struct Staging {
    pub dir: PathBuf,
}

impl Staging {
    pub fn create() -> Result<Self> {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos());
        let dir = std::env::temp_dir().join(format!("husk-restore-{}-{nanos}", std::process::id()));
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&dir)
            .with_context(|| format!("cannot create staging dir {}", dir.display()))?;
        Ok(Staging { dir })
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

#[derive(Clone, Debug)]
pub enum Source {
    File(PathBuf),
    Link(PathBuf),
}

#[derive(Debug)]
pub struct Member {
    pub name: PathBuf,
    pub source: Source,
    pub mode: u32,
}

/// Decrypts the payload into `staging`; nothing is written outside it.
pub fn extract(
    husk: &Path,
    payload_offset: u64,
    identity: &age::x25519::Identity,
    staging: &Path,
) -> Result<Vec<Member>> {
    let mut f = File::open(husk)?;
    f.seek(io::SeekFrom::Start(payload_offset))?;
    let decryptor = match age::Decryptor::new(f).context("payload is not a valid age stream")? {
        age::Decryptor::Recipients(d) => d,
        _ => bail!("payload is not recipient-encrypted"),
    };
    let reader = decryptor
        .decrypt(std::iter::once(identity as &dyn age::Identity))
        .map_err(|e| anyhow!("cannot decrypt payload with this identity: {e}"))?;
    let mut archive = tar::Archive::new(zstd::Decoder::new(reader)?);

    let mut members = Vec::new();
    for (i, entry) in archive.entries()?.enumerate() {
        let mut entry = entry.context("payload is corrupt or truncated")?;
        let name = entry.path()?.into_owned();
        let mode = entry.header().mode().unwrap_or(0o644) & 0o777;
        match entry.header().entry_type() {
            tar::EntryType::Regular => {
                let dest = staging.join(i.to_string());
                let mut out = OpenOptions::new()
                    .write(true)
                    .create_new(true)
                    .mode(0o600)
                    .open(&dest)?;
                io::copy(&mut entry, &mut out)?;
                members.push(Member {
                    name,
                    source: Source::File(dest),
                    mode,
                });
            }
            tar::EntryType::Symlink => {
                if let Some(target) = entry.link_name()? {
                    members.push(Member {
                        name,
                        source: Source::Link(target.into_owned()),
                        mode,
                    });
                }
            }
            _ => {}
        }
    }
    Ok(members)
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum State {
    New,
    Identical,
    Differs,
}

pub struct FileItem {
    pub category: &'static str,
    pub size: u64,
    pub target: PathBuf,
    pub source: Source,
    pub mode: u32,
    pub state: State,
}

pub struct RelItem {
    pub rel: PathBuf,
    pub source: Source,
    pub mode: u32,
}

pub struct RepoItem {
    pub record: RepoRecord,
    pub target: PathBuf,
    pub exists: bool,
    pub patch: Option<PathBuf>,
    pub untracked: Vec<RelItem>,
    pub binary: Vec<RelItem>,
}

pub struct SoftwareItem {
    pub record: crate::archive::format::SoftwareRecord,
    pub staged: HashMap<PathBuf, (Source, u32)>,
    pub generated: HashMap<String, PathBuf>,
}

pub struct Plan {
    pub software: Vec<SoftwareItem>,
    pub packages: Vec<String>,
    pub files: Vec<FileItem>,
    pub repos: Vec<RepoItem>,
    pub warnings: Vec<String>,
}

pub fn map_target(root: Option<&Path>, original: &Path) -> PathBuf {
    match root {
        Some(r) => r.join(original.strip_prefix("/").unwrap_or(original)),
        None => original.to_path_buf(),
    }
}

fn file_size(source: &Source) -> u64 {
    match source {
        Source::File(p) => fs::metadata(p).map_or(0, |m| m.len()),
        Source::Link(_) => 0,
    }
}

fn state_of(source: &Source, target: &Path) -> State {
    if fs::symlink_metadata(target).is_err() {
        State::New
    } else if same_content(source, target) {
        State::Identical
    } else {
        State::Differs
    }
}

fn same_content(source: &Source, target: &Path) -> bool {
    match source {
        Source::Link(t) => fs::read_link(target).is_ok_and(|cur| &cur == t),
        Source::File(p) => {
            let Ok(tm) = fs::symlink_metadata(target) else {
                return false;
            };
            if !tm.is_file() {
                return false;
            }
            match (fs::read(p), fs::read(target)) {
                (Ok(a), Ok(b)) => a == b,
                _ => false,
            }
        }
    }
}

/// A member name decoded from `<category>/<sanitized original path>/<rel...>`.
struct ParsedMember {
    comps: Vec<OsString>,
    top: String,
    original: PathBuf,
    rel: PathBuf,
}

fn parse_member_name(name: &Path) -> Option<ParsedMember> {
    let comps: Vec<OsString> = name
        .components()
        .map(|c| match c {
            Component::Normal(s) => Some(s.to_os_string()),
            _ => None,
        })
        .collect::<Option<_>>()?;
    if comps.len() < 2 {
        return None;
    }
    let top = comps[0].to_string_lossy().into_owned();
    let original = comps[1].to_str().and_then(unsanitize_path)?;
    let rel: PathBuf = comps[2..].iter().collect();
    Some(ParsedMember {
        comps,
        top,
        original,
        rel,
    })
}

pub fn build_plan(manifest: Manifest, members: Vec<Member>, opts: &Options) -> Plan {
    let root = opts.target_root.as_deref();
    let mut warnings = Vec::new();
    let mut files = Vec::new();
    let personal: std::collections::HashSet<PathBuf> = manifest
        .personal_files
        .iter()
        .map(|p| p.path.clone())
        .collect();

    let known: [(&str, &'static str, Vec<PathBuf>); 3] = [
        (
            "dotfiles",
            "dotfile",
            manifest.dotfiles.iter().map(|d| d.path.clone()).collect(),
        ),
        (
            "env",
            "env",
            manifest.env_files.iter().map(|d| d.path.clone()).collect(),
        ),
        ("compose", "compose", manifest.compose_files.clone()),
    ];

    let mut software: Vec<SoftwareItem> = manifest
        .software
        .into_iter()
        .map(|record| SoftwareItem {
            record,
            staged: HashMap::new(),
            generated: HashMap::new(),
        })
        .collect();

    let mut repos: Vec<RepoItem> = manifest
        .repos
        .into_iter()
        .map(|record| {
            let target = map_target(root, &record.path);
            let exists = target.join(".git").exists();
            RepoItem {
                record,
                target,
                exists,
                patch: None,
                untracked: vec![],
                binary: vec![],
            }
        })
        .collect();
    let repo_index: HashMap<PathBuf, usize> = repos
        .iter()
        .enumerate()
        .map(|(i, r)| (r.record.path.clone(), i))
        .collect();

    for m in members {
        let Some(p) = parse_member_name(&m.name) else {
            warnings.push(format!(
                "ignored unexpected archive member {}",
                m.name.display()
            ));
            continue;
        };

        match known.iter().find(|(t, _, _)| *t == p.top) {
            Some((_, category, paths)) => {
                place_known_member(category, paths, &p, root, m, &mut files, &mut warnings);
            }
            None => match p.top.as_str() {
                "files" => place_software_member(&p.comps, &mut software, m, &mut warnings),
                "personal" => place_personal_member(
                    &personal,
                    &p.original,
                    &p.rel,
                    root,
                    m,
                    &mut files,
                    &mut warnings,
                ),
                "repos" => place_repo_member(
                    &p.comps,
                    &p.original,
                    &repo_index,
                    &mut repos,
                    m,
                    &mut warnings,
                ),
                _ => warnings.push(format!(
                    "ignored unexpected archive member {}",
                    m.name.display()
                )),
            },
        }
    }

    Plan {
        software,
        packages: manifest.packages,
        files,
        repos,
        warnings,
    }
}

fn place_known_member(
    category: &'static str,
    paths: &[PathBuf],
    p: &ParsedMember,
    root: Option<&Path>,
    m: Member,
    files: &mut Vec<FileItem>,
    warnings: &mut Vec<String>,
) {
    if !paths.contains(&p.original) {
        warnings.push(format!(
            "ignored {} not listed in manifest",
            m.name.display()
        ));
        return;
    }
    let full = p.original.join(&p.rel);
    let target = map_target(root, &full);
    let state = state_of(&m.source, &target);
    let size = file_size(&m.source);
    files.push(FileItem {
        category,
        size,
        target,
        source: m.source,
        mode: m.mode,
        state,
    });
}

/// `files/<app>/<sanitized path>` or `files/<app>/generated/<name>`.
fn place_software_member(
    comps: &[OsString],
    software: &mut [SoftwareItem],
    m: Member,
    warnings: &mut Vec<String>,
) {
    let app = comps[1].to_string_lossy().into_owned();
    let Some(item) = software.iter_mut().find(|s| s.record.app == app) else {
        warnings.push(format!(
            "ignored {} (app not in manifest)",
            m.name.display()
        ));
        return;
    };
    let (Some(Component::Normal(_)), true) = (m.name.components().nth(2), comps.len() >= 3) else {
        return;
    };
    let third = comps[2].to_string_lossy().into_owned();
    if third == "generated" && comps.len() == 4 {
        let name = comps[3].to_string_lossy().into_owned();
        if item.record.generated.contains(&name) {
            if let Source::File(p) = m.source {
                item.generated.insert(name, p);
            }
        } else {
            warnings.push(format!(
                "ignored {} (not listed in manifest)",
                m.name.display()
            ));
        }
    } else if let (Some(orig), 3) = (unsanitize_path(&third), comps.len()) {
        if item.record.files.contains(&orig) {
            item.staged.insert(orig, (m.source, m.mode));
        } else {
            warnings.push(format!(
                "ignored {} (not listed in manifest)",
                m.name.display()
            ));
        }
    } else {
        warnings.push(format!("ignored unexpected member {}", m.name.display()));
    }
}

fn place_personal_member(
    personal: &std::collections::HashSet<PathBuf>,
    original: &Path,
    rel: &Path,
    root: Option<&Path>,
    m: Member,
    files: &mut Vec<FileItem>,
    warnings: &mut Vec<String>,
) {
    let full = original.join(rel);
    if !personal.contains(&full) {
        warnings.push(format!(
            "ignored {} not listed in manifest",
            m.name.display()
        ));
        return;
    }
    let target = map_target(root, &full);
    let state = state_of(&m.source, &target);
    let size = file_size(&m.source);
    files.push(FileItem {
        category: "personal",
        size,
        target,
        source: m.source,
        mode: m.mode,
        state,
    });
}

fn place_repo_member(
    comps: &[OsString],
    original: &Path,
    repo_index: &HashMap<PathBuf, usize>,
    repos: &mut [RepoItem],
    m: Member,
    warnings: &mut Vec<String>,
) {
    let Some(&i) = repo_index.get(original) else {
        warnings.push(format!(
            "ignored {} (repo not in manifest)",
            m.name.display()
        ));
        return;
    };
    let kind = comps
        .get(2)
        .map(|c| c.to_string_lossy().into_owned())
        .unwrap_or_default();
    let sub: PathBuf = comps[3.min(comps.len())..].iter().collect();
    match kind.as_str() {
        "diff.patch" if comps.len() == 3 => {
            if let Source::File(p) = m.source {
                repos[i].patch = Some(p);
            }
        }
        "untracked" if comps.len() > 3 => repos[i].untracked.push(RelItem {
            rel: sub,
            source: m.source,
            mode: m.mode,
        }),
        "binary_changes" if comps.len() > 3 => repos[i].binary.push(RelItem {
            rel: sub,
            source: m.source,
            mode: m.mode,
        }),
        _ => warnings.push(format!("ignored unexpected member {}", m.name.display())),
    }
}

#[derive(Default)]
pub struct Report {
    pub ok: Vec<String>,
    pub failed: Vec<String>,
    pub manual: Vec<String>,
    pub compose_commands: Vec<String>,
}

impl Report {
    fn ok(&mut self, msg: impl Into<String>) {
        let m = msg.into();
        println!("  ok    {m}");
        self.ok.push(m);
    }
    fn fail(&mut self, msg: impl Into<String>) {
        let m = msg.into();
        println!("  FAIL  {m}");
        self.failed.push(m);
    }
    fn manual(&mut self, msg: impl Into<String>) {
        self.manual.push(msg.into());
    }
}

fn backup_name(target: &Path, ts: &str) -> PathBuf {
    let mut n = 0;
    loop {
        let mut s = target.as_os_str().to_owned();
        s.push(format!(".husk-backup-{ts}"));
        if n > 0 {
            s.push(format!("-{n}"));
        }
        let p = PathBuf::from(s);
        if fs::symlink_metadata(&p).is_err() {
            return p;
        }
        n += 1;
    }
}

pub(crate) enum Placed {
    Written,
    Unchanged,
    /// Where the previous entry was moved.
    BackedUp(PathBuf),
}

/// A differing existing entry is moved to `<target>.husk-backup-<ts>` when `backup` is set.
pub(crate) fn place(
    source: &Source,
    target: &Path,
    mode: u32,
    backup: bool,
    ts: &str,
) -> Result<Placed> {
    if let Some(parent) = target.parent() {
        fs::create_dir_all(parent)
            .with_context(|| format!("cannot create {}", parent.display()))?;
    }
    let mut moved = None;
    if fs::symlink_metadata(target).is_ok() {
        if same_content(source, target) {
            return Ok(Placed::Unchanged);
        }
        if backup {
            let b = backup_name(target, ts);
            fs::rename(target, &b).with_context(|| {
                format!("cannot back up {} to {}", target.display(), b.display())
            })?;
            moved = Some(b);
        } else {
            fs::remove_file(target)
                .with_context(|| format!("cannot replace {}", target.display()))?;
        }
    }
    match source {
        Source::File(p) => {
            fs::copy(p, target).with_context(|| format!("cannot write {}", target.display()))?;
            fs::set_permissions(target, fs::Permissions::from_mode(mode))?;
        }
        Source::Link(t) => {
            symlink(t, target).with_context(|| format!("cannot link {}", target.display()))?;
        }
    }
    Ok(moved.map_or(Placed::Written, Placed::BackedUp))
}

fn run_cmd(cmd: &mut Command) -> Result<String> {
    let out = cmd
        .output()
        .with_context(|| format!("cannot run {:?}", cmd.get_program()))?;
    if out.status.success() {
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    } else {
        let err = String::from_utf8_lossy(&out.stderr);
        bail!(
            "{} ({})",
            err.trim().lines().last().unwrap_or("command failed"),
            out.status
        )
    }
}

fn git(repo: &Path, args: &[&str]) -> Result<String> {
    run_cmd(
        Command::new("git")
            .arg("-C")
            .arg(repo)
            .args(["-c", "core.fsmonitor=false"])
            .args(args),
    )
}

pub fn apply(plan: &Plan, package_manager: &str, opts: &Options) -> Report {
    let mut report = Report::default();
    let ts = chrono::Local::now().format("%Y%m%dT%H%M%S").to_string();

    println!("\n[1/5] packages");
    install_packages(plan, package_manager, opts, &mut report);

    // Files inside a not-yet-cloned repo wait for the clone, or it would fail on a non-empty dir.
    let owner = |f: &FileItem| {
        plan.repos
            .iter()
            .position(|r| !r.exists && f.target.starts_with(&r.target))
    };

    println!("\n[2/5] files");
    let free: Vec<&FileItem> = plan.files.iter().filter(|f| owner(f).is_none()).collect();
    place_batch(&free, &ts, &mut report);

    println!("\n[3/5] repositories");
    for (i, repo) in plan.repos.iter().enumerate() {
        let deferred: Vec<&FileItem> = plan.files.iter().filter(|f| owner(f) == Some(i)).collect();
        restore_repo(repo, &deferred, &ts, &mut report);
    }

    println!("\n[4/5] docker compose");
    if report.compose_commands.is_empty() {
        println!("  (no compose files restored)");
    } else {
        println!("  Compose files were written but NOT started. husk never runs");
        println!("  `docker compose up` unattended (this is intentional).");
    }

    println!("\n[5/5] software configuration");
    let allow_external = opts.target_root.is_none() && !opts.skip_packages;
    if plan.software.is_empty() {
        println!("  (none in backup)");
    }
    for item in &plan.software {
        let app = &item.record.app;
        let Some(handler) = crate::apps::find(app) else {
            report.fail(format!(
                "software {app}: no handler for this app in this husk version"
            ));
            report.manual(format!(
                "{app}: upgrade husk or restore its configuration manually"
            ));
            continue;
        };
        let entry = crate::apps::AppConfigEntry {
            app: app.clone(),
            data: item.record.data.clone(),
            files: item.record.files.clone(),
            generated: vec![],
        };
        let ctx = crate::apps::RestoreCtx {
            staged: &item.staged,
            generated: &item.generated,
            target_root: opts.target_root.as_deref(),
            allow_external,
            ts: &ts,
        };
        match handler.restore(&entry, &ctx) {
            Ok(rep) => {
                for m in rep.ok {
                    report.ok(format!("{app}: {m}"));
                }
                for m in rep.failed {
                    report.fail(format!("{app}: {m}"));
                }
                for m in rep.manual {
                    report.manual(format!("{app}: {m}"));
                }
            }
            Err(e) => report.fail(format!("software {app}: {e:#}")),
        }
    }
    report
}

/// Personal files are tallied into one line (there can be thousands).
fn place_batch(items: &[&FileItem], ts: &str, report: &mut Report) {
    let (mut written, mut same, mut replaced, mut failed) = (0usize, 0usize, 0usize, 0usize);
    for item in items {
        if item.category != "personal" {
            place_item(item, ts, report);
            continue;
        }
        match place(&item.source, &item.target, item.mode, true, ts) {
            Ok(Placed::Written) => written += 1,
            Ok(Placed::Unchanged) => same += 1,
            Ok(Placed::BackedUp(_)) => replaced += 1,
            Err(e) => {
                failed += 1;
                report.fail(format!("personal {}: {e:#}", item.target.display()));
            }
        }
    }
    if written + same + replaced + failed > 0 {
        report.ok(format!(
            "personal files: {written} written, {same} already identical, {replaced} replaced \
             (previous versions kept as .husk-backup-<timestamp>), {failed} failed"
        ));
    }
}

fn place_item(item: &FileItem, ts: &str, report: &mut Report) {
    match place(&item.source, &item.target, item.mode, true, ts) {
        Ok(placed) => {
            let msg = match placed {
                Placed::Written => format!("{} -> {}", item.category, item.target.display()),
                Placed::Unchanged => {
                    format!(
                        "{} {} (already identical)",
                        item.category,
                        item.target.display()
                    )
                }
                Placed::BackedUp(b) => format!(
                    "{} -> {} (previous version saved as {})",
                    item.category,
                    item.target.display(),
                    b.display()
                ),
            };
            report.ok(msg);
            if item.category == "compose" {
                report.compose_commands.push(format!(
                    "docker compose -f '{}' up -d",
                    item.target.display()
                ));
            }
        }
        Err(e) => report.fail(format!(
            "{} {}: {e:#}",
            item.category,
            item.target.display()
        )),
    }
}

fn install_packages(plan: &Plan, pm: &str, opts: &Options, report: &mut Report) {
    if plan.packages.is_empty() {
        println!("  (no packages in backup)");
        return;
    }
    if opts.skip_packages || opts.target_root.is_some() {
        let why = if opts.target_root.is_some() {
            "--target-root set (packages can't be redirected)"
        } else {
            "--skip-packages"
        };
        println!("  skipped {} packages: {why}", plan.packages.len());
        report.manual(format!(
            "{} packages were not installed ({why})",
            plan.packages.len()
        ));
        return;
    }

    let available = |name: &str| -> bool {
        let mut c = match pm {
            "pacman" => {
                let mut c = Command::new("pacman");
                c.args(["-Si", name]);
                c
            }
            "apt" => {
                let mut c = Command::new("apt-cache");
                c.args(["show", "--no-all-versions", name]);
                c
            }
            _ => return false,
        };
        c.stdout(Stdio::null()).stderr(Stdio::null());
        c.status().is_ok_and(|s| s.success())
    };

    let (found, missing): (Vec<&String>, Vec<&String>) =
        plan.packages.iter().partition(|p| available(p));
    for p in &missing {
        report.fail(format!("package {p}: not found in configured repositories"));
        report.manual(format!("install '{p}' manually (AUR/third-party/renamed?)"));
    }
    if found.is_empty() {
        return;
    }

    let install = |names: &[&String]| -> Result<()> {
        let is_root = run_cmd(Command::new("id").arg("-u"))
            .map(|s| s.trim() == "0")
            .unwrap_or(false);
        let (prog, args): (&str, Vec<&str>) = match pm {
            "pacman" => ("pacman", vec!["-S", "--needed", "--noconfirm"]),
            "apt" => ("apt-get", vec!["install", "-y"]),
            _ => bail!("unsupported package manager {pm}"),
        };
        let mut cmd = if is_root {
            Command::new(prog)
        } else {
            let mut c = Command::new("sudo");
            c.arg(prog);
            c
        };
        cmd.args(args).args(names.iter().map(|s| s.as_str()));
        let status = cmd.status()?;
        if status.success() {
            Ok(())
        } else {
            bail!("exit {status}")
        }
    };

    println!(
        "  installing {} packages ({} not found)",
        found.len(),
        missing.len()
    );
    if install(&found).is_ok() {
        report.ok(format!("installed/verified {} packages", found.len()));
    } else {
        println!("  batch install failed; retrying individually");
        // One bad package fails the whole transaction, so isolate it.
        for p in found {
            match install(&[p]) {
                Ok(()) => report.ok(format!("package {p}")),
                Err(e) => report.fail(format!("package {p}: {e:#}")),
            }
        }
    }
}

/// `deferred`: restored files inside this repo that must wait for the clone.
fn restore_repo(repo: &RepoItem, deferred: &[&FileItem], ts: &str, report: &mut Report) {
    let skipped = |report: &mut Report, name: &str| {
        if !deferred.is_empty() {
            report.manual(format!(
                "{name}: {} file(s) inside this repo (e.g. env/compose) were NOT written because \
                 the repo could not be cloned; they remain in the .husk file",
                deferred.len()
            ));
        }
    };
    let name = repo.record.path.display().to_string();
    let target = &repo.target;
    let mut freshly_cloned = false;

    if !repo.exists {
        let Some(url) = repo.record.remote_url.as_deref() else {
            report.fail(format!(
                "repo {name}: local-only repo (no remote), cannot be cloned; its uncommitted \
                 changes were skipped"
            ));
            report.manual(format!(
                "{name}: no remote existed, so nothing to clone. The captured patch/untracked \
                 files remain in the .husk file."
            ));
            skipped(report, &name);
            return;
        };
        if let Some(parent) = target.parent() {
            let _ = fs::create_dir_all(parent);
        }
        let clone = run_cmd(
            Command::new("git")
                .args(["clone", "--quiet", "--", url])
                .arg(target)
                .env("GIT_TERMINAL_PROMPT", "0")
                // URL comes from the manifest; refuse exotic transports like ext::.
                .env("GIT_ALLOW_PROTOCOL", "file:git:http:https:ssh"),
        );
        if let Err(e) = clone {
            report.fail(format!("repo {name}: git clone {url} failed: {e:#}"));
            report.manual(format!(
                "{name}: clone failed; re-run restore after fixing access to {url}"
            ));
            skipped(report, &name);
            return;
        }
        freshly_cloned = true;
        report.ok(format!("repo {name}: cloned {url}"));

        if let Some(sha) = &repo.record.base_commit_sha {
            let branch = &repo.record.branch;
            let real_branch = !branch.starts_with('(');
            let checkout = if real_branch {
                git(target, &["checkout", "--quiet", "-B", branch, sha])
            } else {
                git(target, &["checkout", "--quiet", "--detach", sha])
            };
            match checkout {
                Ok(_) => {
                    if real_branch {
                        let _ = git(
                            target,
                            &[
                                "branch",
                                "--set-upstream-to",
                                &format!("origin/{branch}"),
                                branch,
                            ],
                        );
                    }
                    report.ok(format!(
                        "repo {name}: checked out {} at {}",
                        branch,
                        &sha[..sha.len().min(12)]
                    ));
                }
                Err(e) => {
                    report.fail(format!(
                        "repo {name}: cannot check out base commit {sha}: {e:#}"
                    ));
                    report.manual(format!(
                        "{name}: base commit missing upstream (force-pushed/deleted?); left on default branch"
                    ));
                }
            }
        }
    } else {
        report.ok(format!("repo {name}: already present, restoring in place"));
        if let (Some(sha), Ok(head)) = (
            &repo.record.base_commit_sha,
            git(target, &["rev-parse", "HEAD"]),
        ) {
            if head.trim() != sha {
                report.manual(format!(
                    "{name}: HEAD ({}) differs from the backed-up base commit ({})",
                    &head.trim()[..head.trim().len().min(12)],
                    &sha[..sha.len().min(12)]
                ));
            }
        }
    }

    place_batch(deferred, ts, report);

    for (label, items, backup) in [
        ("untracked", &repo.untracked, !freshly_cloned),
        ("binary change", &repo.binary, !freshly_cloned),
    ] {
        let (mut done, mut bad) = (0, 0);
        for it in items {
            match place(&it.source, &target.join(&it.rel), it.mode, backup, ts) {
                Ok(_) => done += 1,
                Err(e) => {
                    bad += 1;
                    report.fail(format!("repo {name}: {label} {}: {e:#}", it.rel.display()));
                }
            }
        }
        if done > 0 || (bad == 0 && !items.is_empty()) {
            report.ok(format!("repo {name}: {done} {label} file(s) restored"));
        }
    }

    // git apply is all-or-nothing; on failure keep the raw patch for manual use.
    if let Some(patch) = &repo.patch {
        let applied = run_cmd(
            Command::new("git")
                .arg("-C")
                .arg(target)
                .args(["apply", "--whitespace=nowarn"])
                .arg(patch),
        );
        match applied {
            Ok(_) => report.ok(format!("repo {name}: diff applied")),
            Err(e) => {
                let mut dest = target.as_os_str().to_owned();
                dest.push(".husk-unapplied.patch");
                let dest = PathBuf::from(dest);
                match fs::copy(patch, &dest) {
                    Ok(_) => {
                        report.fail(format!("repo {name}: git apply failed: {e:#}"));
                        report.manual(format!(
                            "{name}: patch did not apply; saved raw diff to {} - apply manually with \
                             `git -C {} apply {}`",
                            dest.display(),
                            target.display(),
                            dest.display()
                        ));
                    }
                    Err(ce) => report.fail(format!(
                        "repo {name}: git apply failed ({e:#}) AND saving the patch failed: {ce}"
                    )),
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn os(family: &str, id: &str, arch: &str, pm: &str) -> OsInfo {
        OsInfo {
            os_family: family.into(),
            os_id: id.into(),
            os_version: String::new(),
            kernel_arch: arch.into(),
            package_manager: pm.into(),
        }
    }

    #[test]
    fn compat_rules() {
        let here = os("arch", "garuda", "x86_64", "pacman");
        assert!(check_compat(&here_clone(&here), &here, false).is_ok());
        assert!(check_compat(&os("debian", "debian", "x86_64", "apt"), &here, true).is_err());
        assert!(check_compat(&os("arch", "garuda", "aarch64", "pacman"), &here, true).is_err());
        let other = os("arch", "arch", "x86_64", "pacman");
        assert!(check_compat(&other, &here, false).is_err());
        assert!(check_compat(&other, &here, true)
            .unwrap()
            .iter()
            .any(|w| w.contains("--force")));
    }

    fn here_clone(o: &OsInfo) -> OsInfo {
        os(&o.os_family, &o.os_id, &o.kernel_arch, &o.package_manager)
    }

    #[test]
    fn target_mapping() {
        assert_eq!(
            map_target(None, Path::new("/home/a/.bashrc")),
            PathBuf::from("/home/a/.bashrc")
        );
        assert_eq!(
            map_target(Some(Path::new("/r")), Path::new("/home/a/.bashrc")),
            PathBuf::from("/r/home/a/.bashrc")
        );
    }
}
