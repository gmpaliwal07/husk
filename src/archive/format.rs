//! `.husk` file writer.
//! Layout, format version 2 (all in one file, in this order):
//! 1. header    : b"HUSK" + version byte + compact JSON + '\n'   (plaintext)
//! 2. manifest  : u32 big-endian length N + N bytes of JSON      (plaintext;
//!    includes `payload_sha256`, the SHA-256 of the payload section)
//! 3. signature : u32 big-endian length (always 64) + raw Ed25519 signature
//!    over exactly the N manifest bytes
//! 4. payload   : age-encrypted stream of a zstd-compressed tar (rest of file)
//!
//! The manifest carries the hash of the encrypted payload, so the signature
//! transitively authenticates the payload too.
//!
//! KNOWN LIMITATION: the header is NOT covered by the signature, so tampering
//! with it can't change what gets decrypted, only whether the compat check passes.

use std::collections::BTreeSet;
use std::ffi::OsStr;
use std::fs::{self, File, OpenOptions};
use std::io::{self, BufRead, BufReader, BufWriter, Read, Write};
use std::os::unix::ffi::{OsStrExt, OsStringExt};
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use walkdir::WalkDir;

use crate::config::Excludes;
use crate::discovery::{self, git_raw, is_skipped, DotfileEntry, FileEntry, GitRepoEntry};
use crate::os_detect::OsInfo;

pub const MAGIC: &[u8; 4] = b"HUSK";
pub const FORMAT_VERSION: u8 = 2;
pub const SCHEMA_VERSION: u32 = 1;
const ZSTD_LEVEL: i32 = 19;

#[derive(Debug, Serialize, Deserialize)]
pub struct Header {
    #[serde(flatten)]
    pub os: OsInfo,
    pub created_at: String,
    pub schema_version: u32,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct Manifest {
    pub payload_sha256: String,
    pub packages: Vec<String>,
    pub repos: Vec<RepoRecord>,
    pub dotfiles: Vec<FileRecord>,
    pub compose_files: Vec<PathBuf>,
    pub env_files: Vec<FileRecord>,
    #[serde(default)]
    pub personal_files: Vec<PersonalFileEntry>,
    #[serde(default)]
    pub software: Vec<SoftwareRecord>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SoftwareRecord {
    pub app: String,
    pub data: serde_json::Value,
    pub files: Vec<PathBuf>,
    pub generated: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct PersonalFileEntry {
    pub path: PathBuf,
    pub size_bytes: u64,
}

pub struct PersonalFile {
    pub folder: PathBuf,
    pub rel: PathBuf,
    pub size_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct RepoRecord {
    pub path: PathBuf,
    pub remote_url: Option<String>,
    pub branch: String,
    pub base_commit_sha: Option<String>,
    pub duplicate_of: Vec<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct FileRecord {
    pub path: PathBuf,
    pub size_bytes: u64,
}

pub struct Selection {
    pub packages: Vec<String>,
    pub dotfiles: Vec<DotfileEntry>,
    pub repos: Vec<GitRepoEntry>,
    pub compose_files: Vec<PathBuf>,
    pub env_files: Vec<FileEntry>,
    pub excludes: Excludes,
    pub personal: Vec<PersonalFile>,
    pub software: Vec<crate::apps::AppConfigEntry>,
}

pub struct WriteReport {
    pub total_bytes: u64,
    pub header_bytes: u64,
    pub manifest_bytes: u64,
    pub signature_bytes: u64,
    pub payload_bytes: u64,
    pub uncompressed_bytes: u64,
    pub members: usize,
    pub warnings: Vec<String>,
}

/// Reversible tar-member-safe encoding: bytes outside `[A-Za-z0-9._-]` become `%XX`.
pub fn sanitize_path(path: &Path) -> String {
    let mut out = String::new();
    for &b in path.as_os_str().as_bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

#[allow(dead_code)]
pub fn unsanitize_path(name: &str) -> Option<PathBuf> {
    let bytes = name.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0;
    while i < bytes.len() {
        if bytes[i] == b'%' {
            let hex = std::str::from_utf8(bytes.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(hex, 16).ok()?);
            i += 3;
        } else {
            out.push(bytes[i]);
            i += 1;
        }
    }
    Some(PathBuf::from(std::ffi::OsString::from_vec(out)))
}

pub fn write(
    out_path: &Path,
    os: &OsInfo,
    sel: &Selection,
    signing_key: &SigningKey,
    recipient: &age::x25519::Recipient,
) -> Result<WriteReport> {
    let mut warnings = Vec::new();
    let header_bytes = build_header_bytes(os)?;
    let mut manifest = build_manifest(sel, &mut warnings);

    let sibling = |suffix: &str| {
        let mut name = out_path.as_os_str().to_owned();
        name.push(suffix);
        PathBuf::from(name)
    };
    let payload_tmp = sibling(".payload.partial");
    let out_tmp = sibling(".partial");
    let cleanup = || {
        let _ = fs::remove_file(&payload_tmp);
        let _ = fs::remove_file(&out_tmp);
    };

    let built = assemble_husk_file(
        &header_bytes,
        &mut manifest,
        sel,
        (signing_key, recipient),
        (&payload_tmp, &out_tmp),
        &mut warnings,
    );

    let (members, uncompressed, payload_len, sizes) = match built {
        Ok(v) => v,
        Err(e) => {
            cleanup();
            return Err(e);
        }
    };
    let finish = fs::rename(&out_tmp, out_path)
        .with_context(|| format!("cannot move result to {}", out_path.display()));
    let _ = fs::remove_file(&payload_tmp);
    if let Err(e) = finish {
        cleanup();
        return Err(e);
    }

    Ok(WriteReport {
        total_bytes: fs::metadata(out_path)?.len(),
        header_bytes: sizes.header,
        manifest_bytes: sizes.manifest,
        signature_bytes: sizes.signature,
        payload_bytes: payload_len,
        uncompressed_bytes: uncompressed,
        members,
        warnings,
    })
}

fn build_header_bytes(os: &OsInfo) -> Result<Vec<u8>> {
    let header = Header {
        os: OsInfo {
            os_family: os.os_family.clone(),
            os_id: os.os_id.clone(),
            os_version: os.os_version.clone(),
            kernel_arch: os.kernel_arch.clone(),
            package_manager: os.package_manager.clone(),
        },
        created_at: chrono::Utc::now().to_rfc3339(),
        schema_version: SCHEMA_VERSION,
    };
    let mut header_bytes = Vec::new();
    header_bytes.extend_from_slice(MAGIC);
    header_bytes.push(FORMAT_VERSION);
    header_bytes.extend_from_slice(&serde_json::to_vec(&header)?);
    header_bytes.push(b'\n');
    Ok(header_bytes)
}

/// Writes the encrypted payload to `payload_tmp`, signs the manifest, then writes
/// header + manifest + signature + payload to `out_tmp`.
fn assemble_husk_file(
    header_bytes: &[u8],
    manifest: &mut Manifest,
    sel: &Selection,
    (signing_key, recipient): (&SigningKey, &age::x25519::Recipient),
    (payload_tmp, out_tmp): (&Path, &Path),
    warnings: &mut Vec<String>,
) -> Result<(usize, u64, u64, WriteSizes)> {
    let payload_file = create_private(payload_tmp)?;
    let (members, uncompressed, payload_len, payload_hash) =
        write_payload(payload_file, recipient, sel, warnings)?;

    manifest.payload_sha256 = crate::keys::to_hex(&payload_hash);

    let manifest_json = serde_json::to_vec(manifest)?;
    let signature = signing_key.sign(&manifest_json).to_bytes();
    let manifest_section = length_prefixed(&manifest_json);
    let signature_section = length_prefixed(&signature);

    let mut out = BufWriter::new(create_private(out_tmp)?);
    out.write_all(header_bytes)?;
    out.write_all(&manifest_section)?;
    out.write_all(&signature_section)?;
    let mut payload = File::open(payload_tmp)?;
    let copied = io::copy(&mut payload, &mut out)?;
    anyhow::ensure!(
        copied == payload_len,
        "payload temp file changed while copying"
    );
    out.into_inner().map_err(|e| e.into_error())?.sync_all()?;

    Ok((
        members,
        uncompressed,
        payload_len,
        WriteSizes {
            header: header_bytes.len() as u64,
            manifest: manifest_section.len() as u64,
            signature: signature_section.len() as u64,
        },
    ))
}

struct WriteSizes {
    header: u64,
    manifest: u64,
    signature: u64,
}

fn create_private(path: &Path) -> Result<File> {
    OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create {}", path.display()))
}

struct HashingWriter<W: Write> {
    inner: W,
    hasher: Sha256,
    len: u64,
}

impl<W: Write> Write for HashingWriter<W> {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        let n = self.inner.write(buf)?;
        self.hasher.update(&buf[..n]);
        self.len += n as u64;
        Ok(n)
    }
    fn flush(&mut self) -> io::Result<()> {
        self.inner.flush()
    }
}

fn length_prefixed(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(4 + data.len());
    out.extend_from_slice(&(data.len() as u32).to_be_bytes());
    out.extend_from_slice(data);
    out
}

fn write_payload(
    file: File,
    recipient: &age::x25519::Recipient,
    sel: &Selection,
    warnings: &mut Vec<String>,
) -> Result<(usize, u64, u64, [u8; 32])> {
    let mut out = HashingWriter {
        inner: BufWriter::new(file),
        hasher: Sha256::new(),
        len: 0,
    };

    let encryptor = age::Encryptor::with_recipients(vec![Box::new(recipient.clone())])
        .context("no age recipients")?;
    let age_stream = encryptor.wrap_output(&mut out)?;
    let encoder = zstd::Encoder::new(age_stream, ZSTD_LEVEL)?;
    let mut tar = Archive::new(encoder);
    tar.add_selection(sel, warnings)?;
    let (members, uncompressed, encoder) = tar.finish()?;
    encoder.finish()?.finish()?;
    out.inner
        .into_inner()
        .map_err(|e| e.into_error())?
        .sync_all()?;

    Ok((members, uncompressed, out.len, out.hasher.finalize().into()))
}

pub struct SignedSections {
    pub header: Header,
    pub manifest: Vec<u8>,
    pub signature: [u8; 64],
    #[allow(dead_code)]
    pub payload_offset: u64,
}

pub fn read_signed_sections(path: &Path) -> Result<SignedSections> {
    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let file_len = file.metadata()?.len();
    let mut r = BufReader::new(file);
    let mut offset = 0u64;

    let mut magic = [0u8; 5];
    r.read_exact(&mut magic)
        .context("file too short for a .husk header")?;
    if &magic[..4] != MAGIC {
        anyhow::bail!("not a .husk file (bad magic)");
    }
    if magic[4] != FORMAT_VERSION {
        anyhow::bail!(
            "unsupported format version {} (this build reads version {FORMAT_VERSION})",
            magic[4]
        );
    }
    offset += 5;

    let mut line = Vec::new();
    let n = r.by_ref().take(64 * 1024).read_until(b'\n', &mut line)?;
    if line.last() != Some(&b'\n') {
        anyhow::bail!("header is not newline-terminated");
    }
    offset += n as u64;
    let header: Header = serde_json::from_slice(&line).context("header is not valid JSON")?;

    let mut read_section = |what: &str, offset: &mut u64| -> Result<Vec<u8>> {
        let mut len = [0u8; 4];
        r.read_exact(&mut len)
            .with_context(|| format!("truncated before {what} length"))?;
        let len = u32::from_be_bytes(len) as u64;
        *offset += 4;
        if len > file_len.saturating_sub(*offset) {
            anyhow::bail!("{what} length {len} exceeds file size (corrupt file)");
        }
        let mut buf = vec![0u8; len as usize];
        r.read_exact(&mut buf)?;
        *offset += len;
        Ok(buf)
    };
    let manifest = read_section("manifest", &mut offset)?;
    let sig = read_section("signature", &mut offset)?;
    let signature: [u8; 64] = sig
        .try_into()
        .map_err(|v: Vec<u8>| anyhow::anyhow!("signature is {} bytes, expected 64", v.len()))?;

    Ok(SignedSections {
        header,
        manifest,
        signature,
        payload_offset: offset,
    })
}

#[derive(Debug, PartialEq, Eq)]
pub enum Verification {
    Pass,
    SignatureInvalid,
    PayloadHashMismatch,
    ManifestMalformed,
}

fn hash_file_from(path: &Path, offset: u64) -> Result<String> {
    use std::io::Seek;
    let mut f = File::open(path)?;
    f.seek(io::SeekFrom::Start(offset))?;
    let mut hasher = Sha256::new();
    io::copy(&mut f, &mut hasher)?;
    Ok(crate::keys::to_hex(&hasher.finalize()))
}

/// Checks the manifest signature, then that the stored payload matches the signed hash.
/// Never decrypts. Payload hash is only trusted once the signature has passed.
pub fn verify(path: &Path, key: &VerifyingKey) -> Result<(SignedSections, Verification)> {
    let parsed = read_signed_sections(path)?;
    let sig = ed25519_dalek::Signature::from_bytes(&parsed.signature);
    if key.verify_strict(&parsed.manifest, &sig).is_err() {
        return Ok((parsed, Verification::SignatureInvalid));
    }
    let Ok(manifest) = serde_json::from_slice::<Manifest>(&parsed.manifest) else {
        return Ok((parsed, Verification::ManifestMalformed));
    };
    let actual = hash_file_from(path, parsed.payload_offset)?;
    let outcome = if actual.eq_ignore_ascii_case(&manifest.payload_sha256) {
        Verification::Pass
    } else {
        Verification::PayloadHashMismatch
    };
    Ok((parsed, outcome))
}

fn build_manifest(sel: &Selection, warnings: &mut Vec<String>) -> Manifest {
    let repos = sel
        .repos
        .iter()
        .map(|r| {
            let base_commit_sha = git_raw(&r.path, &["rev-parse", "--verify", "-q", "HEAD"])
                .map(|b| String::from_utf8_lossy(&b).trim().to_string())
                .filter(|s| !s.is_empty());
            if base_commit_sha.is_none() {
                warnings.push(format!(
                    "{}: no HEAD commit (unborn branch?)",
                    r.path.display()
                ));
            }
            RepoRecord {
                path: r.path.clone(),
                remote_url: r.remote_url.clone(),
                branch: r.branch.clone(),
                base_commit_sha,
                duplicate_of: r.duplicate_of.clone(),
            }
        })
        .collect();
    let rec = |path: &PathBuf, size_bytes: u64| FileRecord {
        path: path.clone(),
        size_bytes,
    };
    Manifest {
        payload_sha256: String::new(),
        packages: sel.packages.clone(),
        repos,
        dotfiles: sel
            .dotfiles
            .iter()
            .map(|d| rec(&d.path, d.size_bytes))
            .collect(),
        compose_files: sel.compose_files.clone(),
        env_files: sel
            .env_files
            .iter()
            .map(|f| rec(&f.path, f.size_bytes))
            .collect(),
        software: sel
            .software
            .iter()
            .map(|e| SoftwareRecord {
                app: e.app.clone(),
                data: e.data.clone(),
                files: e.files.clone(),
                generated: e.generated.iter().map(|g| g.name.clone()).collect(),
            })
            .collect(),
        personal_files: sel
            .personal
            .iter()
            .map(|p| PersonalFileEntry {
                path: p.folder.join(&p.rel),
                size_bytes: p.size_bytes,
            })
            .collect(),
    }
}

struct Archive<W: Write> {
    tar: tar::Builder<W>,
    members: usize,
    bytes: u64,
}

impl<W: Write> Archive<W> {
    fn new(w: W) -> Self {
        let mut tar = tar::Builder::new(w);
        tar.follow_symlinks(false);
        Archive {
            tar,
            members: 0,
            bytes: 0,
        }
    }

    fn finish(self) -> Result<(usize, u64, W)> {
        Ok((self.members, self.bytes, self.tar.into_inner()?))
    }

    fn add_bytes(&mut self, name: &Path, data: &[u8]) -> Result<()> {
        let mut h = tar::Header::new_gnu();
        h.set_size(data.len() as u64);
        h.set_mode(0o644);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_secs());
        h.set_mtime(now);
        h.set_cksum();
        self.tar.append_data(&mut h, name, data)?;
        self.members += 1;
        self.bytes += data.len() as u64;
        Ok(())
    }

    fn add_path(&mut self, src: &Path, name: &Path, warnings: &mut Vec<String>) -> Result<()> {
        let meta = match fs::symlink_metadata(src) {
            Ok(m) => m,
            Err(e) => {
                warnings.push(format!("skipped {}: {e}", src.display()));
                return Ok(());
            }
        };
        if meta.is_file() {
            if let Err(e) = File::open(src) {
                warnings.push(format!("skipped {}: {e}", src.display()));
                return Ok(());
            }
        } else if !meta.file_type().is_symlink() {
            return Ok(());
        }
        self.tar
            .append_path_with_name(src, name)
            .with_context(|| format!("failed to archive {}", src.display()))?;
        self.members += 1;
        self.bytes += meta.len();
        Ok(())
    }

    fn add_tree(&mut self, src: &Path, prefix: &Path, warnings: &mut Vec<String>) -> Result<()> {
        let base = prefix.join(sanitize_path(src));
        let is_dir = fs::symlink_metadata(src).is_ok_and(|m| m.is_dir());
        if !is_dir {
            return self.add_path(src, &base, warnings);
        }
        let walker = WalkDir::new(src)
            .follow_links(false)
            .into_iter()
            .filter_entry(|e| !is_skipped(e));
        for entry in walker {
            match entry {
                Ok(e) if !e.file_type().is_dir() => {
                    let rel = e.path().strip_prefix(src).unwrap_or(e.path());
                    self.add_path(e.path(), &base.join(rel), warnings)?;
                }
                Ok(_) => {}
                Err(e) => warnings.push(format!("skipped entry under {}: {e}", src.display())),
            }
        }
        Ok(())
    }

    fn add_repo(
        &mut self,
        repo: &GitRepoEntry,
        skip: &Excludes,
        warnings: &mut Vec<String>,
    ) -> Result<()> {
        let root = &repo.path;
        let base = Path::new("repos").join(sanitize_path(root));

        let mut binaries = BTreeSet::new();
        for extra in [&["--cached"][..], &[][..]] {
            let mut args = vec!["diff", "--no-ext-diff", "--no-textconv", "--numstat", "-z"];
            args.extend_from_slice(extra);
            if let Some(out) = git_raw(root, &args) {
                binaries.extend(binary_paths(&out));
            }
        }

        let excludes: Vec<String> = binaries
            .iter()
            .map(|p| {
                format!(
                    ":(exclude,literal){}",
                    String::from_utf8_lossy(p.as_os_str().as_bytes())
                )
            })
            .collect();
        let diff = |extra: &[&str]| {
            let mut args = vec![
                "diff",
                "--no-ext-diff",
                "--no-textconv",
                "--no-color",
                "--src-prefix=a/",
                "--dst-prefix=b/",
            ];
            args.extend_from_slice(extra);
            if !excludes.is_empty() {
                args.push("--");
                args.push(".");
                args.extend(excludes.iter().map(String::as_str));
            }
            git_raw(root, &args)
        };
        let mut patch = Vec::new();
        for extra in [&["--cached"][..], &[][..]] {
            match diff(extra) {
                Some(d) => patch.extend_from_slice(&d),
                None => warnings.push(format!("{}: git diff failed", root.display())),
            }
        }
        if !patch.is_empty() {
            self.add_bytes(&base.join("diff.patch"), &patch)?;
        }

        match git_raw(
            root,
            &[
                "status",
                "--porcelain",
                "-z",
                "--ignored=no",
                "--untracked-files=all",
            ],
        ) {
            Some(status) => {
                for rel in discovery::untracked_paths(&status) {
                    if skip.matches(&rel, &root.join(&rel)) {
                        continue;
                    }
                    self.add_path(
                        &root.join(&rel),
                        &base.join("untracked").join(&rel),
                        warnings,
                    )?;
                }
            }
            None => warnings.push(format!("{}: git status failed", root.display())),
        }

        for rel in &binaries {
            self.add_path(
                &root.join(rel),
                &base.join("binary_changes").join(rel),
                warnings,
            )?;
        }
        Ok(())
    }

    fn add_software_entry(
        &mut self,
        entry: &crate::apps::AppConfigEntry,
        warnings: &mut Vec<String>,
    ) -> Result<()> {
        let base = Path::new("files").join(&entry.app);
        for f in &entry.files {
            self.add_path(f, &base.join(sanitize_path(f)), warnings)?;
        }
        for g in &entry.generated {
            self.add_bytes(&base.join("generated").join(&g.name), &g.contents)?;
        }
        Ok(())
    }

    fn add_personal_file(&mut self, p: &PersonalFile, warnings: &mut Vec<String>) -> Result<()> {
        let name = Path::new("personal")
            .join(sanitize_path(&p.folder))
            .join(&p.rel);
        self.add_path(&p.folder.join(&p.rel), &name, warnings)
    }

    fn add_selection(&mut self, sel: &Selection, warnings: &mut Vec<String>) -> Result<()> {
        for repo in &sel.repos {
            self.add_repo(repo, &sel.excludes, warnings)?;
        }
        for d in &sel.dotfiles {
            self.add_tree(&d.path, Path::new("dotfiles"), warnings)?;
        }
        for f in &sel.env_files {
            self.add_tree(&f.path, Path::new("env"), warnings)?;
        }
        for c in &sel.compose_files {
            self.add_tree(c, Path::new("compose"), warnings)?;
        }
        for entry in &sel.software {
            self.add_software_entry(entry, warnings)?;
        }
        for p in &sel.personal {
            self.add_personal_file(p, warnings)?;
        }
        Ok(())
    }
}

fn binary_paths(numstat_z: &[u8]) -> Vec<PathBuf> {
    let mut toks = numstat_z.split(|&b| b == 0).filter(|t| !t.is_empty());
    let mut out = Vec::new();
    while let Some(tok) = toks.next() {
        let mut parts = tok.splitn(3, |&b| b == b'\t');
        let (Some(added), Some(deleted), Some(path)) = (parts.next(), parts.next(), parts.next())
        else {
            continue;
        };
        let path = if path.is_empty() {
            toks.next();
            match toks.next() {
                Some(new) => new,
                None => break,
            }
        } else {
            path
        };
        if added == b"-" && deleted == b"-" {
            out.push(PathBuf::from(OsStr::from_bytes(path)));
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sanitize_round_trips() {
        for p in ["/home/arch/husk", "/a b/%x/.env", "/weird/ünï/😀", "/"] {
            let s = sanitize_path(Path::new(p));
            assert!(!s.contains('/'), "{s}");
            assert_eq!(unsanitize_path(&s).unwrap(), PathBuf::from(p));
        }
    }

    #[test]
    fn signed_encrypted_round_trip() {
        use ed25519_dalek::{Signature, SigningKey};
        use std::io::Read;

        let dir = std::env::temp_dir().join(format!("husk-test-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let dotfile = dir.join(".testrc");
        fs::write(&dotfile, "export SECRET_MARKER=1\n").unwrap();

        let signing = SigningKey::from_bytes(&[7u8; 32]);
        let identity = age::x25519::Identity::generate();
        let os = OsInfo {
            os_family: "arch".into(),
            os_id: "test".into(),
            os_version: String::new(),
            kernel_arch: "x86_64".into(),
            package_manager: "pacman".into(),
        };
        let sel = Selection {
            packages: vec!["foo".into()],
            dotfiles: vec![DotfileEntry {
                path: dotfile.clone(),
                size_bytes: 23,
            }],
            repos: vec![],
            compose_files: vec![],
            env_files: vec![],
            excludes: Excludes::default(),
            personal: vec![PersonalFile {
                folder: dir.clone(),
                rel: PathBuf::from("photo.jpg"),
                size_bytes: 4,
            }],
            software: vec![],
        };
        fs::write(dir.join("photo.jpg"), b"jpeg").unwrap();
        let out = dir.join("t.husk");
        write(&out, &os, &sel, &signing, &identity.to_public()).unwrap();

        let parsed = read_signed_sections(&out).unwrap();
        let sig = Signature::from_bytes(&parsed.signature);
        signing
            .verifying_key()
            .verify_strict(&parsed.manifest, &sig)
            .unwrap();
        let manifest: Manifest = serde_json::from_slice(&parsed.manifest).unwrap();
        assert_eq!(manifest.packages, vec!["foo".to_string()]);

        let raw = fs::read(&out).unwrap();
        let payload = &raw[parsed.payload_offset as usize..];
        assert!(payload.starts_with(b"age-encryption.org/v1"));
        assert!(!payload.windows(13).any(|w| w == b"SECRET_MARKER"));
        let decryptor = match age::Decryptor::new(payload).unwrap() {
            age::Decryptor::Recipients(d) => d,
            _ => panic!("expected recipient-encrypted payload"),
        };
        let reader = decryptor
            .decrypt(std::iter::once(&identity as &dyn age::Identity))
            .unwrap();
        let mut archive = tar::Archive::new(zstd::Decoder::new(reader).unwrap());
        let mut found = false;
        let mut found_personal = false;
        for entry in archive.entries().unwrap() {
            let mut entry = entry.unwrap();
            let name = entry.path().unwrap().to_string_lossy().into_owned();
            if name == format!("personal/{}/photo.jpg", sanitize_path(&dir)) {
                found_personal = true;
            }
            if name == format!("dotfiles/{}", sanitize_path(&dotfile)) {
                let mut body = String::new();
                entry.read_to_string(&mut body).unwrap();
                assert_eq!(body, "export SECRET_MARKER=1\n");
                found = true;
            }
        }
        assert!(found, "dotfile missing from decrypted payload");
        assert_eq!(manifest.personal_files.len(), 1);
        assert!(
            found_personal,
            "personal file missing from decrypted payload"
        );

        let key = signing.verifying_key();
        assert_eq!(verify(&out, &key).unwrap().1, Verification::Pass);
        let signed_hash = serde_json::from_slice::<Manifest>(&parsed.manifest)
            .unwrap()
            .payload_sha256;
        assert_eq!(signed_hash.len(), 64);

        let mut bad = raw.clone();
        let last = bad.len() - 1;
        bad[last] ^= 1;
        let bad_payload = dir.join("bad-payload.husk");
        fs::write(&bad_payload, &bad).unwrap();
        assert_eq!(
            verify(&bad_payload, &key).unwrap().1,
            Verification::PayloadHashMismatch
        );

        let mut bad = raw.clone();
        bad[parsed.payload_offset as usize - 64 - 4 - 10] ^= 1;
        let bad_manifest = dir.join("bad-manifest.husk");
        fs::write(&bad_manifest, &bad).unwrap();
        assert_eq!(
            verify(&bad_manifest, &key).unwrap().1,
            Verification::SignatureInvalid
        );

        let other = SigningKey::from_bytes(&[9u8; 32]).verifying_key();
        assert_eq!(
            verify(&out, &other).unwrap().1,
            Verification::SignatureInvalid
        );

        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn numstat_binary_detection() {
        let data = b"1\t2\ttext.rs\0-\t-\timg.png\0-\t-\t\0old.bin\0new.bin\0";
        let got = binary_paths(data);
        assert_eq!(
            got,
            vec![PathBuf::from("img.png"), PathBuf::from("new.bin")]
        );
    }
}
