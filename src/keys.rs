//! Key management: Ed25519 signing key + age X25519 identity, under ~/.config/husk/ (mode 0600).
use std::env;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;

use age::secrecy::ExposeSecret;
use anyhow::{bail, Context, Result};
use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;

const IDENTITY_PREFIX: &str = "AGE-SECRET-KEY-";

pub struct KeyPaths {
    pub dir: PathBuf,
    pub signing: PathBuf,
    pub identity: PathBuf,
    pub recipient: PathBuf,
}

impl KeyPaths {
    pub fn new() -> Result<Self> {
        let home = env::var_os("HOME").context("$HOME is not set")?;
        let dir = PathBuf::from(home).join(".config/husk");
        Ok(KeyPaths {
            signing: dir.join("signing.key"),
            identity: dir.join("recipient.key"),
            recipient: dir.join("recipient.pub"),
            dir,
        })
    }
}

pub fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

pub fn from_hex(s: &str) -> Result<Vec<u8>> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        bail!("invalid hex string");
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).context("invalid hex string"))
        .collect()
}

pub struct Generated {
    pub signing_pubkey_hex: String,
    pub recipient: String,
}

/// Generate both keypairs and write them.keys unless `force`.
pub fn generate(paths: &KeyPaths, force: bool) -> Result<Generated> {
    let existing: Vec<&Path> = [&paths.signing, &paths.identity, &paths.recipient]
        .into_iter()
        .map(PathBuf::as_path)
        .filter(|p| p.exists())
        .collect();
    if !existing.is_empty() && !force {
        let list: Vec<String> = existing.iter().map(|p| p.display().to_string()).collect();
        bail!(
            "keys already exist: {}\nOverwriting would orphan every backup made with them. \
             Re-run with --force if you really mean it.",
            list.join(", ")
        );
    }

    fs::DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(&paths.dir)
        .with_context(|| format!("cannot create {}", paths.dir.display()))?;

    let signing = SigningKey::generate(&mut OsRng);
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();

    write_private(
        &paths.signing,
        format!("{}\n", to_hex(&signing.to_bytes())).as_bytes(),
    )?;
    write_private(
        &paths.identity,
        format!(
            "# husk age identity (PRIVATE the recovery secret for your backups)\n\
             # public key: {recipient}\n{}\n",
            identity.to_string().expose_secret()
        )
        .as_bytes(),
    )?;
    write_private(&paths.recipient, format!("{recipient}\n").as_bytes())?;

    Ok(Generated {
        signing_pubkey_hex: to_hex(signing.verifying_key().as_bytes()),
        recipient,
    })
}

/// Write with mode 0600 from creation, and force if the file already existed.
fn write_private(path: &Path, data: &[u8]) -> Result<()> {
    let mut f = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot write {}", path.display()))?;
    f.set_permissions(fs::Permissions::from_mode(0o600))?;
    f.write_all(data)?;
    f.sync_all()?;
    Ok(())
}

pub fn load_signing_key(paths: &KeyPaths) -> Result<SigningKey> {
    let text = fs::read_to_string(&paths.signing).with_context(|| {
        format!(
            "cannot read signing key {} run `husk keygen` first",
            paths.signing.display()
        )
    })?;
    let seed: [u8; 32] = from_hex(&text)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("{} is not a 32-byte hex key", paths.signing.display()))?;
    Ok(SigningKey::from_bytes(&seed))
}

/// The public age recipient to encrypt to. Prefers `recipient.pub`
pub fn load_recipient(paths: &KeyPaths) -> Result<age::x25519::Recipient> {
    let missing = || {
        format!(
            "no age recipient found ({} or {}) run `husk keygen` first",
            paths.recipient.display(),
            paths.identity.display()
        )
    };
    if let Ok(text) = fs::read_to_string(&paths.recipient) {
        return age::x25519::Recipient::from_str(text.trim())
            .map_err(|e| anyhow::anyhow!("{} is invalid: {e}", paths.recipient.display()));
    }
    let text = fs::read_to_string(&paths.identity).with_context(missing)?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with(IDENTITY_PREFIX))
        .with_context(|| format!("no age identity in {}", paths.identity.display()))?;
    let identity = age::x25519::Identity::from_str(line)
        .map_err(|e| anyhow::anyhow!("{} is invalid: {e}", paths.identity.display()))?;
    Ok(identity.to_public())
}

/// The private age identity needed to decrypt. This is the file `husk keygen`
pub fn load_identity(paths: &KeyPaths) -> Result<age::x25519::Identity> {
    let text = fs::read_to_string(&paths.identity).with_context(|| {
        format!(
            "cannot read {}.\nThis is the identity file you were told to back up separately \
             when you ran `husk keygen` it is the only way to decrypt a backup. Copy it back \
             to that path (mode 0600) and retry.",
            paths.identity.display()
        )
    })?;
    let line = text
        .lines()
        .map(str::trim)
        .find(|l| l.starts_with(IDENTITY_PREFIX))
        .with_context(|| format!("no age identity found in {}", paths.identity.display()))?;
    age::x25519::Identity::from_str(line)
        .map_err(|e| anyhow::anyhow!("{} is invalid: {e}", paths.identity.display()))
}

pub fn parse_verifying_key(hex: &str) -> Result<VerifyingKey> {
    let bytes: [u8; 32] = from_hex(hex)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("public key must be 32 bytes (64 hex chars)"))?;
    VerifyingKey::from_bytes(&bytes).context("not a valid Ed25519 public key")
}
