use std::collections::HashMap;
use std::env;
use std::fs;
use std::process::Command;

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};

const OS_RELEASE_PATHS: [&str; 2] = ["/etc/os-release", "/usr/lib/os-release"];

#[derive(Debug, Serialize, Deserialize)]
pub struct OsInfo {
    /// "debian" | "arch"
    pub os_family: String,
    /// ID from os-release
    pub os_id: String,
    /// VERSION_ID from os-release; empty if absent (e.g. Arch rolling)
    pub os_version: String,
    /// Output of `uname -m`
    pub kernel_arch: String,
    /// "apt" | "pacman"
    pub package_manager: String,
}

pub fn detect() -> Result<OsInfo> {
    let fields = parse_os_release(&read_os_release()?);

    let os_id = fields.get("ID").cloned().unwrap_or_default();
    let id_like = fields.get("ID_LIKE").cloned().unwrap_or_default();
    let os_version = fields.get("VERSION_ID").cloned().unwrap_or_default();

    let os_family = detect_family(&os_id, &id_like)?;
    let package_manager = detect_package_manager(os_family)?;

    Ok(OsInfo {
        os_family: os_family.to_string(),
        os_id,
        os_version,
        kernel_arch: kernel_arch()?,
        package_manager: package_manager.to_string(),
    })
}

fn read_os_release() -> Result<String> {
    for path in OS_RELEASE_PATHS {
        if let Ok(contents) = fs::read_to_string(path) {
            return Ok(contents);
        }
    }
    bail!("could not read any of: {}", OS_RELEASE_PATHS.join(", "))
}

/// Parse os-release `KEY=value` lines, stripping surrounding quotes.
fn parse_os_release(contents: &str) -> HashMap<String, String> {
    contents
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('#'))
        .filter_map(|line| line.split_once('='))
        .map(|(key, value)| {
            let value = value.trim();
            let value = value
                .strip_prefix('"')
                .and_then(|v| v.strip_suffix('"'))
                .or_else(|| value.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
                .unwrap_or(value);
            (key.trim().to_string(), value.to_string())
        })
        .collect()
}

/// Map ID / ID_LIKE onto a supported family. ID takes precedence over ID_LIKE.
fn detect_family(os_id: &str, id_like: &str) -> Result<&'static str> {
    for name in std::iter::once(os_id).chain(id_like.split_whitespace()) {
        match name {
            "debian" | "ubuntu" => return Ok("debian"),
            "arch" => return Ok("arch"),
            _ => {}
        }
    }
    bail!("unsupported OS: ID={os_id:?}, ID_LIKE={id_like:?} (only Debian and Arch families are supported)")
}

/// Pick the family's package manager, confirming its binary is on PATH.
fn detect_package_manager(os_family: &str) -> Result<&'static str> {
    let (name, binary) = match os_family {
        "debian" => ("apt", "apt-get"),
        "arch" => ("pacman", "pacman"),
        other => bail!("no known package manager for OS family {other:?}"),
    };
    if !on_path(binary) {
        bail!("expected package manager {name:?} for OS family {os_family:?}, but `{binary}` is not on PATH");
    }
    Ok(name)
}

fn on_path(binary: &str) -> bool {
    env::var_os("PATH")
        .map(|paths| env::split_paths(&paths).any(|dir| dir.join(binary).is_file()))
        .unwrap_or(false)
}

fn kernel_arch() -> Result<String> {
    let output = Command::new("uname")
        .arg("-m")
        .output()
        .context("failed to run `uname -m`")?;
    if !output.status.success() {
        bail!("`uname -m` exited with {}", output.status);
    }
    Ok(String::from_utf8(output.stdout)
        .context("`uname -m` output was not valid UTF-8")?
        .trim()
        .to_string())
}
