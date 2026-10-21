//! VS Code (and the Code - OSS / VSCodium / Insiders variants).

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result};
use serde_json::json;

use super::{
    home_dir, on_path, run, str_list, AppConfigEntry, AppHandler, AppRestoreReport, RestoreCtx,
};

pub struct VsCode;

/// (config dir under ~/.config, CLI binary, label)
const VARIANTS: [(&str, &str, &str); 4] = [
    ("Code", "code", "Visual Studio Code"),
    ("Code - OSS", "code", "Code - OSS"),
    ("VSCodium", "codium", "VSCodium"),
    ("Code - Insiders", "code-insiders", "VS Code Insiders"),
];

fn user_dir(config_dir: &str) -> Result<PathBuf> {
    Ok(home_dir()?.join(".config").join(config_dir).join("User"))
}

fn detect() -> Option<(&'static str, &'static str, &'static str)> {
    let has_dir = |d: &str| user_dir(d).is_ok_and(|p| p.is_dir());
    VARIANTS
        .iter()
        .find(|(d, b, _)| has_dir(d) && on_path(b))
        .or_else(|| VARIANTS.iter().find(|(d, _, _)| has_dir(d)))
        .or_else(|| VARIANTS.iter().find(|(_, b, _)| on_path(b)))
        .copied()
}

impl AppHandler for VsCode {
    fn id(&self) -> &str {
        "vscode"
    }
    fn name(&self) -> &str {
        "VS Code (extensions, settings, keybindings, snippets)"
    }
    fn is_present(&self) -> bool {
        detect().is_some()
    }

    fn capture(&self) -> Result<AppConfigEntry> {
        let (config_dir, binary, label) = detect().context("VS Code not found")?;
        let user = user_dir(config_dir)?;

        // Exact output of `<code> --list-extensions`, in order.
        let (extensions, list_error) = if on_path(binary) {
            match run(binary, &["--list-extensions"]) {
                Ok(out) => (
                    out.lines()
                        .map(str::trim)
                        .filter(|l| !l.is_empty())
                        .map(String::from)
                        .collect(),
                    None,
                ),
                Err(e) => (Vec::new(), Some(format!("{e:#}"))),
            }
        } else {
            (
                Vec::new(),
                Some(format!(
                    "`{binary}` not on PATH; extension list unavailable"
                )),
            )
        };

        let mut files = Vec::new();
        for name in ["settings.json", "keybindings.json"] {
            let p = user.join(name);
            if p.is_file() {
                files.push(p);
            }
        }
        if let Ok(rd) = fs::read_dir(user.join("snippets")) {
            let mut snippets: Vec<PathBuf> = rd
                .filter_map(Result::ok)
                .map(|e| e.path())
                .filter(|p| p.is_file())
                .collect();
            snippets.sort();
            files.extend(snippets);
        }

        Ok(AppConfigEntry {
            app: self.id().to_string(),
            data: json!({
                "home": home_dir()?,
                "variant": label,
                "binary": binary,
                "extensions": extensions,
                "extension_list_error": list_error,
            }),
            files,
            generated: vec![],
        })
    }

    fn restore(&self, entry: &AppConfigEntry, ctx: &RestoreCtx) -> Result<AppRestoreReport> {
        let mut rep = AppRestoreReport::default();
        for f in &entry.files {
            ctx.place_file(f, &mut rep);
        }

        // The binary comes from the manifest; only run a known VS Code CLI.
        let binary = entry
            .data
            .get("binary")
            .and_then(|v| v.as_str())
            .and_then(|b| VARIANTS.iter().map(|v| v.1).find(|k| *k == b))
            .unwrap_or("code");
        let (extensions, flaglike): (Vec<String>, Vec<String>) =
            str_list(&entry.data, "extensions")
                .into_iter()
                .partition(|e| !e.starts_with('-'));
        for e in &flaglike {
            rep.failed.push(format!(
                "vscode extension {e}: looks like a flag, refusing to run it"
            ));
        }
        if extensions.is_empty() {
            return Ok(rep);
        }

        if !ctx.allow_external {
            rep.manual.push(format!(
                "{} extension(s) not installed in this mode; to install them run:",
                extensions.len()
            ));
            for e in &extensions {
                rep.manual
                    .push(format!("  {binary} --install-extension {e}"));
            }
            return Ok(rep);
        }
        if !on_path(binary) {
            rep.manual.push(format!(
                "`{binary}` is not installed on this machine. Install VS Code, then run for each \
                 extension: {binary} --install-extension <id>  ({} extensions, see manifest)",
                extensions.len()
            ));
            return Ok(rep);
        }

        // One failure (e.g. extension withdrawn from the marketplace) must not stop the rest.
        let mut installed = 0;
        for ext in &extensions {
            match run(binary, &["--install-extension", ext]) {
                Ok(_) => installed += 1,
                Err(e) => rep.failed.push(format!("vscode extension {ext}: {e:#}")),
            }
        }
        rep.ok.push(format!(
            "installed {installed}/{} VS Code extensions",
            extensions.len()
        ));
        Ok(rep)
    }
}
