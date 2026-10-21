//! GNOME / dconf settings (`dconf dump /`).

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use serde_json::json;

use super::{
    home_dir, on_path, run, AppConfigEntry, AppHandler, AppRestoreReport, GeneratedFile, RestoreCtx,
};

pub struct GnomeSettings;

const DUMP: &str = "dconf.ini";

fn dump() -> Option<String> {
    if !on_path("dconf") {
        return None;
    }
    run("dconf", &["dump", "/"])
        .ok()
        .filter(|s| !s.trim().is_empty())
}

impl AppHandler for GnomeSettings {
    fn id(&self) -> &str {
        "gnome_settings"
    }
    fn name(&self) -> &str {
        "GNOME / dconf desktop settings"
    }
    fn is_present(&self) -> bool {
        dump().is_some()
    }

    fn capture(&self) -> Result<AppConfigEntry> {
        let text = dump().context("`dconf dump /` produced nothing")?;
        let sections = text.lines().filter(|l| l.starts_with('[')).count();
        Ok(AppConfigEntry {
            app: self.id().to_string(),
            data: json!({ "home": home_dir()?, "sections": sections, "bytes": text.len() }),
            files: vec![],
            generated: vec![GeneratedFile {
                name: DUMP.into(),
                contents: text.into_bytes(),
            }],
        })
    }

    fn restore(&self, entry: &AppConfigEntry, ctx: &RestoreCtx) -> Result<AppRestoreReport> {
        let mut rep = AppRestoreReport::default();
        let Some(contents) = ctx.generated_bytes(DUMP) else {
            rep.failed.push("dconf dump missing from payload".into());
            return Ok(rep);
        };
        let home = super::data_home(&entry.data);

        if !ctx.allow_external || !on_path("dconf") {
            let out = ctx.map(&home.join(format!(
                ".config/husk/dconf-captured-{}.ini",
                ctx.timestamp()
            )));
            match write_bytes(&out, &contents) {
                Ok(()) => rep.manual.push(format!(
                    "dconf settings were not applied (this would overwrite live desktop settings). \
                     Saved the captured dump to {}; apply with: dconf load / < {}",
                    out.display(),
                    out.display()
                )),
                Err(e) => rep
                    .failed
                    .push(format!("dconf: cannot save dump to {}: {e}", out.display())),
            }
            return Ok(rep);
        }

        // Loading replaces keys across the whole database: snapshot the current state first.
        if let Some(current) = dump() {
            let saved_to = ctx.map(&home.join(format!(
                ".config/husk/dconf-before-restore-{}.ini",
                ctx.timestamp()
            )));
            match write_bytes(&saved_to, current.as_bytes()) {
                Ok(()) => rep.ok.push(format!(
                    "saved current dconf settings to {}",
                    saved_to.display()
                )),
                Err(e) => {
                    rep.failed.push(format!(
                        "dconf: cannot snapshot current settings ({e}); not loading"
                    ));
                    return Ok(rep);
                }
            }
        }
        match load(&contents) {
            Ok(()) => rep.ok.push("dconf settings loaded".into()),
            Err(e) => rep.failed.push(format!("dconf load: {e:#}")),
        }
        Ok(rep)
    }
}

fn write_bytes(path: &Path, contents: &[u8]) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    Ok(())
}

fn load(contents: &[u8]) -> Result<()> {
    let mut child = Command::new("dconf")
        .args(["load", "/"])
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("cannot run dconf")?;
    child
        .stdin
        .take()
        .context("no stdin")?
        .write_all(contents)?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}
