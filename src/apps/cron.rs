//! The user's crontab.

use std::io::Write;
use std::path::Path;
use std::process::{Command, Stdio};

use anyhow::{bail, Context, Result};
use serde_json::json;

use super::{
    home_dir, on_path, AppConfigEntry, AppHandler, AppRestoreReport, GeneratedFile, RestoreCtx,
};

pub struct Crontab;

const FILE: &str = "crontab";

fn current() -> Option<String> {
    if !on_path("crontab") {
        return None;
    }

    let out = Command::new("crontab").arg("-l").output().ok()?;

    if !out.status.success() {
        return None;
    }

    let text = String::from_utf8_lossy(&out.stdout).into_owned();
    (!text.trim().is_empty()).then_some(text)
}

impl AppHandler for Crontab {
    fn id(&self) -> &str {
        "crontab"
    }
    fn name(&self) -> &str {
        "User crontab"
    }
    /// Restoring replaces the live crontab, so this one is opt-in.
    fn default_enabled(&self) -> bool {
        false
    }
    fn is_present(&self) -> bool {
        current().is_some()
    }

    fn capture(&self) -> Result<AppConfigEntry> {
        let text = current().context("no crontab to capture")?;
        let jobs: usize = text
            .lines()
            .filter(|l| !l.trim().is_empty() && !l.trim_start().starts_with('#'))
            .count();
        Ok(AppConfigEntry {
            app: self.id().to_string(),
            data: json!({ "home": home_dir()?, "jobs": jobs }),
            files: vec![],
            generated: vec![GeneratedFile {
                name: FILE.into(),
                contents: text.into_bytes(),
            }],
        })
    }

    fn restore(&self, entry: &AppConfigEntry, ctx: &RestoreCtx) -> Result<AppRestoreReport> {
        let mut rep = AppRestoreReport::default();

        let Some(bytes) = ctx.generated_bytes(FILE) else {
            rep.failed.push("crontab missing from payload".into());
            return Ok(rep);
        };

        let wanted = String::from_utf8_lossy(&bytes).into_owned();
        let home = super::data_home(&entry.data);

        if current().as_deref() == Some(wanted.as_str()) {
            rep.ok.push("crontab already identical".into());
            return Ok(rep);
        }

        if !ctx.allow_external || !on_path("crontab") {
            let staged = ctx.map(&home.join(format!("crontab.husk-captured-{}", ctx.timestamp())));
            match write_captured(&staged, &wanted) {
                Ok(()) => rep.manual.push(format!(
                    "crontab not installed (would replace the live crontab). \
                     Captured copy: {} - install with `crontab {}`",
                    staged.display(),
                    staged.display()
                )),
                Err(e) => rep
                    .failed
                    .push(format!("crontab: cannot save captured copy: {e}")),
            }
            return Ok(rep);
        }

        if let Some(existing) = current() {
            let backup = ctx.map(&home.join(format!("crontab.husk-backup-{}", ctx.timestamp())));
            if let Err(e) = write_captured(&backup, &existing) {
                rep.failed.push(format!(
                    "crontab: cannot back up existing crontab ({e}); not replacing"
                ));
                return Ok(rep);
            }
            rep.ok
                .push(format!("existing crontab saved to {}", backup.display()));
        }

        match install(&wanted) {
            Ok(()) => rep.ok.push("crontab installed".into()),
            Err(e) => rep.failed.push(format!("crontab: {e:#}")),
        }

        Ok(rep)
    }
}

fn write_captured(path: &Path, contents: &str) -> Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(path, contents)?;
    Ok(())
}

fn install(text: &str) -> Result<()> {
    let mut child = Command::new("crontab")
        .arg("-")
        .stdin(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .context("cannot run crontab")?;
    child
        .stdin
        .take()
        .context("no stdin")?
        .write_all(text.as_bytes())?;
    let out = child.wait_with_output()?;
    if !out.status.success() {
        bail!("{}", String::from_utf8_lossy(&out.stderr).trim());
    }
    Ok(())
}
