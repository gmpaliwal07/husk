//! Flatpak applications (ids + the remote they came from).
use anyhow::Result;
use serde_json::json;

use super::{on_path, run, AppConfigEntry, AppHandler, AppRestoreReport, RestoreCtx};

pub struct Flatpak;

/// Parse `flatpak list --app --columns=application,origin` (tab separated).
pub fn parse_list(out: &str) -> Vec<(String, String)> {
    out.lines()
        .filter_map(|l| {
            let mut it = l.split('\t');
            let id = it.next()?.trim();
            let remote = it.next().unwrap_or("").trim();
            (!id.is_empty()).then(|| (id.to_string(), remote.to_string()))
        })
        .collect()
}

fn installed() -> Vec<(String, String)> {
    if !on_path("flatpak") {
        return vec![];
    }
    run(
        "flatpak",
        &["list", "--app", "--columns=application,origin"],
    )
    .map(|o| parse_list(&o))
    .unwrap_or_default()
}

impl AppHandler for Flatpak {
    fn id(&self) -> &str {
        "flatpak"
    }
    fn name(&self) -> &str {
        "Flatpak applications"
    }
    fn is_present(&self) -> bool {
        !installed().is_empty()
    }

    fn capture(&self) -> Result<AppConfigEntry> {
        let apps: Vec<_> = installed()
            .into_iter()
            .map(|(id, remote)| json!({"id": id, "remote": remote}))
            .collect();
        Ok(AppConfigEntry {
            app: self.id().to_string(),
            data: json!({ "apps": apps }),
            files: vec![],
            generated: vec![],
        })
    }

    fn restore(&self, entry: &AppConfigEntry, ctx: &RestoreCtx) -> Result<AppRestoreReport> {
        let mut rep = AppRestoreReport::default();
        let apps = entry
            .data
            .get("apps")
            .and_then(|v| v.as_array())
            .cloned()
            .unwrap_or_default();
        let all: Vec<(String, String)> = apps
            .iter()
            .filter_map(|a| {
                let remote = a
                    .get("remote")
                    .and_then(|r| r.as_str())
                    .filter(|r| !r.is_empty());
                Some((
                    a.get("id")?.as_str()?.to_string(),
                    remote.unwrap_or("flathub").to_string(),
                ))
            })
            .collect();
        let (pairs, rejected): (Vec<_>, Vec<_>) = all
            .into_iter()
            .partition(|(id, remote)| !id.starts_with('-') && !remote.starts_with('-'));
        for (id, _) in &rejected {
            rep.failed.push(format!(
                "flatpak {id}: id/remote looks like a flag, refusing to run it"
            ));
        }
        if pairs.is_empty() {
            return Ok(rep);
        }
        if !ctx.allow_external || !on_path("flatpak") {
            let why = if on_path("flatpak") {
                "not run in this mode"
            } else {
                "flatpak is not installed here"
            };
            rep.manual.push(format!(
                "{} Flatpak app(s) not installed ({why}); run:",
                pairs.len()
            ));
            for (id, remote) in &pairs {
                rep.manual
                    .push(format!("  flatpak install -y {remote} {id}"));
            }
            return Ok(rep);
        }
        let mut done = 0;
        for (id, remote) in &pairs {
            match run(
                "flatpak",
                &["install", "-y", "--noninteractive", remote, id],
            ) {
                Ok(_) => done += 1,
                Err(e) => rep.failed.push(format!("flatpak {id}: {e:#}")),
            }
        }
        rep.ok
            .push(format!("installed {done}/{} Flatpak apps", pairs.len()));
        Ok(rep)
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn parses_list() {
        let got =
            super::parse_list("org.mozilla.firefox\tflathub\ncom.spotify.Client\tflathub\n\n");
        assert_eq!(got.len(), 2);
        assert_eq!(got[0], ("org.mozilla.firefox".into(), "flathub".into()));
    }
}
