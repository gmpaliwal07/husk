//! Globally installed developer tools: npm -g, pipx, cargo install.

use anyhow::Result;
use serde_json::json;

use super::{on_path, run, AppConfigEntry, AppHandler, AppRestoreReport, RestoreCtx};

pub struct DevTools;

type Pkgs = Vec<(String, String)>;
type ArgsBuilder = fn(&str, &str) -> Vec<String>;

/// `npm ls -g --depth=0 --json` -> (name, version), without npm/corepack themselves.
pub fn parse_npm(json_text: &str) -> Pkgs {
    let Ok(v) = serde_json::from_str::<serde_json::Value>(json_text) else {
        return vec![];
    };
    let Some(deps) = v.get("dependencies").and_then(|d| d.as_object()) else {
        return vec![];
    };
    let mut out: Pkgs = deps
        .iter()
        .filter(|(name, _)| !["npm", "corepack"].contains(&name.as_str()))
        .map(|(n, d)| {
            (
                n.clone(),
                d.get("version")
                    .and_then(|x| x.as_str())
                    .unwrap_or("")
                    .to_string(),
            )
        })
        .collect();
    out.sort();
    out
}

/// `pipx list --short` lines: `name version`.
pub fn parse_pipx(out: &str) -> Pkgs {
    out.lines()
        .filter_map(|l| {
            let mut it = l.split_whitespace();
            Some((it.next()?.to_string(), it.next().unwrap_or("").to_string()))
        })
        .collect()
}

/// `cargo install --list`: registry installs are unindented `name vX.Y.Z:` lines.
pub fn parse_cargo(out: &str) -> Pkgs {
    out.lines()
        .filter(|l| !l.starts_with(char::is_whitespace) && l.ends_with(':'))
        .filter_map(|l| {
            let l = l.trim_end_matches(':');
            if l.contains('(') {
                return None;
            }
            let mut it = l.split_whitespace();
            let name = it.next()?;
            let ver = it.next()?.trim_start_matches('v');
            Some((name.to_string(), ver.to_string()))
        })
        .collect()
}

fn gather() -> (Pkgs, Pkgs, Pkgs) {
    let npm = if on_path("npm") {
        std::process::Command::new("npm")
            .args(["ls", "-g", "--depth=0", "--json"])
            .output()
            .map(|o| parse_npm(&String::from_utf8_lossy(&o.stdout)))
            .unwrap_or_default()
    } else {
        vec![]
    };
    let pipx = if on_path("pipx") {
        run("pipx", &["list", "--short"])
            .map(|o| parse_pipx(&o))
            .unwrap_or_default()
    } else {
        vec![]
    };
    let cargo = if on_path("cargo") {
        run("cargo", &["install", "--list"])
            .map(|o| parse_cargo(&o))
            .unwrap_or_default()
    } else {
        vec![]
    };
    (npm, pipx, cargo)
}

fn to_json(p: &Pkgs) -> Vec<serde_json::Value> {
    p.iter()
        .map(|(n, v)| json!({"name": n, "version": v}))
        .collect()
}

fn from_json(data: &serde_json::Value, key: &str) -> Pkgs {
    data.get(key)
        .and_then(|v| v.as_array())
        .map(|a| {
            a.iter()
                .filter_map(|x| {
                    Some((
                        x.get("name")?.as_str()?.to_string(),
                        x.get("version")
                            .and_then(|v| v.as_str())
                            .unwrap_or("")
                            .to_string(),
                    ))
                })
                .collect()
        })
        .unwrap_or_default()
}

impl AppHandler for DevTools {
    fn id(&self) -> &str {
        "dev_tools"
    }
    fn name(&self) -> &str {
        "Global dev tools (npm -g, pipx, cargo install)"
    }
    fn is_present(&self) -> bool {
        let (n, p, c) = gather();
        !(n.is_empty() && p.is_empty() && c.is_empty())
    }

    fn capture(&self) -> Result<AppConfigEntry> {
        let (npm, pipx, cargo) = gather();
        Ok(AppConfigEntry {
            app: self.id().to_string(),
            data: json!({ "npm": to_json(&npm), "pipx": to_json(&pipx), "cargo": to_json(&cargo) }),
            files: vec![],
            generated: vec![],
        })
    }

    fn restore(&self, entry: &AppConfigEntry, ctx: &RestoreCtx) -> Result<AppRestoreReport> {
        let mut rep = AppRestoreReport::default();
        // (tool binary, install args builder, packages)
        let groups: [(&str, Pkgs, ArgsBuilder); 3] = [
            ("npm", from_json(&entry.data, "npm"), |n, v| {
                vec![
                    "install".into(),
                    "-g".into(),
                    if v.is_empty() {
                        n.into()
                    } else {
                        format!("{n}@{v}")
                    },
                ]
            }),
            ("pipx", from_json(&entry.data, "pipx"), |n, _| {
                vec!["install".into(), n.into()]
            }),
            ("cargo", from_json(&entry.data, "cargo"), |n, v| {
                let mut a = vec!["install".into(), "--locked".into(), n.to_string()];
                if !v.is_empty() {
                    a.extend(["--version".into(), v.to_string()]);
                }
                a
            }),
        ];

        for (tool, pkgs, args) in groups {
            if pkgs.is_empty() {
                continue;
            }
            let (pkgs, rejected): (Pkgs, Pkgs) = pkgs
                .into_iter()
                .partition(|(n, v)| !n.starts_with('-') && !v.starts_with('-'));
            for (n, _) in &rejected {
                rep.failed.push(format!(
                    "{tool} {n}: package name/version looks like a flag, refusing to run it"
                ));
            }
            if pkgs.is_empty() {
                continue;
            }
            let runnable = ctx.allow_external && on_path(tool);
            if !runnable {
                let why = if on_path(tool) {
                    "not run in this mode"
                } else {
                    "not installed here"
                };
                rep.manual.push(format!(
                    "{} {tool} package(s) not installed ({why}); run:",
                    pkgs.len()
                ));
                for (n, v) in &pkgs {
                    rep.manual
                        .push(format!("  {tool} {}", args(n, v).join(" ")));
                }
                continue;
            }
            let mut done = 0;
            for (n, v) in &pkgs {
                let a = args(n, v);
                let a: Vec<&str> = a.iter().map(String::as_str).collect();
                match run(tool, &a) {
                    Ok(_) => done += 1,
                    Err(e) => rep.failed.push(format!("{tool} {n}: {e:#}")),
                }
            }
            rep.ok.push(format!(
                "{tool}: installed {done}/{} global package(s)",
                pkgs.len()
            ));
        }
        Ok(rep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn npm_json() {
        let j = r#"{"dependencies":{"npm":{"version":"10.0.0"},"typescript":{"version":"5.4.2"},"corepack":{"version":"0.1"},"@angular/cli":{"version":"1.0.0"}}}"#;
        let got = parse_npm(j);
        assert_eq!(
            got,
            vec![
                ("@angular/cli".into(), "1.0.0".into()),
                ("typescript".into(), "5.4.2".into())
            ]
        );
        assert!(parse_npm("not json").is_empty());
    }

    #[test]
    fn cargo_list_skips_path_installs() {
        let out = "ripgrep v14.1.0:\n    rg\nhusk v0.1.0 (/home/a/husk):\n    husk\nfd-find v9.0.0:\n    fd\n";
        assert_eq!(
            parse_cargo(out),
            vec![
                ("ripgrep".into(), "14.1.0".into()),
                ("fd-find".into(), "9.0.0".into())
            ]
        );
    }

    #[test]
    fn pipx_short() {
        assert_eq!(parse_pipx("black 24.2.0\nhttpie 3.2.2\n").len(), 2);
    }
}
