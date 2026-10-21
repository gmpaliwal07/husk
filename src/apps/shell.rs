//! oh-my-zsh (theme, plugins, third-party custom plugins) and starship.

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::Result;
use serde_json::json;

use super::{
    data_home, home_dir, on_path, str_list, AppConfigEntry, AppHandler, AppRestoreReport,
    RestoreCtx,
};

pub struct ShellPlugins;

const OMZ_INSTALL: &str = r#"sh -c "$(curl -fsSL https://raw.githubusercontent.com/ohmyzsh/ohmyzsh/master/tools/install.sh)""#;

fn starship_toml(home: &Path) -> PathBuf {
    home.join(".config/starship.toml")
}

pub fn parse_zshrc(text: &str) -> (Option<String>, Vec<String>) {
    let mut theme = None;
    let mut plugins: Option<Vec<String>> = None;
    let mut in_plugins = false;
    let mut buf: Vec<String> = Vec::new();

    for raw in text.lines() {
        let line = raw.trim();
        if in_plugins {
            collect_plugin_tokens(line, &mut buf, &mut in_plugins);
            if !in_plugins && plugins.is_none() {
                plugins = Some(std::mem::take(&mut buf));
            }
            continue;
        }
        if line.starts_with('#') {
            continue;
        }
        let body = line.strip_prefix("export ").unwrap_or(line);
        if theme.is_none() {
            if let Some(v) = body.strip_prefix("ZSH_THEME=") {
                let v = v
                    .split('#')
                    .next()
                    .unwrap_or("")
                    .trim()
                    .trim_matches(|c| c == '"' || c == '\'');
                if !v.is_empty() {
                    theme = Some(v.to_string());
                }
                continue;
            }
        }
        if plugins.is_none() {
            if let Some(rest) = body.strip_prefix("plugins=(") {
                in_plugins = true;
                collect_plugin_tokens(rest, &mut buf, &mut in_plugins);
                if !in_plugins {
                    plugins = Some(std::mem::take(&mut buf));
                }
            }
        }
    }
    (theme, plugins.unwrap_or_default())
}

fn collect_plugin_tokens(s: &str, out: &mut Vec<String>, open: &mut bool) {
    let s = s.split('#').next().unwrap_or("");
    let (content, closed) = match s.find(')') {
        Some(i) => (&s[..i], true),
        None => (s, false),
    };
    out.extend(content.split_whitespace().map(String::from));
    *open = !closed;
}

fn custom_extensions(omz: &Path) -> Vec<serde_json::Value> {
    let mut found = Vec::new();
    for (kind, sub) in [("plugin", "plugins"), ("theme", "themes")] {
        let Ok(rd) = fs::read_dir(omz.join("custom").join(sub)) else {
            continue;
        };
        let mut dirs: Vec<PathBuf> = rd.filter_map(Result::ok).map(|e| e.path()).collect();
        dirs.sort();
        for dir in dirs {
            let name = dir
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            if name == "example" || !dir.join(".git").exists() {
                continue;
            }
            let url = Command::new("git")
                .arg("-C")
                .arg(&dir)
                .args(["remote", "get-url", "origin"])
                .output()
                .ok()
                .filter(|o| o.status.success())
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string());
            if let Some(url) = url.filter(|u| !u.is_empty()) {
                found.push(json!({"kind": kind, "name": name, "remote_url": url}));
            }
        }
    }
    found
}

impl AppHandler for ShellPlugins {
    fn id(&self) -> &str {
        "shell_plugins"
    }
    fn name(&self) -> &str {
        "Shell plugins (oh-my-zsh theme/plugins, starship)"
    }

    fn is_present(&self) -> bool {
        let Ok(home) = home_dir() else { return false };
        home.join(".oh-my-zsh").is_dir() || starship_toml(&home).is_file() || on_path("starship")
    }

    fn capture(&self) -> Result<AppConfigEntry> {
        let home = home_dir()?;
        let omz = home.join(".oh-my-zsh");

        let oh_my_zsh = if omz.is_dir() {
            let zshrc = fs::read_to_string(home.join(".zshrc")).unwrap_or_default();
            let (theme, plugins) = parse_zshrc(&zshrc);
            Some(json!({
                "theme": theme,
                "plugins": plugins,
                "custom": custom_extensions(&omz),
            }))
        } else {
            None
        };

        let starship_file = starship_toml(&home);
        let mut files = Vec::new();
        if starship_file.is_file() {
            files.push(starship_file);
        }

        Ok(AppConfigEntry {
            app: self.id().to_string(),
            data: json!({
                "home": home,
                "oh_my_zsh": oh_my_zsh,
                "starship_present": on_path("starship") || !files.is_empty(),
            }),
            files,
            generated: vec![],
        })
    }

    fn restore(&self, entry: &AppConfigEntry, ctx: &RestoreCtx) -> Result<AppRestoreReport> {
        let mut rep = AppRestoreReport::default();
        let home = data_home(&entry.data);

        if let Some(omz_data) = entry.data.get("oh_my_zsh").filter(|v| !v.is_null()) {
            let theme = omz_data
                .get("theme")
                .and_then(|v| v.as_str())
                .map(String::from);
            let plugins = str_list(omz_data, "plugins");
            let omz_dir = ctx.map(&home.join(".oh-my-zsh"));
            let custom = omz_data
                .get("custom")
                .and_then(|v| v.as_array())
                .cloned()
                .unwrap_or_default();

            if !omz_dir.is_dir() {
                rep.manual.push(format!(
                    "oh-my-zsh is not installed. husk never runs `curl | sh` for you; to install it run:\n    {OMZ_INSTALL}\n    then re-run `husk restore` to bring back its custom plugins/themes"
                ));
            } else {
                // .zshrc is restored by the dotfiles category; only verify it matches.
                let zshrc = ctx.map(&home.join(".zshrc"));
                match fs::read_to_string(&zshrc) {
                    Ok(text) => {
                        let (t, p) = parse_zshrc(&text);
                        if t == theme && p == plugins {
                            rep.ok.push(format!(
                                ".zshrc already has captured oh-my-zsh theme {:?} and {} plugin(s)",
                                theme.as_deref().unwrap_or("(none)"),
                                plugins.len()
                            ));
                        } else {
                            rep.manual.push(format!(
                                "{} does not match the captured oh-my-zsh settings (theme {:?}, plugins {:?}); \
                                 restore the dotfiles category or edit it by hand",
                                zshrc.display(),
                                theme.as_deref().unwrap_or("(none)"),
                                plugins
                            ));
                        }
                    }
                    Err(_) => rep.manual.push(format!(
                        "{} not found; captured oh-my-zsh theme {:?}, plugins {:?}",
                        zshrc.display(),
                        theme.as_deref().unwrap_or("(none)"),
                        plugins
                    )),
                }

                for c in &custom {
                    let (Some(kind), Some(name), Some(url)) = (
                        c.get("kind").and_then(|v| v.as_str()),
                        c.get("name").and_then(|v| v.as_str()),
                        c.get("remote_url").and_then(|v| v.as_str()),
                    ) else {
                        continue;
                    };
                    let safe_name = !name.is_empty() && !name.contains('/') && name != "..";
                    if !matches!(kind, "plugin" | "theme") || !safe_name {
                        rep.failed
                            .push(format!("oh-my-zsh {kind} {name}: unexpected name, skipped"));
                        continue;
                    }
                    let dest = omz_dir.join("custom").join(format!("{kind}s")).join(name);
                    if dest.exists() {
                        rep.ok
                            .push(format!("oh-my-zsh {kind} {name} already present"));
                    } else if !ctx.allow_external {
                        rep.manual
                            .push(format!("git clone {url} {}", dest.display()));
                    } else {
                        let out = Command::new("git")
                            .args(["clone", "--quiet", "--", url])
                            .arg(&dest)
                            .env("GIT_TERMINAL_PROMPT", "0")
                            .env("GIT_ALLOW_PROTOCOL", "file:git:http:https:ssh")
                            .output();
                        match out {
                            Ok(o) if o.status.success() => {
                                rep.ok.push(format!("cloned oh-my-zsh {kind} {name}"))
                            }
                            Ok(o) => rep.failed.push(format!(
                                "oh-my-zsh {kind} {name}: git clone {url}: {}",
                                String::from_utf8_lossy(&o.stderr).trim()
                            )),
                            Err(e) => rep.failed.push(format!("oh-my-zsh {kind} {name}: {e}")),
                        }
                    }
                }
            }
        }

        for f in &entry.files {
            ctx.place_file(f, &mut rep);
        }
        let wants_starship = entry
            .data
            .get("starship_present")
            .and_then(|v| v.as_bool())
            .unwrap_or(false);
        if wants_starship && !on_path("starship") {
            rep.manual.push(
                "starship binary is not installed: install it (e.g. `pacman -S starship`, \
                 `apt install starship`, or https://starship.rs) - its config was restored"
                    .into(),
            );
        }
        Ok(rep)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_theme_and_single_line_plugins() {
        let z = "export ZSH=\"$HOME/.oh-my-zsh\"\nZSH_THEME=\"robbyrussell\"\nplugins=(git npm docker)\nsource $ZSH/oh-my-zsh.sh\n";
        let (t, p) = parse_zshrc(z);
        assert_eq!(t.as_deref(), Some("robbyrussell"));
        assert_eq!(p, ["git", "npm", "docker"]);
    }

    #[test]
    fn parses_multiline_plugins_comments_and_skips_commented_lines() {
        let z = "# ZSH_THEME=\"commented\"\nZSH_THEME='agnoster' # my theme\n# plugins=(nope)\nplugins=(\n  git # vcs\n  zsh-autosuggestions\n  # fzf\n  z\n)\nplugins=(second ignored)\n";
        let (t, p) = parse_zshrc(z);
        assert_eq!(t.as_deref(), Some("agnoster"));
        assert_eq!(p, ["git", "zsh-autosuggestions", "z"]);
    }

    #[test]
    fn missing_values_are_empty() {
        let (t, p) = parse_zshrc("export PATH=$PATH:/x\n");
        assert_eq!(t, None);
        assert!(p.is_empty());
    }
}
