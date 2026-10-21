# Husk

Back up your Linux setup into one signed, encrypted file, and restore it on a fresh install.

```
husk backup                 # before anything goes wrong
husk restore backup.husk    # on the new machine
```

## What it captures

- **Packages:** explicitly installed (`pacman` / `apt`)
- **Git repos:** uncommitted diffs and untracked files
- **Dotfiles:** shell configs, `.gitconfig`, plus any you add
- **Env and compose files:** captured, but sensitive
- **App config:** VS Code, oh-my-zsh, starship, Flatpak, GNOME, global dev tools (`npm -g`, `pipx`, `cargo install`), crontab (opt-in)
- **Personal files:** opt-in, with size caps

Never captured: passwords, cookies, session tokens, SSH/GPG private keys, browser history.

## Install

Needs [Rust](https://www.rust-lang.org/tools/install).

```bash
cargo install --git https://github.com/gmpaliwal07/husk.git
```

Uninstall with `cargo uninstall husk`. Keys and config live in `~/.config/husk/`.

## Usage

```bash
husk keygen                 # create signing + recovery keys
husk configure              # choose categories, paths, exclusions
husk backup                 # write a .husk file
husk verify backup.husk     # check integrity without restoring
husk restore backup.husk    # check compatibility, show a plan, ask, then write
```

For unattended runs, set `auto_confirm` in the config and add `husk backup` to cron.

**Keep copies off the machine.** Husk only writes locally. Copy the `.husk` file and `~/.config/husk/recipient.key` somewhere safe. Without that key, backups can't be decrypted. Guard `signing.key` too: anyone with it can forge a backup that you'd trust.

## How it works

A `.husk` file is a plaintext header (OS info), a signed manifest, an Ed25519 signature, and an `age`-encrypted payload. Restore checks compatibility, verifies the signature, decrypts, shows the plan, and asks before writing. Replaced files are saved as `<path>.husk-backup-<timestamp>`.

`--pubkey` makes `verify` and `restore` trust a key other than your own, so use it only for keys you trust. `restore` asks for confirmation when it doesn't match yours.

## Status

Debian and Arch-based distros on x86_64. Not production-hardened: keep your backups as a second copy.
