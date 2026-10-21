use std::path::PathBuf;
use std::process::ExitCode;

use anyhow::Result;
use clap::{Parser, Subcommand};
use husk::commands;

#[derive(Parser)]
#[command(
    name = "husk",
    version,
    about = "recovery backup/restore tool for Linux"
)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Init,
    Backup {
        #[arg(long)]
        interactive: bool,
        #[arg(long)]
        configure: bool,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    /// Create or edit ~/.config/husk/backup.toml
    Configure,
    /// Restore from a backup at <PATH>
    Restore {
        path: PathBuf,
        #[arg(long)]
        force: bool,
        #[arg(long)]
        target_root: Option<PathBuf>,
        #[arg(long)]
        skip_packages: bool,
        #[arg(long)]
        pubkey: Option<String>,
    },
    /// Generate the signing and encryption keypairs in ~/.config/husk
    Keygen {
        #[arg(long)]
        force: bool,
    },
    /// Verify a .husk file's manifest signature (does not decrypt)
    Verify {
        path: PathBuf,
        #[arg(long)]
        pubkey: Option<String>,
    },
}

fn main() -> Result<ExitCode> {
    let cli = Cli::parse();

    let code = match cli.command {
        Command::Init => {
            commands::init::run()?;
            ExitCode::SUCCESS
        }
        Command::Backup {
            interactive,
            configure,
            output,
        } => {
            commands::backup::run(commands::backup::Args {
                interactive,
                configure,
                output,
            })?;
            ExitCode::SUCCESS
        }
        Command::Configure => {
            commands::configure::run()?;
            ExitCode::SUCCESS
        }
        Command::Restore {
            path,
            force,
            target_root,
            skip_packages,
            pubkey,
        } => commands::restore::run(&path, force, target_root, skip_packages, pubkey.as_deref())?,
        Command::Keygen { force } => {
            commands::keygen::run(force)?;
            ExitCode::SUCCESS
        }
        Command::Verify { path, pubkey } => commands::verify::run(&path, pubkey.as_deref())?,
    };
    Ok(code)
}
