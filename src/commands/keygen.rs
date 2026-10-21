use anyhow::Result;

use crate::keys::{self, KeyPaths};

pub fn run(force: bool) -> Result<()> {
    let paths = KeyPaths::new()?;
    let generated = keys::generate(&paths, force)?;

    println!("Signing public key (Ed25519, hex) - give this to `husk verify --pubkey`:");
    println!("  {}", generated.signing_pubkey_hex);
    println!();
    println!("Encryption recipient (age X25519 public key):");
    println!("  {}", generated.recipient);
    println!();
    println!("Written (mode 0600):");
    println!("  {}   signing private key", paths.signing.display());
    println!("  {}  age private identity", paths.identity.display());
    println!("  {}  age public recipient", paths.recipient.display());
    println!();
    println!(
        "!! IMPORTANT: back up {} SEPARATELY from this machine",
        paths.identity.display()
    );
    println!("!! (a password manager, not the same disk or pendrive as your backups).");
    println!("!! It is the only way to decrypt your backups. If it is lost, every");
    println!("!! .husk file made with it is permanently unreadable.");
    println!("!! `husk backup` only needs recipient.pub, so once recipient.key is safely");
    println!("!! stored elsewhere you can delete it from this machine.");
    Ok(())
}
