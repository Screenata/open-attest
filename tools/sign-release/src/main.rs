use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use ed25519_dalek::{Signer, SigningKey, VerifyingKey};
use std::fs;
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "sign-release", about = "open-attest release signing helper")]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a fresh Ed25519 keypair. Writes the 32-byte public key to
    /// --out-pub and prints the 32-byte private seed (hex) to stdout.
    ///
    /// Add the printed seed to GitHub Actions secrets as RELEASE_PRIVKEY.
    /// Commit the public key file to the repo.
    Keygen {
        #[arg(long)]
        out_pub: PathBuf,
    },
    /// Sign a file with the Ed25519 private seed and write the hex-encoded
    /// 64-byte signature to --out.
    Sign {
        /// Hex-encoded 32-byte Ed25519 seed (private key).
        #[arg(long, env = "RELEASE_PRIVKEY")]
        key: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        out: PathBuf,
    },
    /// Verify a hex-encoded signature against a file using the given public key.
    /// Useful for local sanity-checking.
    Verify {
        /// Path to 32-byte raw public key file.
        #[arg(long)]
        pubkey: PathBuf,
        #[arg(long)]
        input: PathBuf,
        /// Path to hex-encoded signature file.
        #[arg(long)]
        sig: PathBuf,
    },
}

fn main() -> Result<()> {
    match Cli::parse().command {
        Commands::Keygen { out_pub } => keygen(&out_pub),
        Commands::Sign { key, input, out } => sign(&key, &input, &out),
        Commands::Verify { pubkey, input, sig } => verify(&pubkey, &input, &sig),
    }
}

fn keygen(out_pub: &PathBuf) -> Result<()> {
    let mut csprng = rand::rngs::OsRng;
    let signing = SigningKey::generate(&mut csprng);
    let verifying: VerifyingKey = signing.verifying_key();

    if let Some(parent) = out_pub.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(out_pub, verifying.to_bytes())
        .with_context(|| format!("write pubkey to {}", out_pub.display()))?;

    let seed_hex = hex::encode(signing.to_bytes());

    eprintln!("Wrote public key to {}", out_pub.display());
    eprintln!("Public key (hex): {}", hex::encode(verifying.to_bytes()));
    eprintln!();
    eprintln!("Private seed (hex) — set as GitHub Actions secret RELEASE_PRIVKEY:");
    println!("{seed_hex}");
    Ok(())
}

fn sign(key_hex: &str, input: &PathBuf, out: &PathBuf) -> Result<()> {
    let seed = hex::decode(key_hex.trim()).context("decode private seed hex")?;
    if seed.len() != 32 {
        bail!("private seed must be exactly 32 bytes, got {}", seed.len());
    }
    let signing = SigningKey::from_bytes(&seed.try_into().unwrap());

    let bytes = fs::read(input).with_context(|| format!("read {}", input.display()))?;
    let sig = signing.sign(&bytes);

    if let Some(parent) = out.parent() {
        fs::create_dir_all(parent).ok();
    }
    fs::write(out, hex::encode(sig.to_bytes()))
        .with_context(|| format!("write signature to {}", out.display()))?;
    eprintln!(
        "Signed {} ({} bytes) -> {}",
        input.display(),
        bytes.len(),
        out.display()
    );
    Ok(())
}

fn verify(pubkey: &PathBuf, input: &PathBuf, sig: &PathBuf) -> Result<()> {
    let pk_bytes = fs::read(pubkey).with_context(|| format!("read {}", pubkey.display()))?;
    if pk_bytes.len() != 32 {
        bail!("public key must be 32 bytes, got {}", pk_bytes.len());
    }
    let verifying = VerifyingKey::from_bytes(&pk_bytes.try_into().unwrap())
        .context("parse public key")?;

    let bytes = fs::read(input).with_context(|| format!("read {}", input.display()))?;

    let sig_hex = fs::read_to_string(sig).with_context(|| format!("read {}", sig.display()))?;
    let sig_bytes = hex::decode(sig_hex.trim()).context("decode signature hex")?;
    if sig_bytes.len() != 64 {
        bail!("signature must be 64 bytes, got {}", sig_bytes.len());
    }
    let signature = ed25519_dalek::Signature::from_bytes(&sig_bytes.try_into().unwrap());

    verifying
        .verify_strict(&bytes, &signature)
        .context("signature verification failed")?;
    eprintln!("OK: signature verifies");
    Ok(())
}
