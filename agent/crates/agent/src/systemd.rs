use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const UNIT_NAME: &str = "open-attest.service";

fn unit_path() -> Result<PathBuf> {
    let base = dirs::config_dir().context("Could not determine config directory")?;
    Ok(base.join("systemd").join("user").join(UNIT_NAME))
}

pub fn install_systemd() -> Result<()> {
    let binary = open_attest_config::managed_binary_path()?;
    let path = unit_path()?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("Failed to create systemd user unit directory")?;
    }

    // StartLimitIntervalSec=0 disables systemd's "restart loop" detection;
    // our probation/boot-count logic owns crash detection.
    let unit = format!(
        r#"[Unit]
Description=open-attest endpoint attestation agent
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart={binary} daemon
Restart=always
RestartSec=5
StartLimitIntervalSec=0
StandardOutput=append:/tmp/open-attest.stdout.log
StandardError=append:/tmp/open-attest.stderr.log

[Install]
WantedBy=default.target
"#,
        binary = binary.display(),
    );

    fs::write(&path, unit)
        .with_context(|| format!("Failed to write unit file: {}", path.display()))?;

    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    let status = Command::new("systemctl")
        .args(["--user", "enable", "--now", UNIT_NAME])
        .status()
        .context("Failed to run systemctl --user enable --now")?;

    if !status.success() {
        eprintln!("Warning: systemctl --user enable --now returned non-zero");
    }

    println!("systemd user unit installed: {}", path.display());
    Ok(())
}

pub fn uninstall_systemd() -> Result<()> {
    let _ = Command::new("systemctl")
        .args(["--user", "disable", "--now", UNIT_NAME])
        .status();

    let path = unit_path()?;
    if path.exists() {
        fs::remove_file(&path)
            .with_context(|| format!("Failed to remove unit file: {}", path.display()))?;
        println!("systemd user unit removed: {}", path.display());
    }
    let _ = Command::new("systemctl")
        .args(["--user", "daemon-reload"])
        .status();
    Ok(())
}
