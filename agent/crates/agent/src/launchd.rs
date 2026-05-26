use anyhow::{Context, Result};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

const PLIST_LABEL: &str = "com.open-attest.agent";

fn plist_path() -> Result<PathBuf> {
    let home = dirs::home_dir().context("Could not determine home directory")?;
    Ok(home
        .join("Library")
        .join("LaunchAgents")
        .join(format!("{}.plist", PLIST_LABEL)))
}

fn agent_binary_path() -> Result<String> {
    // Always point the plist at the managed binary so updates that swap
    // the file in place are picked up on the next supervisor relaunch.
    open_attest_config::managed_binary_path()
        .context("Could not determine managed binary path")
        .map(|p| p.to_string_lossy().to_string())
}

pub fn install_launchd() -> Result<()> {
    let binary = agent_binary_path()?;
    let path = plist_path()?;

    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).context("Failed to create LaunchAgents directory")?;
    }

    let plist_content = format!(
        r#"<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>{label}</string>
    <key>ProgramArguments</key>
    <array>
        <string>{binary}</string>
        <string>daemon</string>
    </array>
    <key>KeepAlive</key>
    <true/>
    <key>RunAtLoad</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/open-attest.stdout.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/open-attest.stderr.log</string>
</dict>
</plist>"#,
        label = PLIST_LABEL,
        binary = binary,
    );

    fs::write(&path, plist_content)
        .with_context(|| format!("Failed to write plist: {}", path.display()))?;

    // Load the LaunchAgent
    let status = Command::new("launchctl")
        .args(["load", &path.to_string_lossy()])
        .status()
        .context("Failed to run launchctl load")?;

    if !status.success() {
        eprintln!("Warning: launchctl load returned non-zero exit code");
    }

    println!("LaunchAgent installed: {}", path.display());
    Ok(())
}

pub fn uninstall_launchd() -> Result<()> {
    let path = plist_path()?;

    if path.exists() {
        // Unload first
        let _ = Command::new("launchctl")
            .args(["unload", &path.to_string_lossy()])
            .status();

        fs::remove_file(&path)
            .with_context(|| format!("Failed to remove plist: {}", path.display()))?;
        println!("LaunchAgent removed: {}", path.display());
    } else {
        println!("LaunchAgent plist not found, skipping.");
    }

    Ok(())
}
