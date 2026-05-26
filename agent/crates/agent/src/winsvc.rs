use anyhow::{Context, Result};
use std::process::Command;

const TASK_NAME: &str = "OpenAttestAgent";

fn agent_binary_path() -> Result<String> {
    open_attest_config::managed_binary_path()
        .context("Could not determine managed binary path")
        .map(|p| p.to_string_lossy().to_string())
}

pub fn install_task() -> Result<()> {
    let binary = agent_binary_path()?;

    // Create a scheduled task that runs at logon and restarts on failure
    let status = Command::new("schtasks")
        .args([
            "/Create",
            "/TN", TASK_NAME,
            "/TR", &format!("\"{}\" daemon", binary),
            "/SC", "ONLOGON",
            "/RL", "HIGHEST",
            "/F", // force overwrite if exists
        ])
        .status()
        .context("Failed to run schtasks /Create")?;

    if !status.success() {
        anyhow::bail!("schtasks /Create returned non-zero exit code");
    }

    // Start the task immediately
    let _ = Command::new("schtasks")
        .args(["/Run", "/TN", TASK_NAME])
        .status();

    println!("Scheduled Task installed: {}", TASK_NAME);
    Ok(())
}

pub fn uninstall_task() -> Result<()> {
    // End the running task first
    let _ = Command::new("schtasks")
        .args(["/End", "/TN", TASK_NAME])
        .status();

    let status = Command::new("schtasks")
        .args(["/Delete", "/TN", TASK_NAME, "/F"])
        .status()
        .context("Failed to run schtasks /Delete")?;

    if status.success() {
        println!("Scheduled Task removed: {}", TASK_NAME);
    } else {
        println!("Scheduled Task not found or already removed.");
    }

    Ok(())
}
