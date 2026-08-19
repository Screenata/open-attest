use anyhow::{Context, Result};
use chrono::{Duration, Local};
use std::process::Command;

const TASK_NAME: &str = "OpenAttestAgent";

/// Transient one-shot task used to bring the daemon back after a self-update.
/// Always (re)created with /F so a leftover from an aborted attempt is
/// overwritten rather than colliding.
const RESTART_TASK_NAME: &str = "OpenAttestAgentRestart";

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

    // Drop a pending self-update restart, if one is booked.
    let _ = Command::new("schtasks")
        .args(["/Delete", "/TN", RESTART_TASK_NAME, "/F"])
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

/// Schedules a one-shot task that re-runs the main agent task, then deletes
/// itself. The updater has already swapped the binary on disk; the daemon is
/// about to exit so the new code takes effect. Unlike launchd/systemd, our
/// ONLOGON task has no supervisor to restart us, so without this the update
/// would not take effect until the next logon.
///
/// Keep the /TR string short: schtasks rejects a task-run value longer than
/// 261 characters, so this must never grow to embed file paths.
pub fn schedule_restart() -> Result<()> {
    // /ST takes HH:MM, so the trigger always lands on a whole minute. Aiming
    // 75s out guarantees the rounded-down time is still in the future —
    // Windows refuses a trigger at or before now — while keeping the daemon's
    // downtime under two minutes.
    let trigger_at = Local::now() + Duration::seconds(75);

    let status = Command::new("schtasks")
        .args([
            "/Create",
            "/TN", RESTART_TASK_NAME,
            "/TR", &format!(
                "cmd /c schtasks /Run /TN {TASK_NAME} & \
                 schtasks /Delete /TN {RESTART_TASK_NAME} /F"
            ),
            "/SC", "ONCE",
            "/SD", &trigger_at.format("%m/%d/%Y").to_string(),
            "/ST", &trigger_at.format("%H:%M").to_string(),
            "/RL", "HIGHEST",
            "/F",
        ])
        .status()
        .context("Failed to run schtasks /Create for the restart task")?;

    if !status.success() {
        anyhow::bail!("schtasks /Create returned non-zero exit code");
    }
    Ok(())
}
