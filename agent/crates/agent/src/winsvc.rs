use crate::DaemonState;
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

/// Reports whether the agent daemon is actually running. The Scheduled Task's
/// own Status field is localized, so this checks the task's existence by exit
/// code and looks for a live process with `tasklist`, whose filter syntax is
/// not localized.
pub fn daemon_state() -> DaemonState {
    match Command::new("schtasks")
        .args(["/Query", "/TN", TASK_NAME])
        .output()
    {
        Ok(o) if o.status.success() => {}
        Ok(_) => return DaemonState::NotInstalled,
        Err(e) => {
            return DaemonState::Unknown {
                reason: format!("schtasks /Query: {e}"),
            }
        }
    }

    match Command::new("tasklist")
        .args(["/FI", "IMAGENAME eq open-attest.exe", "/NH", "/FO", "CSV"])
        .output()
    {
        Ok(o) => state_from_tasklist(&String::from_utf8_lossy(&o.stdout), std::process::id()),
        Err(e) => DaemonState::Unknown {
            reason: format!("tasklist: {e}"),
        },
    }
}

/// Picks the daemon out of `tasklist /FO CSV` output, whose rows look like
/// `"open-attest.exe","1234","Console","1","9,000 K"`. `me` is skipped: the
/// CLI shares an image name with the daemon, so the process running this very
/// query would otherwise read as a live daemon.
fn state_from_tasklist(stdout: &str, me: u32) -> DaemonState {
    for line in stdout.lines() {
        let pid = line
            .split(',')
            .nth(1)
            .map(|f| f.trim_matches('"'))
            .and_then(|p| p.parse::<u32>().ok());
        if let Some(pid) = pid.filter(|p| *p != me) {
            return DaemonState::Running { pid: Some(pid) };
        }
    }

    DaemonState::Stopped {
        detail: Some(
            "the Scheduled Task is registered but no agent process is running".to_string(),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_pid_of_a_running_daemon() {
        let out = "\"open-attest.exe\",\"4242\",\"Console\",\"1\",\"9,000 K\"\n";
        assert_eq!(
            state_from_tasklist(out, 100),
            DaemonState::Running { pid: Some(4242) }
        );
    }

    #[test]
    fn does_not_mistake_this_process_for_the_daemon() {
        // `open-attest status` is itself an open-attest.exe.
        let out = "\"open-attest.exe\",\"100\",\"Console\",\"1\",\"9,000 K\"\n";
        assert!(matches!(
            state_from_tasklist(out, 100),
            DaemonState::Stopped { .. }
        ));
    }

    #[test]
    fn reports_stopped_when_no_process_matches() {
        // What tasklist prints with /NH when the filter matches nothing.
        let out = "INFO: No tasks are running which match the specified criteria.\n";
        assert!(matches!(
            state_from_tasklist(out, 100),
            DaemonState::Stopped { .. }
        ));
    }
}
