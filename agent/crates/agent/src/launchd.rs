use crate::DaemonState;
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

/// Asks launchd what became of the job.
pub fn daemon_state() -> DaemonState {
    let path = match plist_path() {
        Ok(p) => p,
        Err(e) => return DaemonState::Unknown { reason: e.to_string() },
    };
    if !path.exists() {
        return DaemonState::NotInstalled;
    }

    match Command::new("launchctl").arg("list").output() {
        Ok(o) => state_from_list(&String::from_utf8_lossy(&o.stdout)),
        Err(e) => DaemonState::Unknown {
            reason: format!("launchctl list: {e}"),
        },
    }
}

/// `launchctl list` prints one "PID\tLastExitStatus\tLabel" row per job. The
/// PID column is `-` when the job is not running, and the status column
/// carries the exit code of the last run.
fn state_from_list(stdout: &str) -> DaemonState {
    for line in stdout.lines() {
        let mut cols = line.split('\t');
        let pid = cols.next().unwrap_or_default();
        let last_exit = cols.next().unwrap_or_default();
        if cols.next() != Some(PLIST_LABEL) {
            continue;
        }
        return match pid.parse::<u32>() {
            Ok(pid) => DaemonState::Running { pid: Some(pid) },
            Err(_) => DaemonState::Stopped {
                detail: match last_exit.parse::<i32>() {
                    Ok(0) | Err(_) => None,
                    Ok(code) => Some(format!("last exit {code}{}", exit_hint(code))),
                },
            },
        };
    }

    // Plist on disk but launchd does not know about it.
    DaemonState::Stopped {
        detail: Some("job not loaded".to_string()),
    }
}

fn exit_hint(code: i32) -> &'static str {
    // launchd reports EX_CONFIG when it cannot exec the program at all, which
    // for us means the managed binary is missing or not executable. Nothing
    // reaches the log files in that case, so name the cause here.
    if code == 78 {
        " (EX_CONFIG — launchd could not exec the agent binary)"
    } else {
        ""
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const OTHER_JOBS: &str = "\
-\t0\tcom.apple.SafariHistoryServiceAgent
501\t0\tcom.apple.progressd";

    #[test]
    fn reads_the_pid_of_a_running_job() {
        let out = format!("{OTHER_JOBS}\n32114\t0\t{PLIST_LABEL}");
        assert_eq!(
            state_from_list(&out),
            DaemonState::Running { pid: Some(32114) }
        );
    }

    #[test]
    fn reports_ex_config_when_launchd_cannot_exec() {
        // The failure from issue #14: the plist points at a binary that was
        // never placed, so launchd never runs the job and never logs anything.
        let out = format!("{OTHER_JOBS}\n-\t78\t{PLIST_LABEL}");
        match state_from_list(&out) {
            DaemonState::Stopped { detail: Some(d) } => {
                assert!(d.contains("last exit 78"), "{d}");
                assert!(d.contains("EX_CONFIG"), "{d}");
            }
            other => panic!("expected a stopped job, got {other:?}"),
        }
    }

    #[test]
    fn reports_a_cleanly_stopped_job_without_a_reason() {
        let out = format!("-\t0\t{PLIST_LABEL}");
        assert_eq!(state_from_list(&out), DaemonState::Stopped { detail: None });
    }

    #[test]
    fn reports_a_plist_launchd_has_not_loaded() {
        assert_eq!(
            state_from_list(OTHER_JOBS),
            DaemonState::Stopped {
                detail: Some("job not loaded".to_string())
            }
        );
    }
}
