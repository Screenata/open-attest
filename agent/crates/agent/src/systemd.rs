use crate::DaemonState;
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

/// Asks systemd about the user unit.
pub fn daemon_state() -> DaemonState {
    let path = match unit_path() {
        Ok(p) => p,
        Err(e) => return DaemonState::Unknown { reason: e.to_string() },
    };
    if !path.exists() {
        return DaemonState::NotInstalled;
    }

    match Command::new("systemctl")
        .args([
            "--user",
            "show",
            UNIT_NAME,
            "--property=ActiveState",
            "--property=MainPID",
            "--property=ExecMainStatus",
        ])
        .output()
    {
        Ok(o) => state_from_show(&String::from_utf8_lossy(&o.stdout)),
        Err(e) => DaemonState::Unknown {
            reason: format!("systemctl show: {e}"),
        },
    }
}

/// `systemctl show` emits stable KEY=VALUE lines, unlike the human-facing
/// (and localized) `systemctl status` output.
fn state_from_show(stdout: &str) -> DaemonState {
    let field = |key: &str| -> Option<&str> {
        stdout
            .lines()
            .find_map(|l| l.strip_prefix(key)?.strip_prefix('='))
    };

    match field("ActiveState").unwrap_or_default() {
        "active" => DaemonState::Running {
            pid: field("MainPID")
                .and_then(|p| p.parse::<u32>().ok())
                .filter(|p| *p != 0),
        },
        "" => DaemonState::Unknown {
            reason: "systemctl reported no ActiveState".to_string(),
        },
        state => DaemonState::Stopped {
            detail: Some(
                match field("ExecMainStatus").and_then(|s| s.parse::<i32>().ok()) {
                    Some(0) | None => state.to_string(),
                    Some(code) => format!("{state}, last exit {code}"),
                },
            ),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_pid_of_an_active_unit() {
        let out = "ActiveState=active\nMainPID=4242\nExecMainStatus=0\n";
        assert_eq!(
            state_from_show(out),
            DaemonState::Running { pid: Some(4242) }
        );
    }

    #[test]
    fn reports_the_exit_code_of_a_failed_unit() {
        // systemd's analogue of the issue #14 failure: ExecStart points at a
        // binary that is not there, so the unit fails on exec.
        let out = "ActiveState=failed\nMainPID=0\nExecMainStatus=203\n";
        assert_eq!(
            state_from_show(out),
            DaemonState::Stopped {
                detail: Some("failed, last exit 203".to_string())
            }
        );
    }

    #[test]
    fn reports_a_clean_stop_without_an_exit_code() {
        let out = "ActiveState=inactive\nMainPID=0\nExecMainStatus=0\n";
        assert_eq!(
            state_from_show(out),
            DaemonState::Stopped {
                detail: Some("inactive".to_string())
            }
        );
    }

    #[test]
    fn treats_missing_output_as_unknown() {
        assert!(matches!(
            state_from_show(""),
            DaemonState::Unknown { .. }
        ));
    }
}
