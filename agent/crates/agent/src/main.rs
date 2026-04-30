mod cli;
#[cfg(target_os = "macos")]
mod launchd;
mod retry;
#[cfg(target_os = "windows")]
mod winsvc;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::Parser;
use cli::{Cli, Commands};
use open_attest_collector::collect_all;
use open_attest_config as config;
use open_attest_signer::{FileKeyStore, KeyStore};
use open_attest_types::*;
use std::process::Command;

const AGENT_NAME: &str = "open-attest";
const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");

fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

fn get_hostname() -> String {
    Command::new("hostname")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(target_os = "macos")]
fn get_os_version() -> String {
    Command::new("sw_vers")
        .arg("-productVersion")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(target_os = "windows")]
fn get_os_version() -> String {
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command",
               "[System.Environment]::OSVersion.Version.ToString()"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(target_os = "linux")]
fn get_os_version() -> String {
    Command::new("uname")
        .arg("-r")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_else(|_| "unknown".to_string())
}

#[cfg(target_os = "macos")]
fn get_hardware_uuid() -> Option<String> {
    Command::new("ioreg")
        .args(["-rd1", "-c", "IOPlatformExpertDevice"])
        .output()
        .ok()
        .and_then(|o| {
            let output = String::from_utf8_lossy(&o.stdout).to_string();
            for line in output.lines() {
                if line.contains("IOPlatformUUID") {
                    if let Some(uuid) = line.split('"').nth(3) {
                        return Some(uuid.to_string());
                    }
                }
            }
            None
        })
}

#[cfg(target_os = "windows")]
fn get_hardware_uuid() -> Option<String> {
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command",
               "(Get-CimInstance Win32_ComputerSystemProduct).UUID"])
        .output()
        .ok()
        .and_then(|o| {
            let uuid = String::from_utf8_lossy(&o.stdout).trim().to_string();
            if uuid.is_empty() || uuid == "FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF" {
                None
            } else {
                Some(uuid)
            }
        })
}

#[cfg(target_os = "linux")]
fn get_hardware_uuid() -> Option<String> {
    std::fs::read_to_string("/sys/class/dmi/id/product_uuid")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
}

fn get_device_id() -> String {
    get_hardware_uuid().unwrap_or_else(|| uuid::Uuid::now_v7().to_string())
}

fn do_enroll(token: String, server: String) -> Result<()> {
    if config::exists()? {
        bail!("Agent is already enrolled. Run 'open-attest uninstall' first.");
    }

    let config_dir = config::config_dir()?;
    let key_path = open_attest_signer::key_path_in(&config_dir);
    let key_store = FileKeyStore::new(&key_path);

    // Generate keypair
    key_store
        .generate_and_store()
        .context("Failed to generate keypair")?;
    let public_key = key_store.public_key_base64()?;

    let hostname = get_hostname();
    let os_version = get_os_version();
    let hardware_uuid = get_hardware_uuid();
    let device_id = get_device_id();

    let request = EnrollmentRequest {
        token: token.clone(),
        public_key: public_key.clone(),
        hostname: hostname.clone(),
        platform: std::env::consts::OS.to_string(),
        platform_version: os_version.clone(),
        identity_anchors: IdentityAnchors {
            hardware_uuid,
            serial_hash: None,
        },
    };

    let response = open_attest_transport::enroll(&server, &request, &public_key)
        .context("Enrollment request failed")?;

    let agent_config = config::AgentConfig {
        server_url: server,
        agent_id: response.agent_id.clone(),
        device_id,
        key_id: response.key_id.clone(),
        org_id: response.org_id.clone(),
        heartbeat_interval_seconds: response.config.heartbeat_interval_seconds,
        snapshot_interval_seconds: response.config.snapshot_interval_seconds,
        key_path: key_path.to_string_lossy().to_string(),
    };

    config::save(&agent_config).context("Failed to save config")?;

    // Install platform-specific daemon
    #[cfg(target_os = "macos")]
    if let Err(e) = launchd::install_launchd() {
        eprintln!("Warning: Failed to install LaunchAgent: {}", e);
    }
    #[cfg(target_os = "windows")]
    if let Err(e) = winsvc::install_task() {
        eprintln!("Warning: Failed to install Scheduled Task: {}", e);
    }

    println!("Enrolled successfully!");
    println!("  Agent ID:  {}", response.agent_id);
    println!("  Key ID:    {}", response.key_id);
    println!("  Org ID:    {}", response.org_id);
    Ok(())
}

fn do_status() -> Result<()> {
    if !config::exists()? {
        println!("Agent is not enrolled.");
        return Ok(());
    }

    let cfg = config::load()?;
    println!("Agent Status:");
    println!("  Agent ID:   {}", cfg.agent_id);
    println!("  Device ID:  {}", cfg.device_id);
    println!("  Server:     {}", cfg.server_url);
    println!("  Org ID:     {}", cfg.org_id);
    println!("  Key ID:     {}", cfg.key_id);
    println!(
        "  Heartbeat:  {}s",
        cfg.heartbeat_interval_seconds
    );
    println!(
        "  Snapshot:   {}s",
        cfg.snapshot_interval_seconds
    );
    Ok(())
}

fn evaluate_compliance(check: &CheckResult) -> Option<&'static str> {
    fn bool_pass_fail(v: &CheckValue) -> Option<&'static str> {
        match v { CheckValue::Bool(v) => Some(if *v { "PASS" } else { "FAIL" }), _ => None }
    }
    match check.key.as_str() {
        "disk_encryption.enabled" | "firewall.enabled" | "screen_lock.password_required" | "password.enabled"
            => bool_pass_fail(&check.value),
        "edr.present" => match &check.value {
            CheckValue::Bool(v) => Some(if *v { "PASS" } else { "WARN" }),
            _ => None,
        },
        "screen_lock.timeout_minutes" => match &check.value {
            CheckValue::Int(v) => Some(if *v > 0 && *v <= 15 { "PASS" } else { "FAIL" }),
            _ => None,
        },
        "password_policy.min_length" => match &check.value {
            CheckValue::Int(v) => Some(if *v >= 8 { "PASS" } else { "FAIL" }),
            _ => None,
        },
        _ => None,
    }
}

fn do_check(json_output: bool) -> Result<()> {
    let checks = collect_all();

    if json_output {
        let json = serde_json::to_string_pretty(&checks)?;
        println!("{}", json);
        return Ok(());
    }

    // Print table header
    println!("{:<35} {:<30} {}", "CHECK", "VALUE", "STATUS");
    println!("{}", "-".repeat(75));

    for check in &checks {
        let value_str = match &check.value {
            CheckValue::Bool(v) => format!("{}", v),
            CheckValue::Int(v) => format!("{}", v),
            CheckValue::Str(v) => v.clone(),
            CheckValue::StringList(v) => v.join(", "),
        };

        let status = evaluate_compliance(check).unwrap_or("\u{2014}");

        println!("{:<35} {:<30} {}", check.key, value_str, status);
    }

    // Summary — single pass
    let (mut passing, mut failing, mut warnings) = (0, 0, 0);
    for check in &checks {
        match evaluate_compliance(check) {
            Some("PASS") => passing += 1,
            Some("FAIL") => failing += 1,
            Some("WARN") => warnings += 1,
            _ => {}
        }
    }
    let total_evaluated = passing + failing + warnings;

    println!();
    println!(
        "{}/{} checks passing, {} failing, {} warnings",
        passing, total_evaluated, failing, warnings
    );

    Ok(())
}

fn build_attestation_payload(cfg: &config::AgentConfig) -> AttestationPayload {
    let checks = collect_all();
    let hostname = get_hostname();
    let os_version = get_os_version();

    AttestationPayload {
        schema_version: "1.0".to_string(),
        attestation_id: uuid::Uuid::now_v7().to_string(),
        collected_at: now_iso(),
        agent: AgentInfo {
            name: AGENT_NAME.to_string(),
            version: AGENT_VERSION.to_string(),
            agent_id: cfg.agent_id.clone(),
        },
        device: DeviceInfo {
            device_id: cfg.device_id.clone(),
            hostname,
            platform: std::env::consts::OS.to_string(),
            platform_version: os_version,
            identity_anchors: IdentityAnchors {
                hardware_uuid: get_hardware_uuid(),
                serial_hash: None,
            },
        },
        user: Some(UserIdentity {
            username: Command::new("whoami")
                .output()
                .ok()
                .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string()),
            email: None,
        }),
        checks,
    }
}

fn do_attest() -> Result<()> {
    if !config::exists()? {
        bail!("Agent is not enrolled. Run 'open-attest enroll' first.");
    }

    let cfg = config::load()?;
    let key_store = FileKeyStore::new(&cfg.key_path);

    if !key_store.exists() {
        bail!("Signing key not found at: {}", cfg.key_path);
    }

    let payload = build_attestation_payload(&cfg);

    let sign_fn = |data: &[u8]| -> String { key_store.sign(data).expect("Signing failed") };

    let response =
        open_attest_transport::submit_attestation(&cfg.server_url, &cfg.agent_id, &payload, &sign_fn)?;

    println!("Attestation submitted successfully.");
    if let Some(new_config) = response.config {
        println!(
            "  Updated intervals: heartbeat={}s, snapshot={}s",
            new_config.heartbeat_interval_seconds, new_config.snapshot_interval_seconds
        );
    }

    Ok(())
}

fn do_uninstall() -> Result<()> {
    // Remove platform-specific daemon
    #[cfg(target_os = "macos")]
    if let Err(e) = launchd::uninstall_launchd() {
        eprintln!("Warning: Failed to uninstall LaunchAgent: {}", e);
    }
    #[cfg(target_os = "windows")]
    if let Err(e) = winsvc::uninstall_task() {
        eprintln!("Warning: Failed to remove Scheduled Task: {}", e);
    }

    // Delete config directory
    let config_dir = config::config_dir()?;
    if config_dir.exists() {
        std::fs::remove_dir_all(&config_dir)
            .with_context(|| format!("Failed to remove config dir: {}", config_dir.display()))?;
        println!("Removed config directory: {}", config_dir.display());
    }

    println!("Agent uninstalled successfully.");
    Ok(())
}

fn do_web() -> Result<()> {
    let cfg = config::load()?;
    let url = format!("{}/admin/", cfg.server_url);
    println!("Opening {}", url);
    #[cfg(target_os = "macos")]
    Command::new("open").arg(&url).spawn()?;
    #[cfg(target_os = "windows")]
    Command::new("cmd").args(["/c", "start", &url]).spawn()?;
    #[cfg(target_os = "linux")]
    Command::new("xdg-open").arg(&url).spawn()?;
    Ok(())
}

fn detect_drift(prev: &[CheckResult], current: &[CheckResult]) -> Vec<String> {
    let mut changed = vec![];
    for curr in current {
        if let Some(prev_check) = prev.iter().find(|p| p.key == curr.key) {
            if prev_check.value != curr.value {
                changed.push(curr.key.clone());
            }
        } else {
            // New check that wasn't in previous snapshot
            changed.push(curr.key.clone());
        }
    }
    changed
}

fn drain_retry_queue(
    queue: &retry::RetryQueue,
    cfg: &config::AgentConfig,
    key_store: &FileKeyStore,
) {
    match queue.pending() {
        Ok(items) => {
            for (path, json) in items {
                match serde_json::from_str::<AttestationPayload>(&json) {
                    Ok(payload) => {
                        let sign_fn = |data: &[u8]| -> String {
                            key_store.sign(data).expect("Signing failed")
                        };
                        match open_attest_transport::submit_attestation(
                            &cfg.server_url,
                            &cfg.agent_id,
                            &payload,
                            &sign_fn,
                        ) {
                            Ok(_) => {
                                let _ = queue.remove(&path);
                                eprintln!(
                                    "[{}] Retry delivered: {}",
                                    now_iso(),
                                    path.display()
                                );
                            }
                            Err(e) => {
                                eprintln!("[{}] Retry failed: {}", now_iso(), e);
                                break; // Stop retrying if server is still down
                            }
                        }
                    }
                    Err(e) => {
                        eprintln!("[{}] Invalid retry payload, removing: {}", now_iso(), e);
                        let _ = queue.remove(&path);
                    }
                }
            }
        }
        Err(e) => eprintln!("[{}] Failed to read retry queue: {}", now_iso(), e),
    }
}

async fn do_daemon() -> Result<()> {
    if !config::exists()? {
        bail!("Agent is not enrolled. Run 'open-attest enroll' first.");
    }

    let cfg = config::load()?;
    let key_store = FileKeyStore::new(&cfg.key_path);

    if !key_store.exists() {
        bail!("Signing key not found at: {}", cfg.key_path);
    }

    let retry_dir = config::config_dir()?.join("retry");
    let queue = retry::RetryQueue::new(&retry_dir)?;

    println!(
        "Daemon started. Heartbeat every {}s, snapshot every {}s.",
        cfg.heartbeat_interval_seconds, cfg.snapshot_interval_seconds
    );

    let heartbeat_interval =
        tokio::time::Duration::from_secs(cfg.heartbeat_interval_seconds);
    let snapshot_interval =
        tokio::time::Duration::from_secs(cfg.snapshot_interval_seconds);
    let drift_interval = tokio::time::Duration::from_secs(600);

    let mut heartbeat_timer = tokio::time::interval(heartbeat_interval);
    let mut snapshot_timer = tokio::time::interval(snapshot_interval);
    let mut drift_timer = tokio::time::interval(drift_interval);

    // Skip the first immediate tick for all timers
    heartbeat_timer.tick().await;
    snapshot_timer.tick().await;
    drift_timer.tick().await;

    let mut last_checks: Option<Vec<CheckResult>> = None;

    loop {
        tokio::select! {
            _ = heartbeat_timer.tick() => {
                let payload = HeartbeatPayload {
                    device_id: cfg.device_id.clone(),
                    agent_id: cfg.agent_id.clone(),
                    timestamp: now_iso(),
                };
                let sign_fn = |data: &[u8]| -> String {
                    key_store.sign(data).expect("Signing failed")
                };
                match open_attest_transport::send_heartbeat(
                    &cfg.server_url, &cfg.agent_id, &payload, &sign_fn
                ) {
                    Ok(_) => {
                        eprintln!("[{}] Heartbeat sent", now_iso());
                        drain_retry_queue(&queue, &cfg, &key_store);
                    }
                    Err(e) => eprintln!("[{}] Heartbeat failed: {}", now_iso(), e),
                }
            }
            _ = snapshot_timer.tick() => {
                let payload = build_attestation_payload(&cfg);
                let payload_json = serde_json::to_string(&payload)?;
                let sign_fn = |data: &[u8]| -> String {
                    key_store.sign(data).expect("Signing failed")
                };
                match open_attest_transport::submit_attestation(
                    &cfg.server_url, &cfg.agent_id, &payload, &sign_fn
                ) {
                    Ok(_) => {
                        eprintln!("[{}] Attestation submitted", now_iso());
                        last_checks = Some(payload.checks.clone());
                        drain_retry_queue(&queue, &cfg, &key_store);
                    }
                    Err(e) => {
                        eprintln!("[{}] Attestation failed: {}, queuing for retry", now_iso(), e);
                        let _ = queue.enqueue(&payload_json);
                    }
                }

                // Evict old entries periodically
                let _ = queue.evict_old(604800); // 7 days
            }
            _ = drift_timer.tick() => {
                let current_checks = collect_all();
                if let Some(ref prev) = last_checks {
                    let changed = detect_drift(prev, &current_checks);
                    if !changed.is_empty() {
                        eprintln!(
                            "[{}] Drift detected in {} checks, submitting attestation",
                            now_iso(),
                            changed.len()
                        );
                        for key in &changed {
                            eprintln!("[{}]   Changed: {}", now_iso(), key);
                        }
                        // Submit immediate attestation
                        let payload = build_attestation_payload(&cfg);
                        let sign_fn = |data: &[u8]| -> String {
                            key_store.sign(data).expect("Signing failed")
                        };
                        match open_attest_transport::submit_attestation(
                            &cfg.server_url, &cfg.agent_id, &payload, &sign_fn
                        ) {
                            Ok(_) => eprintln!("[{}] Drift attestation submitted", now_iso()),
                            Err(e) => eprintln!("[{}] Drift attestation failed: {}", now_iso(), e),
                        }
                    }
                }
                last_checks = Some(current_checks);
            }
        }
    }
}

#[tokio::main]
async fn main() {
    let cli = Cli::parse();

    let result = match cli.command {
        Commands::Enroll { token, server } => do_enroll(token, server),
        Commands::Status => do_status(),
        Commands::Check { json } => do_check(json),
        Commands::Attest => do_attest(),
        Commands::Uninstall => do_uninstall(),
        Commands::Daemon => do_daemon().await,
        Commands::Web => do_web(),
    };

    if let Err(e) = result {
        eprintln!("Error: {:#}", e);
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use open_attest_types::{CheckResult, CheckValue};

    fn check(key: &str, value: CheckValue) -> CheckResult {
        CheckResult {
            key: key.to_string(),
            value,
            observed_at: "2026-01-01T00:00:00Z".to_string(),
            source: "test".to_string(),
        }
    }

    #[test]
    fn drift_no_change() {
        let prev = vec![
            check("disk_encryption.enabled", CheckValue::Bool(true)),
            check("firewall.enabled", CheckValue::Bool(true)),
        ];
        let current = vec![
            check("disk_encryption.enabled", CheckValue::Bool(true)),
            check("firewall.enabled", CheckValue::Bool(true)),
        ];
        assert!(detect_drift(&prev, &current).is_empty());
    }

    #[test]
    fn drift_value_changed() {
        let prev = vec![
            check("disk_encryption.enabled", CheckValue::Bool(true)),
            check("firewall.enabled", CheckValue::Bool(true)),
        ];
        let current = vec![
            check("disk_encryption.enabled", CheckValue::Bool(true)),
            check("firewall.enabled", CheckValue::Bool(false)),
        ];
        let changed = detect_drift(&prev, &current);
        assert_eq!(changed, vec!["firewall.enabled"]);
    }

    #[test]
    fn drift_new_check_added() {
        let prev = vec![
            check("disk_encryption.enabled", CheckValue::Bool(true)),
        ];
        let current = vec![
            check("disk_encryption.enabled", CheckValue::Bool(true)),
            check("edr.present", CheckValue::Bool(false)),
        ];
        let changed = detect_drift(&prev, &current);
        assert_eq!(changed, vec!["edr.present"]);
    }

    #[test]
    fn drift_multiple_changes() {
        let prev = vec![
            check("os.version", CheckValue::Str("14.4".to_string())),
            check("screen_lock.timeout_minutes", CheckValue::Int(5)),
        ];
        let current = vec![
            check("os.version", CheckValue::Str("14.5".to_string())),
            check("screen_lock.timeout_minutes", CheckValue::Int(10)),
        ];
        let changed = detect_drift(&prev, &current);
        assert_eq!(changed.len(), 2);
        assert!(changed.contains(&"os.version".to_string()));
        assert!(changed.contains(&"screen_lock.timeout_minutes".to_string()));
    }

    #[test]
    fn drift_empty_prev() {
        let prev: Vec<CheckResult> = vec![];
        let current = vec![
            check("disk_encryption.enabled", CheckValue::Bool(true)),
        ];
        let changed = detect_drift(&prev, &current);
        assert_eq!(changed, vec!["disk_encryption.enabled"]);
    }
}
