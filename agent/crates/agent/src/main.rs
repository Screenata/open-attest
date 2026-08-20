mod cli;
#[cfg(target_os = "macos")]
mod launchd;
mod retry;
#[cfg(target_os = "linux")]
mod systemd;
#[cfg(target_os = "windows")]
mod winsvc;

use anyhow::{bail, Context, Result};
use chrono::Utc;
use clap::Parser;
use cli::{Cli, Commands};
use open_attest_collector::{collect_all, collect_inventory};
use open_attest_config as config;
use open_attest_signer::{FileKeyStore, KeyStore};
use open_attest_types::*;
use std::path::{Path, PathBuf};
use std::process::Command;

const AGENT_NAME: &str = "open-attest";
const AGENT_VERSION: &str = env!("CARGO_PKG_VERSION");
const BUILD_TARGET: &str = env!("BUILD_TARGET");

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

/// What the platform supervisor reports about the agent job.
#[derive(Debug, PartialEq)]
enum DaemonState {
    Running { pid: Option<u32> },
    Stopped { detail: Option<String> },
    /// No launchd plist / systemd unit / Scheduled Task registered at all.
    NotInstalled,
    Unknown { reason: String },
}

impl std::fmt::Display for DaemonState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DaemonState::Running { pid: Some(pid) } => write!(f, "running (pid {pid})"),
            DaemonState::Running { pid: None } => write!(f, "running"),
            DaemonState::Stopped { detail: Some(d) } => write!(f, "not running: {d}"),
            DaemonState::Stopped { detail: None } => write!(f, "not running"),
            DaemonState::NotInstalled => write!(f, "not installed"),
            DaemonState::Unknown { reason } => write!(f, "unknown ({reason})"),
        }
    }
}

fn daemon_state() -> DaemonState {
    #[cfg(target_os = "macos")]
    {
        launchd::daemon_state()
    }
    #[cfg(target_os = "linux")]
    {
        systemd::daemon_state()
    }
    #[cfg(target_os = "windows")]
    {
        winsvc::daemon_state()
    }
    #[cfg(not(any(target_os = "macos", target_os = "linux", target_os = "windows")))]
    {
        DaemonState::Unknown {
            reason: "unsupported platform".to_string(),
        }
    }
}

/// Copies `src` over `dst`, creating the parent directory. The copy lands on a
/// sibling temp path first so an interrupted write can never leave a truncated
/// executable at `dst`.
fn stage_binary(src: &Path, dst: &Path) -> Result<()> {
    if let Some(parent) = dst.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("Failed to create directory: {}", parent.display()))?;
    }

    let mut tmp = dst.as_os_str().to_owned();
    tmp.push(".incoming");
    let tmp = PathBuf::from(tmp);
    let _ = std::fs::remove_file(&tmp);

    std::fs::copy(src, &tmp)
        .with_context(|| format!("Failed to copy {} to {}", src.display(), tmp.display()))?;
    // Make it executable before it is visible at the final path.
    open_attest_updater::swap::make_executable(&tmp)?;
    std::fs::rename(&tmp, dst)
        .with_context(|| format!("Failed to move the binary into {}", dst.display()))?;
    Ok(())
}

/// Makes sure the agent binary exists at the managed path, copying the running
/// executable there if not. Every supervisor execs that path, and the updater
/// swaps that path, but only the macOS .pkg actually puts a binary there — a
/// raw release binary on $PATH, or the Windows installer's Program Files copy,
/// would otherwise leave the supervisor pointed at nothing. launchd cannot
/// exec, the job dies with exit 78 (EX_CONFIG), and no log is ever written.
fn install_managed_binary() -> Result<PathBuf> {
    let managed = config::managed_binary_path()?;
    let current = std::env::current_exe().context("Could not determine the running executable")?;

    // Already running from the managed path (a .pkg install, or a repair after
    // one) — nothing to copy, and copying a file onto itself would truncate it.
    if let (Ok(a), Ok(b)) = (
        std::fs::canonicalize(&current),
        std::fs::canonicalize(&managed),
    ) {
        if a == b {
            return Ok(managed);
        }
    }

    stage_binary(&current, &managed).with_context(|| {
        format!("Failed to install the agent binary to {}", managed.display())
    })?;
    Ok(managed)
}

/// Installs the platform supervisor that keeps the daemon running. Shared by
/// `enroll` and `repair`.
fn install_supervisor() {
    #[cfg(target_os = "macos")]
    if let Err(e) = launchd::install_launchd() {
        eprintln!("Warning: Failed to install LaunchAgent: {}", e);
    }
    #[cfg(target_os = "linux")]
    if let Err(e) = systemd::install_systemd() {
        eprintln!("Warning: Failed to install systemd user unit: {}", e);
    }
    #[cfg(target_os = "windows")]
    if let Err(e) = winsvc::install_task() {
        eprintln!("Warning: Failed to install Scheduled Task: {}", e);
    }
}

/// Waits briefly for the supervisor to bring the daemon up, then reports what
/// happened. Supervisors start the job asynchronously, so an immediate query
/// races the launch.
fn report_daemon_startup() {
    let mut state = daemon_state();
    for _ in 0..10 {
        if matches!(state, DaemonState::Running { .. }) {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(300));
        state = daemon_state();
    }

    match state {
        DaemonState::Running { .. } => println!("Background agent is running."),
        other => {
            eprintln!("Warning: the background agent is {other}.");
            eprintln!("         No heartbeats or attestations will be sent until it starts.");
            #[cfg(unix)]
            eprintln!("         See /tmp/open-attest.stderr.log, then try 'open-attest repair'.");
            #[cfg(not(unix))]
            eprintln!("         Try 'open-attest repair'.");
        }
    }
}

fn do_enroll(token: String, server: String) -> Result<()> {
    if config::exists()? {
        bail!("Agent is already enrolled. Run 'open-attest uninstall' first.");
    }

    // Before anything else: the supervisor installed below execs the managed
    // path, so if the binary cannot be put there this enrollment would produce
    // a device that reports in once and never again. Failing here leaves no
    // server-side or on-disk state behind.
    let managed_bin = install_managed_binary()?;

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

    install_supervisor();

    println!("Enrolled successfully!");
    println!("  Agent ID:  {}", response.agent_id);
    println!("  Key ID:    {}", response.key_id);
    println!("  Org ID:    {}", response.org_id);
    println!("  Binary:    {}", managed_bin.display());
    report_daemon_startup();
    Ok(())
}

/// Re-stages the managed binary and reinstalls the supervisor. Devices
/// enrolled by 0.8.0 and earlier are left with a supervisor pointing at a
/// binary that was never placed, and `enroll` refuses to run on an enrolled
/// device, so repairing that needs its own entry point.
fn do_repair() -> Result<()> {
    if !config::exists()? {
        bail!("Agent is not enrolled. Run 'open-attest enroll' first.");
    }

    let managed_bin = install_managed_binary()?;
    println!("Agent binary: {}", managed_bin.display());
    install_supervisor();
    report_daemon_startup();
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

    // Enrollment config alone says nothing about whether the agent is alive,
    // and "is this working?" is the question `status` is run to answer.
    let managed_bin = config::managed_binary_path()?;
    let binary_present = managed_bin.exists();
    println!(
        "  Binary:     {}{}",
        managed_bin.display(),
        if binary_present { "" } else { "  (MISSING)" }
    );
    let state = daemon_state();
    println!("  Daemon:     {state}");

    if !matches!(state, DaemonState::Running { .. }) {
        println!();
        println!("The background agent is not running: no heartbeats or attestations are being sent.");
        if !binary_present {
            println!("The managed binary is missing, which is what the supervisor tries to exec.");
        }
        println!("Run 'open-attest repair' to reinstall it.");
    }
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
    let mut checks = collect_all();
    checks.extend(collect_inventory());

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

fn build_attestation_payload(cfg: &config::AgentConfig, checks: Vec<CheckResult>) -> AttestationPayload {
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
            target_triple: BUILD_TARGET.to_string(),
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

    let mut checks = collect_all();
    checks.extend(collect_inventory());
    let payload = build_attestation_payload(&cfg, checks);

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
    #[cfg(target_os = "linux")]
    if let Err(e) = systemd::uninstall_systemd() {
        eprintln!("Warning: Failed to uninstall systemd unit: {}", e);
    }
    #[cfg(target_os = "windows")]
    if let Err(e) = winsvc::uninstall_task() {
        eprintln!("Warning: Failed to remove Scheduled Task: {}", e);
    }

    // Remove the managed binary and any .prev/.failed siblings, plus the
    // bin directory if it ends up empty.
    let managed_bin = config::managed_binary_path()?;
    for suffix in ["", ".prev", ".failed", ".new", ".incoming"] {
        let p = if suffix.is_empty() {
            managed_bin.clone()
        } else {
            let mut s = managed_bin.as_os_str().to_owned();
            s.push(suffix);
            std::path::PathBuf::from(s)
        };
        if p.exists() {
            if let Err(e) = std::fs::remove_file(&p) {
                eprintln!("Warning: failed to remove {}: {}", p.display(), e);
            }
        }
    }
    let bin_dir = config::bin_dir()?;
    if bin_dir.exists() {
        // remove_dir succeeds only if the directory is empty — fine, we
        // don't want to nuke ~/.local/bin on Linux if other things live there.
        let _ = std::fs::remove_dir(&bin_dir);
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

fn do_update(force: bool) -> Result<()> {
    if !config::exists()? {
        bail!("Agent is not enrolled. Run 'open-attest enroll' first.");
    }
    let cfg = config::load()?;
    let key_store = FileKeyStore::new(&cfg.key_path);
    if !key_store.exists() {
        bail!("Signing key not found at: {}", cfg.key_path);
    }

    let payload = HeartbeatPayload {
        device_id: cfg.device_id.clone(),
        agent_id: cfg.agent_id.clone(),
        timestamp: now_iso(),
    };
    let sign_fn = |data: &[u8]| -> String { key_store.sign(data).expect("Signing failed") };
    let response =
        open_attest_transport::send_heartbeat(&cfg.server_url, &cfg.agent_id, &payload, &sign_fn)
            .context("heartbeat failed")?;

    let mut offer = match response.update_offer {
        Some(o) => o,
        None => {
            println!("No update available.");
            return Ok(());
        }
    };
    if force {
        offer.force = true;
    }

    let bin_path = config::managed_binary_path()?;
    let state_dir = config::state_dir()?;
    let current_exe = std::env::current_exe().context("current_exe")?;
    let ctx = open_attest_updater::UpdateContext {
        state_dir: &state_dir,
        bin_path: &bin_path,
        current_exe: &current_exe,
        running_version: AGENT_VERSION,
        running_target_triple: BUILD_TARGET,
        release_pubkey: open_attest_updater::RELEASE_PUBKEY,
    };

    match open_attest_updater::check_and_apply(&offer, &ctx)? {
        open_attest_updater::UpdateOutcome::Installed { version } => {
            println!(
                "Installed {version}. Restart the daemon to use the new version."
            );
        }
        open_attest_updater::UpdateOutcome::SkippedAlreadyAtVersion => {
            println!("Already at offered version ({}).", offer.version);
        }
        open_attest_updater::UpdateOutcome::SkippedBinaryNotManaged => {
            println!(
                "Refusing to update: this binary is not at the managed location ({}). \
                 Reinstall via .pkg/.tar.gz to enable auto-updates.",
                bin_path.display()
            );
        }
        open_attest_updater::UpdateOutcome::SkippedRateLimited => {
            println!("Skipped: another update attempt was tried recently. Use --force to override.");
        }
        open_attest_updater::UpdateOutcome::SkippedNonIdle => {
            println!(
                "Skipped: an update is already in flight (state is non-idle). \
                 Restart the daemon or wait for probation to complete."
            );
        }
        open_attest_updater::UpdateOutcome::Failed { version, reason } => {
            bail!("Update to {version} failed: {reason}");
        }
    }
    Ok(())
}

/// True for check keys that come from the heavy inventory collectors.
/// Drift detection ignores these — an inventory delta shouldn't trigger
/// an extra attestation between regular snapshots.
fn is_inventory_key(key: &str) -> bool {
    key == "apps.installed" || key == "browser_extensions"
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

/// Maximum age of inventory data before the next snapshot tick re-collects it.
/// Heavy collectors (installed apps, eventually browser extensions) only run
/// on this cadence; intervening snapshots ship cheap checks only.
const INVENTORY_INTERVAL_SECS: u64 = 86_400; // 24 hours

/// Returns true if the daemon should exit (a successful swap happened and we
/// want the supervisor to restart us on the new binary).
fn handle_update_offer(
    offer: Option<UpdateOffer>,
    ctx: &open_attest_updater::UpdateContext,
) -> bool {
    let Some(offer) = offer else {
        return false;
    };
    match open_attest_updater::check_and_apply(&offer, ctx) {
        Ok(open_attest_updater::UpdateOutcome::Installed { version }) => {
            // Windows has no supervisor for the ONLOGON task, so the daemon
            // may only exit once a restart is actually booked. If booking it
            // fails, keep running the old code — the swapped binary still
            // takes effect at the next logon.
            #[cfg(target_os = "windows")]
            if let Err(e) = winsvc::schedule_restart() {
                eprintln!(
                    "[{}] Update to {} installed but scheduling the restart failed: {:#}; \
                     staying up, the new binary takes effect at next logon",
                    now_iso(),
                    version,
                    e
                );
                return false;
            }
            eprintln!(
                "[{}] Update to {} installed; exiting for supervisor restart",
                now_iso(),
                version
            );
            true
        }
        Ok(outcome) => {
            // Skip variants and Failed both stay quiet at info level — these
            // are expected behaviors (already-at-version, rate-limited, etc.).
            eprintln!("[{}] Update offer: {:?}", now_iso(), outcome);
            false
        }
        Err(e) => {
            eprintln!("[{}] Update check failed: {:#}", now_iso(), e);
            false
        }
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

    // Build the updater context once; reuse for every check. If the boot-time
    // check rolls back, we exit cleanly so the supervisor restarts on the
    // restored .prev binary.
    let updater_state_dir = config::state_dir()?;
    let updater_bin_path = config::managed_binary_path()?;
    let updater_current_exe = std::env::current_exe().context("current_exe")?;
    let updater_ctx = open_attest_updater::UpdateContext {
        state_dir: &updater_state_dir,
        bin_path: &updater_bin_path,
        current_exe: &updater_current_exe,
        running_version: AGENT_VERSION,
        running_target_triple: BUILD_TARGET,
        release_pubkey: open_attest_updater::RELEASE_PUBKEY,
    };
    match open_attest_updater::on_daemon_boot(&updater_ctx) {
        Ok(open_attest_updater::BootAction::RolledBack) => {
            eprintln!(
                "[{}] Rollback complete; exiting for supervisor restart on previous binary",
                now_iso()
            );
            return Ok(());
        }
        Ok(open_attest_updater::BootAction::Confirmed) => {
            eprintln!(
                "[{}] Update to {} confirmed; previous binary cleaned up",
                now_iso(),
                AGENT_VERSION
            );
        }
        Ok(open_attest_updater::BootAction::None) => {}
        Err(e) => eprintln!("[{}] on_daemon_boot failed: {:#}", now_iso(), e),
    }

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
    let mut last_inventory_at: Option<tokio::time::Instant> = None;
    let inventory_interval = tokio::time::Duration::from_secs(INVENTORY_INTERVAL_SECS);

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
                    Ok(response) => {
                        eprintln!("[{}] Heartbeat sent", now_iso());
                        let _ = open_attest_updater::record_successful_attestation(&updater_state_dir);
                        drain_retry_queue(&queue, &cfg, &key_store);
                        if handle_update_offer(response.update_offer, &updater_ctx) {
                            return Ok(());
                        }
                    }
                    Err(e) => eprintln!("[{}] Heartbeat failed: {}", now_iso(), e),
                }
            }
            _ = snapshot_timer.tick() => {
                let include_inventory = last_inventory_at
                    .map(|t| t.elapsed() >= inventory_interval)
                    .unwrap_or(true);
                let mut checks = collect_all();
                if include_inventory {
                    checks.extend(collect_inventory());
                }
                let payload = build_attestation_payload(&cfg, checks);
                let payload_json = serde_json::to_string(&payload)?;
                let sign_fn = |data: &[u8]| -> String {
                    key_store.sign(data).expect("Signing failed")
                };
                match open_attest_transport::submit_attestation(
                    &cfg.server_url, &cfg.agent_id, &payload, &sign_fn
                ) {
                    Ok(response) => {
                        eprintln!(
                            "[{}] Attestation submitted ({} checks{})",
                            now_iso(),
                            payload.checks.len(),
                            if include_inventory { ", with inventory" } else { "" },
                        );
                        if include_inventory {
                            last_inventory_at = Some(tokio::time::Instant::now());
                        }
                        last_checks = Some(payload.checks.clone());
                        let _ = open_attest_updater::record_successful_attestation(&updater_state_dir);
                        drain_retry_queue(&queue, &cfg, &key_store);
                        if handle_update_offer(response.update_offer, &updater_ctx) {
                            return Ok(());
                        }
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
                    // Compare only cheap checks; ignore inventory entries that
                    // the previous snapshot may have carried.
                    let prev_cheap: Vec<_> = prev.iter()
                        .filter(|c| !is_inventory_key(&c.key))
                        .cloned()
                        .collect();
                    let changed = detect_drift(&prev_cheap, &current_checks);
                    if !changed.is_empty() {
                        eprintln!(
                            "[{}] Drift detected in {} checks, submitting attestation",
                            now_iso(),
                            changed.len()
                        );
                        for key in &changed {
                            eprintln!("[{}]   Changed: {}", now_iso(), key);
                        }
                        // Drift attestations are cheap-only — no inventory.
                        let payload = build_attestation_payload(&cfg, current_checks.clone());
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

fn main() {
    let cli = Cli::parse();

    // Most subcommands are synchronous and use blocking HTTP; only `daemon`
    // needs an async runtime. Wrapping everything in `#[tokio::main]` causes
    // blocking reqwest clients to panic on drop ("Cannot drop a runtime in a
    // context where blocking is not allowed").
    let result = match cli.command {
        Commands::Enroll { token, server } => do_enroll(token, server),
        Commands::Status => do_status(),
        Commands::Repair => do_repair(),
        Commands::Check { json } => do_check(json),
        Commands::Attest => do_attest(),
        Commands::Uninstall => do_uninstall(),
        Commands::Daemon => {
            let rt = tokio::runtime::Runtime::new().expect("failed to create tokio runtime");
            rt.block_on(do_daemon())
        }
        Commands::Web => do_web(),
        Commands::Update { force } => do_update(force),
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
    use tempfile::tempdir;

    #[test]
    fn stage_binary_creates_missing_parent_dirs() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("open-attest");
        let dst = dir.path().join("Application Support/open-attest/bin/open-attest");
        std::fs::write(&src, b"agent v1").unwrap();

        stage_binary(&src, &dst).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"agent v1");
        // Source stays put: it may be the binary the user installed on $PATH.
        assert!(src.exists());
    }

    #[cfg(unix)]
    #[test]
    fn stage_binary_makes_the_copy_executable() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("bin").join("open-attest");
        std::fs::write(&src, b"agent").unwrap();
        std::fs::set_permissions(&src, std::fs::Permissions::from_mode(0o644)).unwrap();

        stage_binary(&src, &dst).unwrap();
        let mode = std::fs::metadata(&dst).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }

    #[test]
    fn stage_binary_replaces_an_older_copy() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("bin").join("open-attest");
        std::fs::create_dir_all(dst.parent().unwrap()).unwrap();
        std::fs::write(&dst, b"agent v1").unwrap();
        std::fs::write(&src, b"agent v2").unwrap();

        stage_binary(&src, &dst).unwrap();
        assert_eq!(std::fs::read(&dst).unwrap(), b"agent v2");
        // No .incoming left behind.
        assert!(!dir.path().join("bin").join("open-attest.incoming").exists());
    }

    #[test]
    fn stage_binary_fails_when_source_is_missing() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("nope");
        let dst = dir.path().join("bin").join("open-attest");
        assert!(stage_binary(&src, &dst).is_err());
        assert!(!dst.exists());
    }

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
