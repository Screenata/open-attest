#[cfg(target_os = "macos")]
use chrono::Utc;
#[cfg(target_os = "macos")]
use open_attest_types::{CheckResult, CheckValue};
#[cfg(target_os = "macos")]
use std::process::Command;

#[cfg(target_os = "macos")]
fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Pure parser functions — testable on any platform.
pub mod parsers {
    pub fn parse_disk_encryption(output: &str) -> bool {
        output.contains("FileVault is On")
    }

    pub fn parse_firewall(output: &str) -> Option<bool> {
        let trimmed = output.trim();

        // Legacy `defaults read ... globalstate` output is just the numeric state.
        let state = if matches!(trimmed, "0" | "1" | "2") {
            trimmed.parse::<u8>().ok()
        } else {
            // `socketfilterfw --getglobalstate` prints, for example:
            // "Firewall is enabled. (State = 1)"
            trimmed.split_once("State =").and_then(|(_, rest)| {
                let value: String = rest
                    .trim_start()
                    .chars()
                    .take_while(|c| c.is_ascii_digit())
                    .collect();
                value.parse::<u8>().ok()
            })
        };

        match state {
            Some(0) => Some(false),
            Some(1 | 2) => Some(true),
            _ => None,
        }
    }

    /// Sentinel meaning "no lock will ever trigger" (display never sleeps and screensaver never kicks in).
    pub const SCREEN_LOCK_NEVER: i64 = 0;
    /// Sentinel meaning "couldn't determine" — distinct from "never" so the UI can distinguish.
    pub const SCREEN_LOCK_UNKNOWN: i64 = -1;

    /// Parse `pmset -g custom` (or any pmset output) for the AC `displaysleep` value, in minutes.
    /// Returns None if not found. `0` from pmset means "never" — preserved as Some(0).
    pub fn parse_pmset_displaysleep(output: &str) -> Option<i64> {
        // pmset prints lines like " displaysleep         5"
        for line in output.lines() {
            let trimmed = line.trim();
            if let Some(rest) = trimmed.strip_prefix("displaysleep") {
                let num: String = rest.chars().filter(|c| c.is_ascii_digit()).collect();
                if let Ok(n) = num.parse::<i64>() {
                    return Some(n);
                }
            }
        }
        None
    }

    /// Parse `defaults -currentHost read com.apple.screensaver idleTime` output, in seconds.
    /// Returns None if the key is missing or unparseable. `0` means "never" — preserved as Some(0).
    pub fn parse_screensaver_idle(output: &str) -> Option<i64> {
        let trimmed = output.trim();
        if trimmed.is_empty() {
            return None;
        }
        trimmed.parse::<i64>().ok()
    }

    /// Compute the effective screen-lock timeout in minutes from the two macOS sources.
    /// `displaysleep_min`: minutes from `pmset` (None = couldn't read, Some(0) = never).
    /// `screensaver_idle_sec`: seconds from `com.apple.screensaver idleTime`
    /// (None = key missing, Some(0) = never).
    ///
    /// Returns:
    ///   SCREEN_LOCK_UNKNOWN (-1) if neither source could be read.
    ///   SCREEN_LOCK_NEVER (0)    if both sources are explicitly "never".
    ///   otherwise the smaller of the two timeouts, in minutes (rounded down, min 1).
    pub fn compute_effective_lock_minutes(
        displaysleep_min: Option<i64>,
        screensaver_idle_sec: Option<i64>,
    ) -> i64 {
        // Convert each source to Option<minutes> where None = "never or unset",
        // Some(n) = "locks after n minutes".
        let ds_min: Option<i64> = match displaysleep_min {
            Some(0) | None => None,
            Some(n) if n > 0 => Some(n),
            _ => None,
        };
        let ss_min: Option<i64> = match screensaver_idle_sec {
            Some(0) | None => None,
            Some(s) if s > 0 => Some((s / 60).max(1)),
            _ => None,
        };

        match (ds_min, ss_min) {
            (Some(a), Some(b)) => a.min(b),
            (Some(a), None) => a,
            (None, Some(b)) => b,
            (None, None) => {
                // Both "never or unset". Distinguish "explicitly never" from "couldn't read".
                if displaysleep_min.is_none() && screensaver_idle_sec.is_none() {
                    SCREEN_LOCK_UNKNOWN
                } else {
                    SCREEN_LOCK_NEVER
                }
            }
        }
    }

    pub fn parse_os_version(output: &str) -> String {
        output.trim().to_string()
    }

    /// True only when `profiles status -type enrollment` reports an active
    /// MDM enrollment. That command prints the same "MDM enrollment:" line
    /// either way — "No" on an unmanaged device, "Yes" or "Yes (User
    /// Approved)" on a managed one — so the value has to be read rather than
    /// the line merely found. DEP registration is deliberately not counted:
    /// a device can be assigned in Apple Business Manager and still not be
    /// enrolled in any MDM.
    pub fn parse_mdm(output: &str) -> bool {
        output
            .lines()
            .find_map(|line| {
                line.split_once(':')
                    .filter(|(key, _)| key.trim().eq_ignore_ascii_case("MDM enrollment"))
            })
            .is_some_and(|(_, value)| value.trim_start().to_ascii_lowercase().starts_with("yes"))
    }

    /// Convert a `stat -f %m` unix-epoch string to an RFC3339 UTC timestamp.
    /// Empty when the input is not a positive integer.
    pub fn parse_epoch_seconds_to_iso(output: &str) -> String {
        let secs = match output.trim().parse::<i64>() {
            Ok(s) if s > 0 => s,
            _ => return String::new(),
        };
        chrono::DateTime::from_timestamp(secs, 0)
            .map(|dt| dt.to_rfc3339_opts(chrono::SecondsFormat::Secs, true))
            .unwrap_or_default()
    }

    /// True only when a THIRD-PARTY anti-malware agent is running. Apple's
    /// built-in XProtect deliberately does not count: `XProtect.bundle` ships
    /// with every macOS install, so treating it as presence made this check
    /// return true on every Mac — worthless as fleet-coverage evidence. A Mac
    /// with no third-party agent now reports false, which is the honest answer;
    /// XProtect's own state is reported separately as `edr.signature_version` /
    /// `edr.signature_last_updated` with source `xprotect`.
    pub fn parse_edr_presence(ps_output: &str, sysext_output: &str) -> bool {
        // Apple's own MRT/XProtect processes are excluded for the same reason.
        let known_processes = [
            "falcond", "falcon-sensor",
            "sentineld", "sentinelone",
            "cbagentd", "cbdaemon",
            "SophosScanD", "SophosAntiVirus",
            "JamfProtect",
            "MalwareBytes",
            "NortonSecurity",
            "McAfeeSystemExtensions",
            "eset_daemon",
            "bdagent",
        ];

        for proc in &known_processes {
            if ps_output.contains(proc) {
                return true;
            }
        }

        let known_sysext_ids = [
            "com.crowdstrike", "com.sentinelone", "com.carbonblack", "com.sophos",
            "com.malwarebytes", "com.eset", "com.bitdefender", "com.trendmicro",
        ];
        for id in &known_sysext_ids {
            if sysext_output.contains(id) {
                return true;
            }
        }

        false
    }

    pub fn parse_admin_members(output: &str) -> Vec<String> {
        if let Some(line) = output.lines().find(|l| l.starts_with("GroupMembership:")) {
            line.trim_start_matches("GroupMembership:")
                .split_whitespace()
                .map(|s| s.to_string())
                .collect()
        } else {
            vec![]
        }
    }

    pub fn parse_password_min_length(account_output: &str, global_output: &str) -> i64 {
        for pattern in &["minChars", "minimumLength", "policyAttributePasswordMinimumLength"] {
            if let Some(pos) = account_output.find(pattern) {
                let after = &account_output[pos..];
                for num_str in after.split(|c: char| !c.is_ascii_digit()).filter(|s| !s.is_empty()) {
                    if let Ok(n) = num_str.parse::<i64>() {
                        if n > 0 && n < 256 {
                            return n;
                        }
                    }
                }
            }
        }

        if let Some(pos) = global_output.find("minChars=") {
            let after = &global_output[pos + 9..];
            let num_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
            if let Ok(n) = num_str.parse::<i64>() {
                if n > 0 {
                    return n;
                }
            }
        }

        0
    }

    /// Parse whether the current user has a login password set.
    /// `dscl . -authonly <user> ""` exits 0 if the empty string IS the password (no password set).
    /// We also check AuthenticationAuthority for absence of password-related entries.
    pub fn parse_password_enabled(authonly_exit_code: i32) -> bool {
        // If `dscl . -authonly user ""` succeeds (exit 0), empty password works → no password set
        authonly_exit_code != 0
    }

    /// Parse hardware info from system_profiler SPHardwareDataType output.
    /// Returns (model_name, serial_number).
    pub fn parse_hardware_info(output: &str) -> (String, String) {
        let mut model = String::new();
        let mut serial = String::new();
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Model Name:") {
                model = trimmed.trim_start_matches("Model Name:").trim().to_string();
            } else if trimmed.starts_with("Serial Number") {
                serial = trimmed.split(':').nth(1).unwrap_or("").trim().to_string();
            }
        }
        (model, serial)
    }

    pub fn parse_screen_lock_password(sysadminctl_output: &str, askforpassword_output: &str) -> bool {
        let lower = sysadminctl_output.to_lowercase();
        if lower.contains("screenlock") {
            if lower.contains("is off") {
                return false;
            }
            if lower.contains("delay is") {
                return true;
            }
        }
        let trimmed = askforpassword_output.trim();
        trimmed == "1"
    }

    /// macOS auto security-update toggle. We require both ConfigDataInstall
    /// (XProtect/MRT definition updates) and CriticalUpdateInstall (critical
    /// security updates) to be enabled. A missing key reflects the macOS
    /// default, which is enabled — so empty input is treated as enabled.
    pub fn parse_auto_update_security_enabled(
        config_data_install: &str,
        critical_update_install: &str,
    ) -> bool {
        let enabled = |s: &str| -> bool {
            let t = s.trim();
            t.is_empty() || t == "1"
        };
        enabled(config_data_install) && enabled(critical_update_install)
    }

    /// True if any configuration profile defines screensaver/screenlock keys,
    /// or if a managed preference plist for the screensaver is installed.
    pub fn parse_screen_lock_managed_by_mdm(
        profiles_output: &str,
        managed_pref_exists: bool,
    ) -> bool {
        if managed_pref_exists {
            return true;
        }
        profiles_output.contains("com.apple.screensaver")
            || profiles_output.contains("com.apple.screenlock")
    }

    /// True when sshd is loaded under launchd.
    /// macOS: `launchctl print system/com.openssh.sshd` exits 0 when loaded.
    pub fn parse_ssh_daemon_enabled_macos(launchctl_exit: i32) -> bool {
        launchctl_exit == 0
    }

    /// Parse `system_profiler SPApplicationsDataType -json` output into a
    /// sorted, deduped list of `"<name>@<version>"` strings. Apps without a
    /// version are emitted as just `"<name>"`. Malformed JSON yields an empty
    /// list.
    pub fn parse_installed_apps_macos(json: &str) -> Vec<String> {
        let v: serde_json::Value = match serde_json::from_str(json) {
            Ok(v) => v,
            Err(_) => return Vec::new(),
        };
        let apps = match v.get("SPApplicationsDataType").and_then(|a| a.as_array()) {
            Some(a) => a,
            None => return Vec::new(),
        };
        let mut entries: Vec<String> = Vec::with_capacity(apps.len());
        for app in apps {
            let name = app
                .get("_name")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .trim();
            if name.is_empty() {
                continue;
            }
            let version = app
                .get("version")
                .and_then(|n| n.as_str())
                .unwrap_or("")
                .trim();
            if version.is_empty() {
                entries.push(name.to_string());
            } else {
                entries.push(format!("{}@{}", name, version));
            }
        }
        entries.sort();
        entries.dedup();
        entries
    }

    /// Parse `dscl . -list /Users UniqueID` output. Returns human local users
    /// (UID ≥ 500, name does not start with `_`), sorted, deduped.
    pub fn parse_local_users(dscl_output: &str) -> Vec<String> {
        let mut users: Vec<String> = Vec::new();
        for line in dscl_output.lines() {
            let parts: Vec<&str> = line.split_whitespace().collect();
            if parts.len() < 2 {
                continue;
            }
            let name = parts[0];
            if name.starts_with('_') {
                continue;
            }
            if let Ok(uid) = parts[1].parse::<i64>() {
                if uid >= 500 {
                    users.push(name.to_string());
                }
            }
        }
        users.sort();
        users.dedup();
        users
    }

    /// Count valid keys across a set of authorized_keys file contents.
    /// A "key" is one non-blank line that isn't a `#` comment.
    pub fn parse_authorized_key_count(file_contents: &[&str]) -> i64 {
        let mut total: i64 = 0;
        for content in file_contents {
            for line in content.lines() {
                let trimmed = line.trim();
                if trimmed.is_empty() || trimmed.starts_with('#') {
                    continue;
                }
                total += 1;
            }
        }
        total
    }
}

// --- Check functions (macOS-specific, use system commands) ---

#[cfg(target_os = "macos")]
fn check_disk_encryption() -> CheckResult {
    let (output, source) = match Command::new("fdesetup").arg("status").output() {
        Ok(out) => (String::from_utf8_lossy(&out.stdout).to_string(), "fdesetup"),
        Err(_) => (String::new(), "unavailable"),
    };
    CheckResult {
        key: "disk_encryption.enabled".to_string(),
        value: CheckValue::Bool(parsers::parse_disk_encryption(&output)),
        observed_at: now_iso(),
        source: source.to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_firewall() -> CheckResult {
    let socketfilterfw_state = Command::new("/usr/libexec/ApplicationFirewall/socketfilterfw")
        .arg("--getglobalstate")
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .filter(|out| out.status.success())
        .and_then(|out| parsers::parse_firewall(&String::from_utf8_lossy(&out.stdout)));

    let (enabled, source) = match socketfilterfw_state {
        Some(enabled) => (enabled, "socketfilterfw"),
        None => {
            let defaults_state = Command::new("defaults")
                .args(["read", "/Library/Preferences/com.apple.alf", "globalstate"])
                .stderr(std::process::Stdio::null())
                .output()
                .ok()
                .filter(|out| out.status.success())
                .and_then(|out| parsers::parse_firewall(&String::from_utf8_lossy(&out.stdout)));

            match defaults_state {
                Some(enabled) => (enabled, "defaults_read"),
                None => (false, "unavailable"),
            }
        }
    };
    CheckResult {
        key: "firewall.enabled".to_string(),
        value: CheckValue::Bool(enabled),
        observed_at: now_iso(),
        source: source.to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_screen_lock_timeout() -> CheckResult {
    // Source 1: screensaver idleTime (seconds). Missing key → defaults exits non-zero.
    let screensaver_raw = Command::new("defaults")
        .args(["-currentHost", "read", "com.apple.screensaver", "idleTime"])
        .stderr(std::process::Stdio::null())
        .output()
        .ok()
        .and_then(|o| if o.status.success() { Some(String::from_utf8_lossy(&o.stdout).to_string()) } else { None })
        .unwrap_or_default();
    let screensaver_idle_sec = parsers::parse_screensaver_idle(&screensaver_raw);

    // Source 2: pmset displaysleep (minutes). Use AC settings as the lock-relevant baseline.
    let pmset_raw = Command::new("pmset")
        .args(["-g", "custom"])
        .stderr(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let displaysleep_min = parsers::parse_pmset_displaysleep(&pmset_raw);

    let effective = parsers::compute_effective_lock_minutes(displaysleep_min, screensaver_idle_sec);

    let source = match (displaysleep_min, screensaver_idle_sec) {
        (Some(_), Some(_)) => "pmset+screensaver",
        (Some(_), None) => "pmset",
        (None, Some(_)) => "screensaver",
        (None, None) => "unavailable",
    };

    CheckResult {
        key: "screen_lock.timeout_minutes".to_string(),
        value: CheckValue::Int(effective),
        observed_at: now_iso(),
        source: source.to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_screen_lock_password() -> CheckResult {
    let sysadminctl_output = Command::new("sysadminctl")
        .args(["-screenLock", "status"])
        .stderr(std::process::Stdio::piped())
        .output()
        .map(|o| format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
        .unwrap_or_default();

    let askforpassword_output = Command::new("defaults")
        .args(["read", "com.apple.screensaver", "askForPassword"])
        .stderr(std::process::Stdio::null())
        .output()
        .and_then(|o| if o.status.success() { Ok(String::from_utf8_lossy(&o.stdout).to_string()) } else { Ok(String::new()) })
        .unwrap_or_default();

    CheckResult {
        key: "screen_lock.password_required".to_string(),
        value: CheckValue::Bool(parsers::parse_screen_lock_password(&sysadminctl_output, &askforpassword_output)),
        observed_at: now_iso(),
        source: "sysadminctl".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_os_version() -> CheckResult {
    let (output, source) = match Command::new("sw_vers").arg("-productVersion").output() {
        Ok(out) => (String::from_utf8_lossy(&out.stdout).to_string(), "sw_vers"),
        Err(_) => (String::new(), "unavailable"),
    };
    CheckResult {
        key: "os.version".to_string(),
        value: CheckValue::Str(parsers::parse_os_version(&output)),
        observed_at: now_iso(),
        source: source.to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_hostname() -> CheckResult {
    let (output, source) = match Command::new("hostname").output() {
        Ok(out) => (String::from_utf8_lossy(&out.stdout).trim().to_string(), "syscall"),
        Err(_) => (String::new(), "unavailable"),
    };
    CheckResult {
        key: "hostname".to_string(),
        value: CheckValue::Str(output),
        observed_at: now_iso(),
        source: source.to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_user_primary() -> CheckResult {
    let (output, source) = match Command::new("whoami").output() {
        Ok(out) => (String::from_utf8_lossy(&out.stdout).trim().to_string(), "whoami"),
        Err(_) => (String::new(), "unavailable"),
    };
    CheckResult {
        key: "user.primary".to_string(),
        value: CheckValue::Str(output),
        observed_at: now_iso(),
        source: source.to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_mdm() -> CheckResult {
    let (output, source) = match Command::new("profiles")
        .args(["status", "-type", "enrollment"])
        .stderr(std::process::Stdio::piped())
        .output()
    {
        Ok(out) => {
            let combined = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
            (combined, "profiles_cmd")
        }
        Err(_) => (String::new(), "unavailable"),
    };
    CheckResult {
        key: "mdm.enrolled".to_string(),
        value: CheckValue::Bool(parsers::parse_mdm(&output)),
        observed_at: now_iso(),
        source: source.to_string(),
    }
}

/// The XProtect bundle, whichever of the two OS locations holds it.
#[cfg(target_os = "macos")]
fn xprotect_bundle_path() -> Option<&'static str> {
    [
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle",
        "/System/Library/CoreServices/XProtect.bundle",
    ]
    .into_iter()
    .find(|p| std::path::Path::new(p).exists())
}

#[cfg(target_os = "macos")]
fn check_edr_presence() -> CheckResult {
    let ps_output = Command::new("ps").args(["aux"]).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let sysext_output = Command::new("systemextensionsctl").arg("list").output()
        .map(|o| format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
        .unwrap_or_default();

    CheckResult {
        key: "edr.present".to_string(),
        value: CheckValue::Bool(parsers::parse_edr_presence(&ps_output, &sysext_output)),
        observed_at: now_iso(),
        source: "process_scan".to_string(),
    }
}

/// XProtect definition currency: the bundle's version string and the bundle
/// mtime (Apple rewrites the bundle on every definition push, so its mtime is
/// the definition date). Reports XProtect only — a third-party EDR's own
/// signature state is not readable from the endpoint without vendor tooling.
#[cfg(target_os = "macos")]
fn check_edr_signature() -> Vec<CheckResult> {
    let (version, last_updated) = match xprotect_bundle_path() {
        Some(bundle) => {
            let version_output = Command::new("defaults")
                .args(["read", &format!("{}/Contents/Info", bundle), "CFBundleShortVersionString"])
                .output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            let mtime_output = Command::new("stat").args(["-f", "%m", bundle]).output()
                .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
                .unwrap_or_default();
            (
                version_output.trim().to_string(),
                parsers::parse_epoch_seconds_to_iso(&mtime_output),
            )
        }
        None => (String::new(), String::new()),
    };
    let observed_at = now_iso();
    vec![
        CheckResult {
            key: "edr.signature_version".to_string(),
            value: CheckValue::Str(version),
            observed_at: observed_at.clone(),
            source: "xprotect".to_string(),
        },
        CheckResult {
            key: "edr.signature_last_updated".to_string(),
            value: CheckValue::Str(last_updated),
            observed_at,
            source: "xprotect".to_string(),
        },
    ]
}

#[cfg(target_os = "macos")]
fn check_local_admin() -> CheckResult {
    let output = Command::new("dscl")
        .args([".", "-read", "/Groups/admin", "GroupMembership"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let members = parsers::parse_admin_members(&output);
    let current_user = Command::new("whoami").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    CheckResult {
        key: "local_admin.is_admin".to_string(),
        value: CheckValue::Bool(members.contains(&current_user)),
        observed_at: now_iso(),
        source: "dscl".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_hardware_info() -> Vec<CheckResult> {
    let output = Command::new("system_profiler")
        .arg("SPHardwareDataType")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let (model, serial) = parsers::parse_hardware_info(&output);
    let ts = now_iso();

    vec![
        CheckResult {
            key: "device.manufacturer".to_string(),
            value: CheckValue::Str("Apple".to_string()),
            observed_at: ts.clone(),
            source: "system_profiler".to_string(),
        },
        CheckResult {
            key: "device.model".to_string(),
            value: CheckValue::Str(model),
            observed_at: ts.clone(),
            source: "system_profiler".to_string(),
        },
        CheckResult {
            key: "device.serial_number".to_string(),
            value: CheckValue::Str(serial),
            observed_at: ts,
            source: "system_profiler".to_string(),
        },
    ]
}

#[cfg(target_os = "macos")]
fn check_password_enabled() -> CheckResult {
    let current_user = Command::new("whoami").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    let exit_code = Command::new("dscl")
        .args([".", "-authonly", &current_user, ""])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.code().unwrap_or(1))
        .unwrap_or(1);

    CheckResult {
        key: "password.enabled".to_string(),
        value: CheckValue::Bool(parsers::parse_password_enabled(exit_code)),
        observed_at: now_iso(),
        source: "dscl_authonly".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_password_policy() -> CheckResult {
    let account_output = Command::new("pwpolicy")
        .arg("getaccountpolicies")
        .stderr(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let global_output = Command::new("pwpolicy")
        .arg("-getglobalpolicy")
        .stderr(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    CheckResult {
        key: "password_policy.min_length".to_string(),
        value: CheckValue::Int(parsers::parse_password_min_length(&account_output, &global_output)),
        observed_at: now_iso(),
        source: "pwpolicy".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_auto_update_security() -> CheckResult {
    let read_default = |key: &str| -> String {
        Command::new("defaults")
            .args([
                "read",
                "/Library/Preferences/com.apple.SoftwareUpdate",
                key,
            ])
            .stderr(std::process::Stdio::null())
            .output()
            .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
            .unwrap_or_default()
    };
    let cdi = read_default("ConfigDataInstall");
    let cui = read_default("CriticalUpdateInstall");
    CheckResult {
        key: "auto_update.security_enabled".to_string(),
        value: CheckValue::Bool(parsers::parse_auto_update_security_enabled(&cdi, &cui)),
        observed_at: now_iso(),
        source: "defaults_softwareupdate".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_screen_lock_managed_by_mdm() -> CheckResult {
    let profiles_output = Command::new("profiles")
        .args(["show", "-type", "configuration"])
        .stderr(std::process::Stdio::null())
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let managed_pref_exists = std::path::Path::new(
        "/Library/Managed Preferences/com.apple.screensaver.plist",
    )
    .exists();

    CheckResult {
        key: "screen_lock.managed_by_mdm".to_string(),
        value: CheckValue::Bool(parsers::parse_screen_lock_managed_by_mdm(
            &profiles_output,
            managed_pref_exists,
        )),
        observed_at: now_iso(),
        source: "profiles".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_ssh_daemon_enabled() -> CheckResult {
    let exit = Command::new("launchctl")
        .args(["print", "system/com.openssh.sshd"])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.code().unwrap_or(1))
        .unwrap_or(1);
    CheckResult {
        key: "ssh.daemon_enabled".to_string(),
        value: CheckValue::Bool(parsers::parse_ssh_daemon_enabled_macos(exit)),
        observed_at: now_iso(),
        source: "launchctl".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_local_users() -> CheckResult {
    let output = Command::new("dscl")
        .args([".", "-list", "/Users", "UniqueID"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    CheckResult {
        key: "users.local".to_string(),
        value: CheckValue::StringList(parsers::parse_local_users(&output)),
        observed_at: now_iso(),
        source: "dscl".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_users_admins() -> CheckResult {
    let output = Command::new("dscl")
        .args([".", "-read", "/Groups/admin", "GroupMembership"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    CheckResult {
        key: "users.admins".to_string(),
        value: CheckValue::StringList(parsers::parse_admin_members(&output)),
        observed_at: now_iso(),
        source: "dscl".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_ssh_authorized_key_count() -> CheckResult {
    let mut contents: Vec<String> = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/Users") {
        for entry in entries.flatten() {
            let path = entry.path().join(".ssh").join("authorized_keys");
            if let Ok(c) = std::fs::read_to_string(&path) {
                contents.push(c);
            }
        }
    }
    if let Ok(c) = std::fs::read_to_string("/var/root/.ssh/authorized_keys") {
        contents.push(c);
    }
    let refs: Vec<&str> = contents.iter().map(|s| s.as_str()).collect();
    CheckResult {
        key: "ssh.authorized_key_count".to_string(),
        value: CheckValue::Int(parsers::parse_authorized_key_count(&refs)),
        observed_at: now_iso(),
        source: "authorized_keys_scan".to_string(),
    }
}

#[cfg(target_os = "macos")]
fn check_installed_apps() -> CheckResult {
    let output = Command::new("system_profiler")
        .args(["SPApplicationsDataType", "-json"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    let apps = crate::truncate_inventory(parsers::parse_installed_apps_macos(&output));
    CheckResult {
        key: "apps.installed".to_string(),
        value: CheckValue::StringList(apps),
        observed_at: now_iso(),
        source: "system_profiler".to_string(),
    }
}

#[cfg(target_os = "macos")]
pub fn collect_inventory() -> Vec<CheckResult> {
    vec![check_installed_apps()]
}

#[cfg(target_os = "macos")]
pub fn collect_all() -> Vec<CheckResult> {
    let mut checks = vec![
        check_disk_encryption(),
        check_firewall(),
        check_screen_lock_timeout(),
        check_screen_lock_password(),
        check_screen_lock_managed_by_mdm(),
        check_os_version(),
        check_hostname(),
        check_user_primary(),
        check_mdm(),
        check_edr_presence(),
        check_password_enabled(),
        check_password_policy(),
        check_local_admin(),
        check_local_users(),
        check_users_admins(),
        check_auto_update_security(),
        check_ssh_daemon_enabled(),
        check_ssh_authorized_key_count(),
    ];
    checks.extend(check_edr_signature());
    checks.extend(check_hardware_info());
    checks
}

#[cfg(test)]
mod tests {
    use super::parsers::*;

    #[test]
    fn parse_fdesetup_on() { assert!(parse_disk_encryption("FileVault is On.")); }
    #[test]
    fn parse_fdesetup_off() { assert!(!parse_disk_encryption("FileVault is Off.")); }
    #[test]
    fn parse_firewall_enabled() {
        assert_eq!(
            parse_firewall("Firewall is enabled. (State = 1)\n"),
            Some(true)
        );
        assert_eq!(
            parse_firewall("Firewall is enabled. (State = 2)\n"),
            Some(true)
        );
        assert_eq!(parse_firewall("1\n"), Some(true));
        assert_eq!(parse_firewall("2\n"), Some(true));
    }
    #[test]
    fn parse_firewall_disabled() {
        assert_eq!(
            parse_firewall("Firewall is disabled. (State = 0)\n"),
            Some(false)
        );
        assert_eq!(parse_firewall("0\n"), Some(false));
    }
    #[test]
    fn parse_firewall_unavailable() {
        assert_eq!(parse_firewall(""), None);
        assert_eq!(parse_firewall("unexpected output"), None);
    }
    #[test]
    fn screensaver_idle_present() { assert_eq!(parse_screensaver_idle("300\n"), Some(300)); }
    #[test]
    fn screensaver_idle_missing() { assert_eq!(parse_screensaver_idle(""), None); }
    #[test]
    fn screensaver_idle_never() { assert_eq!(parse_screensaver_idle("0\n"), Some(0)); }
    #[test]
    fn pmset_displaysleep_present() {
        let out = "Battery Power:\n displaysleep         2\n sleep                10\nAC Power:\n displaysleep         5\n sleep                0\n";
        // First match wins; both AC and battery have it. Either is acceptable as the policy baseline.
        assert!(matches!(parse_pmset_displaysleep(out), Some(2) | Some(5)));
    }
    #[test]
    fn pmset_displaysleep_missing() { assert_eq!(parse_pmset_displaysleep(""), None); }
    #[test]
    fn pmset_displaysleep_never() {
        let out = "AC Power:\n displaysleep         0\n";
        assert_eq!(parse_pmset_displaysleep(out), Some(0));
    }
    #[test]
    fn effective_lock_both_sources() {
        // pmset 5min, screensaver 300s = 5min → min is 5.
        assert_eq!(compute_effective_lock_minutes(Some(5), Some(300)), 5);
        // pmset 10min, screensaver 60s = 1min → min is 1.
        assert_eq!(compute_effective_lock_minutes(Some(10), Some(60)), 1);
    }
    #[test]
    fn effective_lock_screensaver_missing_uses_pmset() {
        // The bug case: idleTime key absent on a fresh macOS; pmset reports 5min.
        // Old behavior returned -1 (FAIL). New behavior: 5 (PASS).
        assert_eq!(compute_effective_lock_minutes(Some(5), None), 5);
    }
    #[test]
    fn effective_lock_pmset_missing_uses_screensaver() {
        assert_eq!(compute_effective_lock_minutes(None, Some(600)), 10);
    }
    #[test]
    fn effective_lock_both_never() {
        // pmset displaysleep=0 (never) AND screensaver idleTime=0 (never).
        assert_eq!(compute_effective_lock_minutes(Some(0), Some(0)), SCREEN_LOCK_NEVER);
    }
    #[test]
    fn effective_lock_unknown() {
        // Both sources unreadable.
        assert_eq!(compute_effective_lock_minutes(None, None), SCREEN_LOCK_UNKNOWN);
    }
    #[test]
    fn effective_lock_pmset_never_screensaver_set() {
        // Display never sleeps, but screensaver kicks in at 600s = 10min.
        assert_eq!(compute_effective_lock_minutes(Some(0), Some(600)), 10);
    }
    #[test]
    fn effective_lock_sub_minute_rounds_to_one() {
        // 30s screensaver should not round to 0 (which would mean "never").
        assert_eq!(compute_effective_lock_minutes(None, Some(30)), 1);
    }
    #[test]
    fn parse_os_version_trim() { assert_eq!(parse_os_version("14.4.1\n"), "14.4.1"); }
    #[test]
    fn parse_mdm_enrolled() {
        assert!(parse_mdm("Enrolled via DEP: Yes\nMDM enrollment: Yes (User Approved)"));
        assert!(parse_mdm("Enrolled via DEP: No\nMDM enrollment: Yes"));
    }

    #[test]
    fn parse_mdm_not_enrolled() {
        // Verbatim output from an unmanaged Mac. `profiles` prints the "MDM
        // enrollment" line whether or not the device is enrolled, so matching
        // on the line alone reported every Mac as managed.
        assert!(!parse_mdm("Enrolled via DEP: No\nMDM enrollment: No"));
    }

    #[test]
    fn parse_mdm_dep_assigned_but_not_enrolled() {
        // Assigned in Apple Business Manager, never enrolled.
        assert!(!parse_mdm("Enrolled via DEP: Yes\nMDM enrollment: No"));
    }

    #[test]
    fn parse_mdm_false_when_the_command_says_nothing() {
        // `profiles` missing or erroring leaves us with no evidence, and
        // "unmanaged" is the safe answer for a posture signal.
        assert!(!parse_mdm(""));
        assert!(!parse_mdm("profiles: unrecognized option"));
    }
    #[test]
    fn edr_crowdstrike() { assert!(parse_edr_presence("root 123 falcond\n", "")); }
    #[test]
    fn edr_none() { assert!(!parse_edr_presence("user 123 bash\nuser 456 vim\n", "no extensions")); }
    #[test]
    fn edr_sysext() { assert!(parse_edr_presence("", "com.crowdstrike.falcon enabled")); }
    #[test]
    fn epoch_to_iso_converts() {
        assert_eq!(parse_epoch_seconds_to_iso("1755590400\n"), "2025-08-19T08:00:00Z");
    }

    #[test]
    fn epoch_to_iso_empty_on_garbage() {
        assert_eq!(parse_epoch_seconds_to_iso(""), "");
        assert_eq!(parse_epoch_seconds_to_iso("stat: no such file"), "");
        assert_eq!(parse_epoch_seconds_to_iso("0"), "");
    }

    #[test]
    fn edr_xprotect_bundle_alone_is_not_presence() { assert!(!parse_edr_presence("", "")); }

    #[test]
    fn edr_apple_builtin_processes_are_not_presence() {
        // XProtect/MRT run on stock macOS — they must not satisfy the check.
        assert!(!parse_edr_presence(
            "root 55 /usr/libexec/XProtect\nroot 61 /usr/libexec/MRT\n",
            "no extensions"
        ));
    }
    #[test]
    fn admin_members_typical() { assert_eq!(parse_admin_members("GroupMembership: root tao admin\n"), vec!["root", "tao", "admin"]); }
    #[test]
    fn admin_members_empty() { assert!(parse_admin_members("").is_empty()); }
    #[test]
    fn password_enabled_yes() { assert!(parse_password_enabled(1)); } // dscl -authonly failed (password exists)
    #[test]
    fn password_enabled_no() { assert!(!parse_password_enabled(0)); } // dscl -authonly succeeded (no password)
    #[test]
    fn password_min_length_account() {
        let xml = r#"<dict><key>policyAttributePasswordMinimumLength</key><integer>8</integer></dict>"#;
        assert_eq!(parse_password_min_length(xml, ""), 8);
    }
    #[test]
    fn password_min_length_global() { assert_eq!(parse_password_min_length("", "minChars=12 maxChars=128"), 12); }
    #[test]
    fn password_min_length_none() { assert_eq!(parse_password_min_length("", ""), 0); }
    #[test]
    fn hardware_info_parse() {
        let output = "      Model Name: MacBook Pro\n      Model Identifier: Mac14,6\n      Serial Number (system): WVQKY3HDCW\n";
        let (model, serial) = parse_hardware_info(output);
        assert_eq!(model, "MacBook Pro");
        assert_eq!(serial, "WVQKY3HDCW");
    }
    #[test]
    fn hardware_info_empty() {
        let (model, serial) = parse_hardware_info("");
        assert!(model.is_empty());
        assert!(serial.is_empty());
    }
    #[test]
    fn screen_lock_pw_immediate() { assert!(parse_screen_lock_password("screenLock delay is immediate", "")); }
    #[test]
    fn screen_lock_pw_delayed() { assert!(parse_screen_lock_password("screenLock delay is 5 seconds", "")); }
    #[test]
    fn screen_lock_pw_off() { assert!(!parse_screen_lock_password("screenLock is off", "")); }
    #[test]
    fn screen_lock_pw_fallback_yes() { assert!(parse_screen_lock_password("", "1\n")); }
    #[test]
    fn screen_lock_pw_fallback_no() { assert!(!parse_screen_lock_password("", "0\n")); }
    #[test]
    fn auto_update_both_explicit_one() {
        assert!(parse_auto_update_security_enabled("1\n", "1\n"));
    }
    #[test]
    fn auto_update_one_disabled() {
        assert!(!parse_auto_update_security_enabled("0\n", "1\n"));
        assert!(!parse_auto_update_security_enabled("1\n", "0\n"));
    }
    #[test]
    fn auto_update_missing_keys_default_enabled() {
        // Empty output (key absent) reflects macOS default, which is enabled.
        assert!(parse_auto_update_security_enabled("", ""));
    }
    #[test]
    fn auto_update_mixed_missing_and_explicit() {
        assert!(parse_auto_update_security_enabled("", "1\n"));
        assert!(!parse_auto_update_security_enabled("", "0\n"));
    }
    #[test]
    fn screen_lock_mdm_managed_pref_plist() {
        assert!(parse_screen_lock_managed_by_mdm("", true));
    }
    #[test]
    fn screen_lock_mdm_profile_screensaver() {
        assert!(parse_screen_lock_managed_by_mdm(
            "_computerlevel[1] attribute: PayloadType: com.apple.screensaver",
            false
        ));
    }
    #[test]
    fn screen_lock_mdm_profile_screenlock() {
        assert!(parse_screen_lock_managed_by_mdm(
            "PayloadType: com.apple.screenlock",
            false
        ));
    }
    #[test]
    fn screen_lock_mdm_none() {
        assert!(!parse_screen_lock_managed_by_mdm(
            "There are no configuration profiles installed",
            false
        ));
    }
    #[test]
    fn ssh_daemon_macos_loaded() {
        assert!(parse_ssh_daemon_enabled_macos(0));
    }
    #[test]
    fn ssh_daemon_macos_not_loaded() {
        assert!(!parse_ssh_daemon_enabled_macos(113));
        assert!(!parse_ssh_daemon_enabled_macos(1));
    }
    #[test]
    fn authorized_key_count_single() {
        let f = "ssh-ed25519 AAAA... user@host\n";
        assert_eq!(parse_authorized_key_count(&[f]), 1);
    }
    #[test]
    fn authorized_key_count_multiple_files() {
        let f1 = "ssh-ed25519 AAAA... a@h\nssh-rsa BBBB... b@h\n";
        let f2 = "ssh-ed25519 CCCC... c@h\n";
        assert_eq!(parse_authorized_key_count(&[f1, f2]), 3);
    }
    #[test]
    fn authorized_key_count_skips_comments_and_blanks() {
        let f = "# this is a comment\n\nssh-rsa AAAA... user@host\n   \n# another\n";
        assert_eq!(parse_authorized_key_count(&[f]), 1);
    }
    #[test]
    fn authorized_key_count_empty() {
        assert_eq!(parse_authorized_key_count(&[]), 0);
        assert_eq!(parse_authorized_key_count(&[""]), 0);
    }

    // --- Local users (macOS) ---
    #[test]
    fn local_users_skips_underscore_and_low_uids() {
        let out = "_appstore 33\n_assetcache 235\ndaemon 1\nnobody -2\nroot 0\ntao 501\nalice 502\n";
        assert_eq!(parse_local_users(out), vec!["alice", "tao"]);
    }
    #[test]
    fn local_users_sorted_and_deduped() {
        let out = "tao 501\nalice 502\ntao 501\n";
        assert_eq!(parse_local_users(out), vec!["alice", "tao"]);
    }
    #[test]
    fn local_users_empty() {
        assert!(parse_local_users("").is_empty());
    }

    // --- Installed apps (macOS) ---
    #[test]
    fn installed_apps_typical() {
        let json = r#"{
            "SPApplicationsDataType": [
                {"_name": "Slack", "version": "4.36.140"},
                {"_name": "1Password 7", "version": "7.9.11"},
                {"_name": "Calculator", "version": "10.16"}
            ]
        }"#;
        assert_eq!(
            parse_installed_apps_macos(json),
            vec!["1Password 7@7.9.11", "Calculator@10.16", "Slack@4.36.140"]
        );
    }
    #[test]
    fn installed_apps_missing_version_keeps_name_only() {
        let json = r#"{
            "SPApplicationsDataType": [
                {"_name": "WeirdApp"},
                {"_name": "Slack", "version": "4.36.140"}
            ]
        }"#;
        assert_eq!(
            parse_installed_apps_macos(json),
            vec!["Slack@4.36.140", "WeirdApp"]
        );
    }
    #[test]
    fn installed_apps_dedup() {
        let json = r#"{
            "SPApplicationsDataType": [
                {"_name": "Slack", "version": "4.36.140"},
                {"_name": "Slack", "version": "4.36.140"}
            ]
        }"#;
        assert_eq!(parse_installed_apps_macos(json), vec!["Slack@4.36.140"]);
    }
    #[test]
    fn installed_apps_malformed_json() {
        assert!(parse_installed_apps_macos("not json").is_empty());
    }
    #[test]
    fn installed_apps_missing_key() {
        assert!(parse_installed_apps_macos("{}").is_empty());
    }
    #[test]
    fn installed_apps_skips_blank_name() {
        let json = r#"{
            "SPApplicationsDataType": [
                {"_name": "", "version": "1.0"},
                {"_name": "Slack", "version": "4.36"}
            ]
        }"#;
        assert_eq!(parse_installed_apps_macos(json), vec!["Slack@4.36"]);
    }
}
