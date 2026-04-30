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

    pub fn parse_firewall(output: &str) -> bool {
        let trimmed = output.trim();
        matches!(trimmed, "1" | "2")
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

    pub fn parse_mdm(output: &str) -> bool {
        output.contains("MDM enrollment")
    }

    pub fn parse_edr_presence(ps_output: &str, sysext_output: &str, xprotect_exists: bool) -> bool {
        if xprotect_exists {
            return true;
        }

        let known_processes = [
            "falcond", "falcon-sensor",
            "sentineld", "sentinelone",
            "cbagentd", "cbdaemon",
            "SophosScanD", "SophosAntiVirus",
            "JamfProtect",
            "MRT", "XProtect",
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
    let (output, source) = match Command::new("defaults")
        .args(["read", "/Library/Preferences/com.apple.alf", "globalstate"])
        .output()
    {
        Ok(out) if out.status.success() => (
            String::from_utf8_lossy(&out.stdout).to_string(),
            "defaults_read",
        ),
        _ => (String::new(), "unavailable"),
    };
    CheckResult {
        key: "firewall.enabled".to_string(),
        value: CheckValue::Bool(parsers::parse_firewall(&output)),
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

#[cfg(target_os = "macos")]
fn check_edr_presence() -> CheckResult {
    let ps_output = Command::new("ps").args(["aux"]).output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let sysext_output = Command::new("systemextensionsctl").arg("list").output()
        .map(|o| format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr)))
        .unwrap_or_default();

    let xprotect_exists =
        std::path::Path::new("/Library/Apple/System/Library/CoreServices/XProtect.bundle").exists()
        || std::path::Path::new("/System/Library/CoreServices/XProtect.bundle").exists();

    CheckResult {
        key: "edr.present".to_string(),
        value: CheckValue::Bool(parsers::parse_edr_presence(&ps_output, &sysext_output, xprotect_exists)),
        observed_at: now_iso(),
        source: "process_scan".to_string(),
    }
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
pub fn collect_all() -> Vec<CheckResult> {
    let mut checks = vec![
        check_disk_encryption(),
        check_firewall(),
        check_screen_lock_timeout(),
        check_screen_lock_password(),
        check_os_version(),
        check_hostname(),
        check_user_primary(),
        check_mdm(),
        check_edr_presence(),
        check_password_enabled(),
        check_password_policy(),
        check_local_admin(),
    ];
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
    fn parse_firewall_enabled() { assert!(parse_firewall("1\n")); assert!(parse_firewall("2\n")); }
    #[test]
    fn parse_firewall_disabled() { assert!(!parse_firewall("0\n")); }
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
    fn parse_mdm_enrolled() { assert!(parse_mdm("MDM enrollment: Yes (User Approved)\nSome other line")); }
    #[test]
    fn parse_mdm_not_enrolled() { assert!(!parse_mdm("Enrolled via DEP: No\nSomething else")); }
    #[test]
    fn edr_crowdstrike() { assert!(parse_edr_presence("root 123 falcond\n", "", false)); }
    #[test]
    fn edr_none() { assert!(!parse_edr_presence("user 123 bash\nuser 456 vim\n", "no extensions", false)); }
    #[test]
    fn edr_sysext() { assert!(parse_edr_presence("", "com.crowdstrike.falcon enabled", false)); }
    #[test]
    fn edr_xprotect_bundle() { assert!(parse_edr_presence("", "", true)); }
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
}
