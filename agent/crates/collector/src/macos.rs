use chrono::Utc;
use open_attest_types::{CheckResult, CheckValue};
use std::process::Command;

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

    pub fn parse_screen_lock_timeout(output: &str) -> i64 {
        let trimmed = output.trim();
        match trimmed.parse::<i64>() {
            Ok(seconds) => seconds / 60,
            Err(_) => -1,
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
    let (output, source) = match Command::new("defaults")
        .args(["-currentHost", "read", "com.apple.screensaver", "idleTime"])
        .output()
    {
        Ok(out) if out.status.success() => (
            String::from_utf8_lossy(&out.stdout).to_string(),
            "defaults_read",
        ),
        _ => (String::new(), "unavailable"),
    };
    CheckResult {
        key: "screen_lock.timeout_minutes".to_string(),
        value: CheckValue::Int(parsers::parse_screen_lock_timeout(&output)),
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
fn check_local_admin() -> (CheckResult, CheckResult) {
    let output = Command::new("dscl")
        .args([".", "-read", "/Groups/admin", "GroupMembership"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let members = parsers::parse_admin_members(&output);
    let current_user = Command::new("whoami").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    let is_admin = members.contains(&current_user);

    (
        CheckResult {
            key: "local_admin.is_admin".to_string(),
            value: CheckValue::Bool(is_admin),
            observed_at: now_iso(),
            source: "dscl".to_string(),
        },
        CheckResult {
            key: "local_admin.members".to_string(),
            value: CheckValue::StringList(members),
            observed_at: now_iso(),
            source: "dscl".to_string(),
        },
    )
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
    let (admin_is_admin, admin_members) = check_local_admin();
    vec![
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
        admin_is_admin,
        admin_members,
    ]
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
    fn parse_screen_lock_300s() { assert_eq!(parse_screen_lock_timeout("300\n"), 5); }
    #[test]
    fn parse_screen_lock_invalid() { assert_eq!(parse_screen_lock_timeout("not a number"), -1); }
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
