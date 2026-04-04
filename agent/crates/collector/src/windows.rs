#[cfg(target_os = "windows")]
use chrono::Utc;
#[cfg(target_os = "windows")]
use open_attest_types::{CheckResult, CheckValue};
#[cfg(target_os = "windows")]
use std::process::Command;

#[cfg(target_os = "windows")]
fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Pure parser functions — testable on any platform.
pub mod parsers {
    /// Parse BitLocker status from Get-BitLockerVolume output.
    /// Looks for ProtectionStatus == "On" or "1".
    pub fn parse_bitlocker(output: &str) -> bool {
        let lower = output.to_lowercase();
        // PowerShell Get-BitLockerVolume: "ProtectionStatus  : On"
        if lower.contains("protectionstatus") {
            if let Some(line) = lower.lines().find(|l| l.contains("protectionstatus")) {
                let after_colon = line.split(':').nth(1).unwrap_or("").trim();
                return after_colon == "on" || after_colon == "1";
            }
        }
        false
    }

    /// Fallback: parse manage-bde output for BitLocker.
    pub fn parse_manage_bde(output: &str) -> bool {
        let lower = output.to_lowercase();
        lower.contains("protection on") || lower.contains("fully encrypted")
    }

    /// Parse Windows Firewall status from Get-NetFirewallProfile output.
    /// Looks for "Enabled : True" across Domain/Private/Public profiles.
    pub fn parse_firewall(output: &str) -> bool {
        let lower = output.to_lowercase();
        // If any profile has Enabled: True, firewall is on
        if lower.contains("enabled") {
            for line in lower.lines() {
                if line.contains("enabled") && line.contains("true") {
                    return true;
                }
            }
        }
        false
    }

    /// Parse screen saver timeout from registry value (seconds as string).
    pub fn parse_screen_lock_timeout(timeout_output: &str) -> i64 {
        let trimmed = timeout_output.trim();
        match trimmed.parse::<i64>() {
            Ok(seconds) if seconds > 0 => seconds / 60,
            _ => -1,
        }
    }

    /// Parse ScreenSaverIsSecure registry value.
    pub fn parse_screen_lock_password(secure_output: &str) -> bool {
        secure_output.trim() == "1"
    }

    /// Parse OS version from `ver` or `systeminfo` output.
    pub fn parse_os_version(output: &str) -> String {
        // `[System.Environment]::OSVersion.Version.ToString()` returns "10.0.22631.0"
        let trimmed = output.trim();
        if !trimmed.is_empty() {
            return trimmed.to_string();
        }
        "unknown".to_string()
    }

    /// Parse AntiVirus product state from Get-CimInstance output.
    /// productState bit 12 (0x1000) = active. We also check displayName.
    pub fn parse_antivirus(output: &str) -> bool {
        let lower = output.to_lowercase();
        // If we see any displayName lines, AV products are registered
        if lower.contains("displayname") {
            return true;
        }
        // Check Windows Defender status from Get-MpComputerStatus
        if lower.contains("antivirusenabled") && lower.contains("true") {
            return true;
        }
        false
    }

    /// Parse whether the current user has a password set.
    /// `net user <username>` output contains "Password Required  Yes/No".
    pub fn parse_password_enabled(output: &str) -> bool {
        let lower = output.to_lowercase();
        for line in lower.lines() {
            if line.contains("password required") {
                return line.contains("yes");
            }
        }
        // Default: assume password is set if we can't determine
        true
    }

    /// Parse net accounts output for minimum password length.
    /// Output: "Minimum password length    8"
    pub fn parse_password_min_length(output: &str) -> i64 {
        let lower = output.to_lowercase();
        for line in lower.lines() {
            if line.contains("minimum password length") {
                // Extract the number at the end of the line
                if let Some(num_str) = line.split_whitespace().last() {
                    if let Ok(n) = num_str.parse::<i64>() {
                        return n;
                    }
                }
            }
        }
        0
    }

    /// Parse local administrators group from `net localgroup Administrators`.
    /// Output format: Members section separated by dashes, one name per line.
    pub fn parse_admin_members(output: &str) -> Vec<String> {
        let mut members = vec![];
        let mut in_members = false;
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("---") {
                in_members = true;
                continue;
            }
            if in_members {
                if trimmed.is_empty() || trimmed.starts_with("The command completed") {
                    break;
                }
                members.push(trimmed.to_string());
            }
        }
        members
    }

    /// Parse MDM enrollment from dsregcmd output.
    /// Looks for "MdmUrl : https://..." indicating MDM enrollment.
    pub fn parse_mdm(output: &str) -> bool {
        let lower = output.to_lowercase();
        lower.contains("mdmurl") && lower.contains("https://")
    }
}

// --- Windows check functions ---

#[cfg(target_os = "windows")]
fn ps(script: &str) -> String {
    Command::new("powershell")
        .args(["-NoProfile", "-NonInteractive", "-Command", script])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default()
}

#[cfg(target_os = "windows")]
fn check_disk_encryption() -> CheckResult {
    // Try Get-BitLockerVolume first
    let bl_output = ps("Get-BitLockerVolume -MountPoint C: | Format-List ProtectionStatus");
    if parsers::parse_bitlocker(&bl_output) {
        return CheckResult {
            key: "disk_encryption.enabled".to_string(),
            value: CheckValue::Bool(true),
            observed_at: now_iso(),
            source: "get_bitlocker_volume".to_string(),
        };
    }

    // Fallback to manage-bde
    let bde_output = Command::new("manage-bde")
        .args(["-status", "C:"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    CheckResult {
        key: "disk_encryption.enabled".to_string(),
        value: CheckValue::Bool(parsers::parse_manage_bde(&bde_output)),
        observed_at: now_iso(),
        source: "manage_bde".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn check_firewall() -> CheckResult {
    let output = ps("Get-NetFirewallProfile | Format-List Name,Enabled");
    CheckResult {
        key: "firewall.enabled".to_string(),
        value: CheckValue::Bool(parsers::parse_firewall(&output)),
        observed_at: now_iso(),
        source: "get_net_firewall_profile".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn check_screen_lock_timeout() -> CheckResult {
    let output = ps(
        "(Get-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaveTimeOut -ErrorAction SilentlyContinue).ScreenSaveTimeOut"
    );
    let minutes = parsers::parse_screen_lock_timeout(&output);

    // If screensaver timeout not set, try power display timeout
    if minutes < 0 {
        let power_output = ps(
            "powercfg /query SCHEME_CURRENT SUB_VIDEO VIDEOIDLE"
        );
        // Parse hex value from "Current AC Power Setting Index: 0x00000258" (600 = 10 min)
        let lower = power_output.to_lowercase();
        for line in lower.lines() {
            if line.contains("current ac power setting index") {
                if let Some(hex_str) = line.split("0x").nth(1) {
                    let hex_str = hex_str.trim();
                    if let Ok(seconds) = i64::from_str_radix(hex_str, 16) {
                        if seconds > 0 {
                            return CheckResult {
                                key: "screen_lock.timeout_minutes".to_string(),
                                value: CheckValue::Int(seconds / 60),
                                observed_at: now_iso(),
                                source: "powercfg".to_string(),
                            };
                        }
                    }
                }
            }
        }
    }

    CheckResult {
        key: "screen_lock.timeout_minutes".to_string(),
        value: CheckValue::Int(minutes),
        observed_at: now_iso(),
        source: "registry".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn check_screen_lock_password() -> CheckResult {
    let output = ps(
        "(Get-ItemProperty -Path 'HKCU:\\Control Panel\\Desktop' -Name ScreenSaverIsSecure -ErrorAction SilentlyContinue).ScreenSaverIsSecure"
    );
    CheckResult {
        key: "screen_lock.password_required".to_string(),
        value: CheckValue::Bool(parsers::parse_screen_lock_password(&output)),
        observed_at: now_iso(),
        source: "registry".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn check_os_version() -> CheckResult {
    let output = ps("[System.Environment]::OSVersion.Version.ToString()");
    CheckResult {
        key: "os.version".to_string(),
        value: CheckValue::Str(parsers::parse_os_version(&output)),
        observed_at: now_iso(),
        source: "dotnet_env".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn check_hostname() -> CheckResult {
    let output = Command::new("hostname").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    CheckResult {
        key: "hostname".to_string(),
        value: CheckValue::Str(output),
        observed_at: now_iso(),
        source: "hostname_cmd".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn check_user_primary() -> CheckResult {
    let output = Command::new("whoami").output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();
    CheckResult {
        key: "user.primary".to_string(),
        value: CheckValue::Str(output),
        observed_at: now_iso(),
        source: "whoami".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn check_edr_presence() -> CheckResult {
    // Try SecurityCenter2 WMI class
    let av_output = ps(
        "Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct -ErrorAction SilentlyContinue | Format-List displayName,productState"
    );
    if parsers::parse_antivirus(&av_output) {
        return CheckResult {
            key: "edr.present".to_string(),
            value: CheckValue::Bool(true),
            observed_at: now_iso(),
            source: "security_center".to_string(),
        };
    }

    // Fallback to Windows Defender status
    let defender_output = ps(
        "Get-MpComputerStatus -ErrorAction SilentlyContinue | Format-List AntivirusEnabled,RealTimeProtectionEnabled"
    );
    CheckResult {
        key: "edr.present".to_string(),
        value: CheckValue::Bool(parsers::parse_antivirus(&defender_output)),
        observed_at: now_iso(),
        source: "windows_defender".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn check_mdm() -> CheckResult {
    let output = Command::new("dsregcmd")
        .arg("/status")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    CheckResult {
        key: "mdm.enrolled".to_string(),
        value: CheckValue::Bool(parsers::parse_mdm(&output)),
        observed_at: now_iso(),
        source: "dsregcmd".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn check_password_enabled() -> CheckResult {
    let current_user = ps("[System.Environment]::UserName");
    let output = Command::new("net")
        .args(["user", current_user.trim()])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    CheckResult {
        key: "password.enabled".to_string(),
        value: CheckValue::Bool(parsers::parse_password_enabled(&output)),
        observed_at: now_iso(),
        source: "net_user".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn check_password_policy() -> CheckResult {
    // Try PowerShell ADSI first (locale-independent)
    let adsi_output = ps("([ADSI]'WinNT://localhost').MinPasswordLength.Value");
    let trimmed = adsi_output.trim();
    if let Ok(n) = trimmed.parse::<i64>() {
        return CheckResult {
            key: "password_policy.min_length".to_string(),
            value: CheckValue::Int(n),
            observed_at: now_iso(),
            source: "adsi".to_string(),
        };
    }

    // Fallback to net accounts
    let net_output = Command::new("net")
        .arg("accounts")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    CheckResult {
        key: "password_policy.min_length".to_string(),
        value: CheckValue::Int(parsers::parse_password_min_length(&net_output)),
        observed_at: now_iso(),
        source: "net_accounts".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn check_local_admin() -> (CheckResult, CheckResult) {
    let output = Command::new("net")
        .args(["localgroup", "Administrators"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let members = parsers::parse_admin_members(&output);
    let current_user = Command::new("whoami").output()
        .map(|o| {
            let full = String::from_utf8_lossy(&o.stdout).trim().to_string();
            // whoami on Windows returns DOMAIN\user, extract just user
            full.split('\\').last().unwrap_or(&full).to_string()
        })
        .unwrap_or_default();

    let is_admin = members.iter().any(|m| m.eq_ignore_ascii_case(&current_user));

    (
        CheckResult {
            key: "local_admin.is_admin".to_string(),
            value: CheckValue::Bool(is_admin),
            observed_at: now_iso(),
            source: "net_localgroup".to_string(),
        },
        CheckResult {
            key: "local_admin.members".to_string(),
            value: CheckValue::StringList(members),
            observed_at: now_iso(),
            source: "net_localgroup".to_string(),
        },
    )
}

#[cfg(target_os = "windows")]
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

    // --- BitLocker ---
    #[test]
    fn bitlocker_on() {
        assert!(parse_bitlocker("ProtectionStatus  : On\nVolumeStatus : FullyEncrypted"));
    }
    #[test]
    fn bitlocker_off() {
        assert!(!parse_bitlocker("ProtectionStatus  : Off\nVolumeStatus : FullyDecrypted"));
    }
    #[test]
    fn manage_bde_encrypted() {
        assert!(parse_manage_bde("    Conversion Status:    Fully Encrypted\n    Protection Status:    Protection On"));
    }
    #[test]
    fn manage_bde_off() {
        assert!(!parse_manage_bde("    Protection Status:    Protection Off"));
    }

    // --- Firewall ---
    #[test]
    fn firewall_enabled() {
        assert!(parse_firewall("Name    : Domain\nEnabled : True\n\nName    : Private\nEnabled : True"));
    }
    #[test]
    fn firewall_disabled() {
        assert!(!parse_firewall("Name    : Domain\nEnabled : False\n\nName    : Private\nEnabled : False"));
    }

    // --- Screen lock ---
    #[test]
    fn screen_lock_timeout_300() {
        assert_eq!(parse_screen_lock_timeout("300"), 5);
    }
    #[test]
    fn screen_lock_timeout_empty() {
        assert_eq!(parse_screen_lock_timeout(""), -1);
    }
    #[test]
    fn screen_lock_password_yes() {
        assert!(parse_screen_lock_password("1"));
    }
    #[test]
    fn screen_lock_password_no() {
        assert!(!parse_screen_lock_password("0"));
    }

    // --- OS version ---
    #[test]
    fn os_version_parse() {
        assert_eq!(parse_os_version("10.0.22631.0\r\n"), "10.0.22631.0");
    }

    // --- Antivirus ---
    #[test]
    fn antivirus_security_center() {
        assert!(parse_antivirus("displayName : Windows Defender\nproductState : 397568"));
    }
    #[test]
    fn antivirus_defender() {
        assert!(parse_antivirus("AntivirusEnabled : True\nRealTimeProtectionEnabled : True"));
    }
    #[test]
    fn antivirus_none() {
        assert!(!parse_antivirus(""));
    }

    // --- Password policy ---
    #[test]
    fn password_min_length_net_accounts() {
        let output = "Force user logoff how long after time expires?:       Never\nMinimum password age (days):                          0\nMaximum password age (days):                          42\nMinimum password length                               8\nLength of password history maintained                  None";
        assert_eq!(parse_password_min_length(output), 8);
    }
    #[test]
    fn password_min_length_none() {
        assert_eq!(parse_password_min_length(""), 0);
    }

    // --- Password enabled ---
    #[test]
    fn password_enabled_yes() {
        assert!(parse_password_enabled("Password Required  Yes\nSome other line"));
    }
    #[test]
    fn password_enabled_no() {
        assert!(!parse_password_enabled("Password Required  No\nSome other line"));
    }
    #[test]
    fn password_enabled_default() {
        assert!(parse_password_enabled("")); // default to true if can't determine
    }

    // --- Admin members ---
    #[test]
    fn admin_members_typical() {
        let output = "Alias name     Administrators\nComment        \n\nMembers\n\n-------------------------------------------------------------------------------\nAdministrator\ntao\nThe command completed successfully.\n";
        let members = parse_admin_members(output);
        assert_eq!(members, vec!["Administrator", "tao"]);
    }
    #[test]
    fn admin_members_empty() {
        assert!(parse_admin_members("").is_empty());
    }

    // --- MDM ---
    #[test]
    fn mdm_enrolled() {
        assert!(parse_mdm("MdmUrl : https://enrollment.manage.microsoft.com\nMdmTouUrl : https://portal.manage.microsoft.com"));
    }
    #[test]
    fn mdm_not_enrolled() {
        assert!(!parse_mdm("AzureAdJoined : YES\nDomainJoined : NO"));
    }
}
