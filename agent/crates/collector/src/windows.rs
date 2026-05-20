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

    /// Parse hardware info from Get-CimInstance Win32_ComputerSystem output.
    /// Returns (manufacturer, model).
    pub fn parse_hardware_info(output: &str) -> (String, String) {
        let mut manufacturer = String::new();
        let mut model = String::new();
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("Manufacturer") {
                manufacturer = trimmed.split(':').nth(1).unwrap_or("").trim().to_string();
            } else if trimmed.starts_with("Model") {
                model = trimmed.split(':').nth(1).unwrap_or("").trim().to_string();
            }
        }
        (manufacturer, model)
    }

    /// Parse serial number from Get-CimInstance Win32_BIOS output.
    pub fn parse_serial_number(output: &str) -> String {
        for line in output.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("SerialNumber") {
                return trimmed.split(':').nth(1).unwrap_or("").trim().to_string();
            }
        }
        String::new()
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

    /// Parse PowerShell registry-walk output for installed programs. Input is
    /// one entry per line in `Name@Version` form (already filtered to entries
    /// that have a DisplayName). Returns sorted, deduped entries.
    pub fn parse_installed_apps_windows(output: &str) -> Vec<String> {
        let mut entries: Vec<String> = output
            .lines()
            .map(|l| l.trim().to_string())
            .filter(|l| !l.is_empty())
            .collect();
        entries.sort();
        entries.dedup();
        entries
    }

    /// Parse `Get-LocalUser | Where-Object Enabled | Select Name` output —
    /// one user name per line, sorted, deduped.
    pub fn parse_local_users(ps_output: &str) -> Vec<String> {
        let mut users: Vec<String> = ps_output
            .lines()
            .map(|s| s.trim().to_string())
            .filter(|s| {
                !s.is_empty()
                    && !s.starts_with("---")
                    && !s.eq_ignore_ascii_case("Name")
            })
            .collect();
        users.sort();
        users.dedup();
        users
    }

    /// Parse `(Get-Service sshd).Status` output. Returns true when "Running".
    pub fn parse_ssh_daemon_enabled(status: &str) -> bool {
        status.trim().eq_ignore_ascii_case("running")
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
fn check_local_admin() -> CheckResult {
    let output = Command::new("net")
        .args(["localgroup", "Administrators"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let members = parsers::parse_admin_members(&output);
    let current_user = Command::new("whoami").output()
        .map(|o| {
            let full = String::from_utf8_lossy(&o.stdout).trim().to_string();
            full.split('\\').last().unwrap_or(&full).to_string()
        })
        .unwrap_or_default();

    CheckResult {
        key: "local_admin.is_admin".to_string(),
        value: CheckValue::Bool(members.iter().any(|m| m.eq_ignore_ascii_case(&current_user))),
        observed_at: now_iso(),
        source: "net_localgroup".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn check_hardware_info() -> Vec<CheckResult> {
    let cs_output = ps("Get-CimInstance Win32_ComputerSystem | Format-List Manufacturer,Model");
    let bios_output = ps("Get-CimInstance Win32_BIOS | Format-List SerialNumber");
    let (manufacturer, model) = parsers::parse_hardware_info(&cs_output);
    let serial = parsers::parse_serial_number(&bios_output);
    let ts = now_iso();

    vec![
        CheckResult { key: "device.manufacturer".to_string(), value: CheckValue::Str(manufacturer), observed_at: ts.clone(), source: "wmi".to_string() },
        CheckResult { key: "device.model".to_string(), value: CheckValue::Str(model), observed_at: ts.clone(), source: "wmi".to_string() },
        CheckResult { key: "device.serial_number".to_string(), value: CheckValue::Str(serial), observed_at: ts, source: "wmi".to_string() },
    ]
}

#[cfg(target_os = "windows")]
fn check_local_users() -> CheckResult {
    let output = ps(
        "Get-LocalUser | Where-Object Enabled -eq $true | Select-Object -ExpandProperty Name"
    );
    CheckResult {
        key: "users.local".to_string(),
        value: CheckValue::StringList(parsers::parse_local_users(&output)),
        observed_at: now_iso(),
        source: "get_localuser".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn check_users_admins() -> CheckResult {
    let output = Command::new("net")
        .args(["localgroup", "Administrators"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();
    CheckResult {
        key: "users.admins".to_string(),
        value: CheckValue::StringList(parsers::parse_admin_members(&output)),
        observed_at: now_iso(),
        source: "net_localgroup".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn check_ssh_daemon_enabled() -> CheckResult {
    let output = ps("(Get-Service sshd -ErrorAction SilentlyContinue).Status");
    CheckResult {
        key: "ssh.daemon_enabled".to_string(),
        value: CheckValue::Bool(parsers::parse_ssh_daemon_enabled(&output)),
        observed_at: now_iso(),
        source: "get_service".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn check_ssh_authorized_key_count() -> CheckResult {
    let mut contents: Vec<String> = Vec::new();
    let program_data = std::env::var("ProgramData")
        .unwrap_or_else(|_| "C:\\ProgramData".to_string());
    let admin_keys = format!("{}\\ssh\\administrators_authorized_keys", program_data);
    if let Ok(c) = std::fs::read_to_string(&admin_keys) {
        contents.push(c);
    }
    if let Ok(entries) = std::fs::read_dir("C:\\Users") {
        for entry in entries.flatten() {
            let path = entry.path().join(".ssh").join("authorized_keys");
            if let Ok(c) = std::fs::read_to_string(&path) {
                contents.push(c);
            }
        }
    }
    let refs: Vec<&str> = contents.iter().map(|s| s.as_str()).collect();
    CheckResult {
        key: "ssh.authorized_key_count".to_string(),
        value: CheckValue::Int(parsers::parse_authorized_key_count(&refs)),
        observed_at: now_iso(),
        source: "authorized_keys_scan".to_string(),
    }
}

#[cfg(target_os = "windows")]
fn check_installed_apps() -> CheckResult {
    let script = "\
        $paths = @( \
            'HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', \
            'HKLM:\\Software\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*', \
            'HKCU:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\*' \
        ); \
        Get-ItemProperty $paths -ErrorAction SilentlyContinue | \
            Where-Object { $_.DisplayName } | \
            ForEach-Object { \"$($_.DisplayName)@$($_.DisplayVersion)\" }";
    let output = ps(script);
    let apps = crate::truncate_inventory(parsers::parse_installed_apps_windows(&output));
    CheckResult {
        key: "apps.installed".to_string(),
        value: CheckValue::StringList(apps),
        observed_at: now_iso(),
        source: "registry".to_string(),
    }
}

#[cfg(target_os = "windows")]
pub fn collect_inventory() -> Vec<CheckResult> {
    vec![check_installed_apps()]
}

#[cfg(target_os = "windows")]
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
        check_local_users(),
        check_users_admins(),
        check_ssh_daemon_enabled(),
        check_ssh_authorized_key_count(),
    ];
    checks.extend(check_hardware_info());
    checks
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

    // --- Hardware info ---
    #[test]
    fn hardware_info_parse() {
        let output = "Manufacturer : Lenovo\nModel        : ThinkPad X1 Carbon\n";
        let (mfr, model) = parse_hardware_info(output);
        assert_eq!(mfr, "Lenovo");
        assert_eq!(model, "ThinkPad X1 Carbon");
    }
    #[test]
    fn serial_number_parse() {
        assert_eq!(parse_serial_number("SerialNumber : PF1234AB\n"), "PF1234AB");
    }
    #[test]
    fn serial_number_empty() {
        assert!(parse_serial_number("").is_empty());
    }

    // --- SSH daemon ---
    #[test]
    fn ssh_daemon_running() {
        assert!(parse_ssh_daemon_enabled("Running\n"));
    }
    #[test]
    fn ssh_daemon_running_lowercase() {
        assert!(parse_ssh_daemon_enabled("running"));
    }
    #[test]
    fn ssh_daemon_stopped() {
        assert!(!parse_ssh_daemon_enabled("Stopped\n"));
    }
    #[test]
    fn ssh_daemon_empty() {
        assert!(!parse_ssh_daemon_enabled(""));
    }

    // --- Authorized keys ---
    #[test]
    fn authorized_key_count_single() {
        let f = "ssh-ed25519 AAAA... user@host\n";
        assert_eq!(parse_authorized_key_count(&[f]), 1);
    }
    #[test]
    fn authorized_key_count_skips_comments() {
        let f = "# administrators_authorized_keys\nssh-rsa AAAA... admin@host\n";
        assert_eq!(parse_authorized_key_count(&[f]), 1);
    }
    #[test]
    fn authorized_key_count_crlf() {
        let f = "ssh-ed25519 AAAA... a@h\r\nssh-rsa BBBB... b@h\r\n";
        assert_eq!(parse_authorized_key_count(&[f]), 2);
    }
    #[test]
    fn authorized_key_count_empty() {
        assert_eq!(parse_authorized_key_count(&[]), 0);
    }

    // --- Local users (Windows) ---
    #[test]
    fn local_users_typical_ps_output() {
        let out = "Administrator\r\ntao\r\nalice\r\n";
        assert_eq!(parse_local_users(out), vec!["Administrator", "alice", "tao"]);
    }
    #[test]
    fn local_users_strips_header_and_separator() {
        let out = "Name\n----\nAdministrator\ntao\n";
        assert_eq!(parse_local_users(out), vec!["Administrator", "tao"]);
    }
    #[test]
    fn local_users_empty() {
        assert!(parse_local_users("").is_empty());
    }

    // --- Installed apps (Windows) ---
    #[test]
    fn installed_apps_typical() {
        let out = "Google Chrome@121.0.6167.85\r\nVisual Studio Code@1.87.0\r\n7-Zip 23.01@23.01\r\n";
        assert_eq!(
            parse_installed_apps_windows(out),
            vec![
                "7-Zip 23.01@23.01",
                "Google Chrome@121.0.6167.85",
                "Visual Studio Code@1.87.0",
            ]
        );
    }
    #[test]
    fn installed_apps_skips_blanks() {
        let out = "\nGoogle Chrome@121\n\nVS Code@1.87\n";
        assert_eq!(
            parse_installed_apps_windows(out),
            vec!["Google Chrome@121", "VS Code@1.87"]
        );
    }
    #[test]
    fn installed_apps_dedup() {
        let out = "Google Chrome@121\nGoogle Chrome@121\n";
        assert_eq!(parse_installed_apps_windows(out), vec!["Google Chrome@121"]);
    }
}
