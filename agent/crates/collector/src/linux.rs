#[cfg(target_os = "linux")]
use chrono::Utc;
#[cfg(target_os = "linux")]
use open_attest_types::{CheckResult, CheckValue};
#[cfg(target_os = "linux")]
use std::process::Command;

#[cfg(target_os = "linux")]
fn now_iso() -> String {
    Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// Pure parser functions — testable on any platform.
pub mod parsers {
    pub fn parse_disk_encryption(lsblk_json: &str, dmsetup: &str, crypttab: &str) -> bool {
        if lsblk_json.contains("crypto_LUKS") {
            return true;
        }
        if dmsetup.contains("crypt") {
            return true;
        }
        for line in crypttab.lines() {
            let trimmed = line.trim();
            if !trimmed.is_empty() && !trimmed.starts_with('#') {
                return true;
            }
        }
        false
    }

    pub fn parse_firewall(ufw_output: &str, iptables_output: &str, firewalld_output: &str) -> (bool, &'static str) {
        if ufw_output.contains("Status: active") {
            return (true, "ufw");
        }
        // iptables: more than 3 lines means rules exist
        if iptables_output.lines().count() > 3 {
            return (true, "iptables");
        }
        if firewalld_output.trim().eq_ignore_ascii_case("running") {
            return (true, "firewalld");
        }
        (false, "ufw")
    }

    pub fn parse_screen_lock_timeout(gsettings_gnome: &str, kde_timeout: &str, gsettings_cinnamon: &str, xfce_delay: &str) -> (i64, &'static str) {
        // GNOME: "uint32 300"
        if let Some(val) = parse_gsettings_uint32(gsettings_gnome) {
            if val > 0 {
                return ((val / 60) as i64, "gsettings");
            }
        }
        // KDE: plain minutes value
        let kde_trimmed = kde_timeout.trim();
        if let Ok(minutes) = kde_trimmed.parse::<i64>() {
            if minutes > 0 {
                return (minutes, "kreadconfig5");
            }
        }
        // Cinnamon: same format as GNOME
        if let Some(val) = parse_gsettings_uint32(gsettings_cinnamon) {
            if val > 0 {
                return ((val / 60) as i64, "gsettings");
            }
        }
        // XFCE: minutes
        let xfce_trimmed = xfce_delay.trim();
        if let Ok(minutes) = xfce_trimmed.parse::<i64>() {
            if minutes > 0 {
                return (minutes, "xfconf-query");
            }
        }
        (-1, "gsettings")
    }

    fn parse_gsettings_uint32(output: &str) -> Option<u64> {
        let trimmed = output.trim();
        // Format: "uint32 300" or just "300"
        if let Some(rest) = trimmed.strip_prefix("uint32 ") {
            rest.parse::<u64>().ok()
        } else {
            trimmed.parse::<u64>().ok()
        }
    }

    pub fn parse_screen_lock_password(gnome_output: &str, kde_output: &str, cinnamon_output: &str, xfce_output: &str) -> (bool, &'static str) {
        // GNOME: "true" or "false"
        let gnome = gnome_output.trim();
        if gnome == "true" {
            return (true, "gsettings");
        }
        if gnome == "false" {
            return (false, "gsettings");
        }
        // KDE
        let kde = kde_output.trim().to_lowercase();
        if kde == "true" {
            return (true, "kreadconfig5");
        }
        if kde == "false" {
            return (false, "kreadconfig5");
        }
        // Cinnamon
        let cinnamon = cinnamon_output.trim();
        if cinnamon == "true" {
            return (true, "gsettings");
        }
        if cinnamon == "false" {
            return (false, "gsettings");
        }
        // XFCE
        let xfce = xfce_output.trim().to_lowercase();
        if xfce == "true" {
            return (true, "xfconf-query");
        }
        if xfce == "false" {
            return (false, "xfconf-query");
        }
        (false, "gsettings")
    }

    pub fn parse_os_version(os_release: &str, uname: &str) -> String {
        for line in os_release.lines() {
            if line.starts_with("PRETTY_NAME=") {
                return line
                    .trim_start_matches("PRETTY_NAME=")
                    .trim_matches('"')
                    .to_string();
            }
        }
        uname.trim().to_string()
    }

    pub fn parse_edr_presence(ps_output: &str, apparmor_exit: i32, selinux_output: &str) -> bool {
        let known = [
            "clamd",
            "freshclam",
            "clamav",
            "falcon-sensor",
            "sentineld",
            "SophosScanD",
            "eset_daemon",
            "bdagent",
            "mcafee",
        ];
        for proc in &known {
            if ps_output.contains(proc) {
                return true;
            }
        }
        if apparmor_exit == 0 {
            return true;
        }
        if selinux_output.trim().eq_ignore_ascii_case("enforcing") {
            return true;
        }
        false
    }

    pub fn parse_password_enabled(shadow_entry: &str, passwd_status: &str) -> bool {
        // Check shadow entry password field
        let shadow_trimmed = shadow_entry.trim();
        if !shadow_trimmed.is_empty() {
            let parts: Vec<&str> = shadow_trimmed.split(':').collect();
            if parts.len() >= 2 {
                let pw_field = parts[1];
                if pw_field == "!" || pw_field == "*" || pw_field == "!!" {
                    return false;
                }
                if !pw_field.is_empty() {
                    return true;
                }
            }
        }
        // Fallback: passwd -S output
        // Format: "username P 2024-01-01 0 99999 7 -1" where P=password, L=locked, NP=no password
        let passwd_trimmed = passwd_status.trim();
        if !passwd_trimmed.is_empty() {
            let parts: Vec<&str> = passwd_trimmed.split_whitespace().collect();
            if parts.len() >= 2 {
                return parts[1] == "P";
            }
        }
        true // default: assume password is set
    }

    pub fn parse_password_min_length(pwquality: &str, pam_password: &str, login_defs: &str) -> i64 {
        // Check /etc/security/pwquality.conf for "minlen = N"
        for line in pwquality.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("minlen") {
                if let Some(val) = trimmed.split('=').nth(1) {
                    if let Ok(n) = val.trim().parse::<i64>() {
                        return n;
                    }
                }
            }
        }
        // Check PAM config for "minlen=N"
        for line in pam_password.lines() {
            if let Some(pos) = line.find("minlen=") {
                let after = &line[pos + 7..];
                let num_str: String = after.chars().take_while(|c| c.is_ascii_digit()).collect();
                if let Ok(n) = num_str.parse::<i64>() {
                    return n;
                }
            }
        }
        // Check /etc/login.defs for "PASS_MIN_LEN N"
        for line in login_defs.lines() {
            let trimmed = line.trim();
            if trimmed.starts_with("PASS_MIN_LEN") {
                let parts: Vec<&str> = trimmed.split_whitespace().collect();
                if parts.len() >= 2 {
                    if let Ok(n) = parts[1].parse::<i64>() {
                        return n;
                    }
                }
            }
        }
        0
    }

    /// Parse hardware info from DMI/sysfs files.
    pub fn parse_hardware_info(vendor: &str, product: &str, serial: &str) -> (String, String, String) {
        (vendor.trim().to_string(), product.trim().to_string(), serial.trim().to_string())
    }

    pub fn parse_admin_members(etc_group: &str) -> Vec<String> {
        for line in etc_group.lines() {
            let trimmed = line.trim();
            // Match "sudo:x:27:user1,user2" or "wheel:x:10:user1,user2"
            if trimmed.starts_with("sudo:") || trimmed.starts_with("wheel:") {
                let parts: Vec<&str> = trimmed.split(':').collect();
                if parts.len() >= 4 && !parts[3].is_empty() {
                    return parts[3].split(',').map(|s| s.trim().to_string()).collect();
                }
                return vec![];
            }
        }
        vec![]
    }
}

// --- Check functions (Linux-specific, use system commands) ---

#[cfg(target_os = "linux")]
fn check_disk_encryption() -> CheckResult {
    let lsblk_json = Command::new("lsblk")
        .args(["-o", "NAME,FSTYPE,TYPE", "--json"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let dmsetup = Command::new("dmsetup")
        .arg("status")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let crypttab = std::fs::read_to_string("/etc/crypttab").unwrap_or_default();

    let source = if lsblk_json.contains("crypto_LUKS") {
        "lsblk"
    } else if dmsetup.contains("crypt") {
        "dmsetup"
    } else {
        "crypttab"
    };

    CheckResult {
        key: "disk_encryption.enabled".to_string(),
        value: CheckValue::Bool(parsers::parse_disk_encryption(&lsblk_json, &dmsetup, &crypttab)),
        observed_at: now_iso(),
        source: source.to_string(),
    }
}

#[cfg(target_os = "linux")]
fn check_firewall() -> CheckResult {
    let ufw_output = Command::new("ufw")
        .arg("status")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let iptables_output = Command::new("sh")
        .args(["-c", "iptables -L -n 2>/dev/null"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let firewalld_output = Command::new("sh")
        .args(["-c", "firewall-cmd --state 2>/dev/null"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let (enabled, source) = parsers::parse_firewall(&ufw_output, &iptables_output, &firewalld_output);
    CheckResult {
        key: "firewall.enabled".to_string(),
        value: CheckValue::Bool(enabled),
        observed_at: now_iso(),
        source: source.to_string(),
    }
}

#[cfg(target_os = "linux")]
fn check_screen_lock_timeout() -> CheckResult {
    let gnome = Command::new("gsettings")
        .args(["get", "org.gnome.desktop.session", "idle-delay"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let kde = Command::new("kreadconfig5")
        .args(["--group", "Daemon", "--key", "Timeout", "--file", "kscreenlockerrc"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let cinnamon = Command::new("gsettings")
        .args(["get", "org.cinnamon.desktop.session", "idle-delay"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let xfce = Command::new("xfconf-query")
        .args(["-c", "xfce4-screensaver", "-p", "/saver/idle-activation/delay"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let (minutes, source) = parsers::parse_screen_lock_timeout(&gnome, &kde, &cinnamon, &xfce);
    CheckResult {
        key: "screen_lock.timeout_minutes".to_string(),
        value: CheckValue::Int(minutes),
        observed_at: now_iso(),
        source: source.to_string(),
    }
}

#[cfg(target_os = "linux")]
fn check_screen_lock_password() -> CheckResult {
    let gnome = Command::new("gsettings")
        .args(["get", "org.gnome.desktop.screensaver", "lock-enabled"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let kde = Command::new("kreadconfig5")
        .args(["--group", "Daemon", "--key", "Autolock", "--file", "kscreenlockerrc"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let cinnamon = Command::new("gsettings")
        .args(["get", "org.cinnamon.desktop.screensaver", "lock-enabled"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let xfce = Command::new("xfconf-query")
        .args(["-c", "xfce4-screensaver", "-p", "/lock/enabled"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let (enabled, source) = parsers::parse_screen_lock_password(&gnome, &kde, &cinnamon, &xfce);
    CheckResult {
        key: "screen_lock.password_required".to_string(),
        value: CheckValue::Bool(enabled),
        observed_at: now_iso(),
        source: source.to_string(),
    }
}

#[cfg(target_os = "linux")]
fn check_os_version() -> CheckResult {
    let os_release = std::fs::read_to_string("/etc/os-release").unwrap_or_default();
    let uname = Command::new("uname")
        .arg("-r")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let source = if !os_release.is_empty() {
        "os-release"
    } else {
        "uname"
    };

    CheckResult {
        key: "os.version".to_string(),
        value: CheckValue::Str(parsers::parse_os_version(&os_release, &uname)),
        observed_at: now_iso(),
        source: source.to_string(),
    }
}

#[cfg(target_os = "linux")]
fn check_hostname() -> CheckResult {
    let (output, source) = match Command::new("hostname").output() {
        Ok(out) => (
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
            "hostname_cmd",
        ),
        Err(_) => (String::new(), "unavailable"),
    };
    CheckResult {
        key: "hostname".to_string(),
        value: CheckValue::Str(output),
        observed_at: now_iso(),
        source: source.to_string(),
    }
}

#[cfg(target_os = "linux")]
fn check_user_primary() -> CheckResult {
    let (output, source) = match Command::new("whoami").output() {
        Ok(out) => (
            String::from_utf8_lossy(&out.stdout).trim().to_string(),
            "whoami",
        ),
        Err(_) => (String::new(), "unavailable"),
    };
    CheckResult {
        key: "user.primary".to_string(),
        value: CheckValue::Str(output),
        observed_at: now_iso(),
        source: source.to_string(),
    }
}

#[cfg(target_os = "linux")]
fn check_edr_presence() -> CheckResult {
    let ps_output = Command::new("ps")
        .args(["aux"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let apparmor_exit = Command::new("sh")
        .args(["-c", "aa-status --enabled 2>/dev/null"])
        .status()
        .map(|s| s.code().unwrap_or(1))
        .unwrap_or(1);

    let selinux_output = Command::new("sh")
        .args(["-c", "getenforce 2>/dev/null"])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    CheckResult {
        key: "edr.present".to_string(),
        value: CheckValue::Bool(parsers::parse_edr_presence(
            &ps_output,
            apparmor_exit,
            &selinux_output,
        )),
        observed_at: now_iso(),
        source: "process_scan".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn check_mdm() -> CheckResult {
    CheckResult {
        key: "mdm.enrolled".to_string(),
        value: CheckValue::Bool(false),
        observed_at: now_iso(),
        source: "not_applicable".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn check_password_enabled() -> CheckResult {
    let current_user = Command::new("whoami")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    // Try reading shadow entry
    let shadow_entry = std::fs::read_to_string("/etc/shadow")
        .unwrap_or_default()
        .lines()
        .find(|l| l.starts_with(&format!("{}:", current_user)))
        .unwrap_or("")
        .to_string();

    // Fallback: passwd -S
    let passwd_status = Command::new("passwd")
        .args(["-S", &current_user])
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).to_string())
        .unwrap_or_default();

    let source = if !shadow_entry.is_empty() {
        "shadow"
    } else {
        "passwd"
    };

    CheckResult {
        key: "password.enabled".to_string(),
        value: CheckValue::Bool(parsers::parse_password_enabled(&shadow_entry, &passwd_status)),
        observed_at: now_iso(),
        source: source.to_string(),
    }
}

#[cfg(target_os = "linux")]
fn check_password_policy() -> CheckResult {
    let pwquality = std::fs::read_to_string("/etc/security/pwquality.conf").unwrap_or_default();
    let pam_password = std::fs::read_to_string("/etc/pam.d/common-password")
        .or_else(|_| std::fs::read_to_string("/etc/pam.d/system-auth"))
        .unwrap_or_default();
    let login_defs = std::fs::read_to_string("/etc/login.defs").unwrap_or_default();

    CheckResult {
        key: "password_policy.min_length".to_string(),
        value: CheckValue::Int(parsers::parse_password_min_length(
            &pwquality,
            &pam_password,
            &login_defs,
        )),
        observed_at: now_iso(),
        source: "pwquality".to_string(),
    }
}

#[cfg(target_os = "linux")]
fn check_local_admin() -> (CheckResult, CheckResult) {
    let etc_group = std::fs::read_to_string("/etc/group").unwrap_or_default();
    let members = parsers::parse_admin_members(&etc_group);

    let current_user = Command::new("whoami")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    let is_admin = members.contains(&current_user);

    (
        CheckResult {
            key: "local_admin.is_admin".to_string(),
            value: CheckValue::Bool(is_admin),
            observed_at: now_iso(),
            source: "etc_group".to_string(),
        },
        CheckResult {
            key: "local_admin.members".to_string(),
            value: CheckValue::StringList(members),
            observed_at: now_iso(),
            source: "etc_group".to_string(),
        },
    )
}

#[cfg(target_os = "linux")]
fn check_hardware_info() -> Vec<CheckResult> {
    let read_dmi = |file: &str| -> String {
        std::fs::read_to_string(format!("/sys/class/dmi/id/{}", file))
            .unwrap_or_default()
    };
    let (vendor, product, serial) = parsers::parse_hardware_info(
        &read_dmi("sys_vendor"),
        &read_dmi("product_name"),
        &read_dmi("product_serial"),
    );
    let ts = now_iso();
    vec![
        CheckResult { key: "device.manufacturer".to_string(), value: CheckValue::Str(vendor), observed_at: ts.clone(), source: "dmi".to_string() },
        CheckResult { key: "device.model".to_string(), value: CheckValue::Str(product), observed_at: ts.clone(), source: "dmi".to_string() },
        CheckResult { key: "device.serial_number".to_string(), value: CheckValue::Str(serial), observed_at: ts, source: "dmi".to_string() },
    ]
}

#[cfg(target_os = "linux")]
pub fn collect_all() -> Vec<CheckResult> {
    let (admin_is_admin, admin_members) = check_local_admin();
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
        admin_is_admin,
        admin_members,
    ];
    checks.extend(check_hardware_info());
    checks
}

#[cfg(test)]
mod tests {
    use super::parsers::*;

    // --- Disk encryption ---
    #[test]
    fn disk_encryption_luks() {
        assert!(parse_disk_encryption(
            r#"{"blockdevices": [{"name":"sda1","fstype":"crypto_LUKS","type":"part"}]}"#,
            "",
            ""
        ));
    }
    #[test]
    fn disk_encryption_dmsetup() {
        assert!(parse_disk_encryption("", "sda_crypt: 0 1234 crypt", ""));
    }
    #[test]
    fn disk_encryption_crypttab() {
        assert!(parse_disk_encryption("", "", "sda_crypt UUID=abc-123 none luks\n"));
    }
    #[test]
    fn disk_encryption_crypttab_comments_only() {
        assert!(!parse_disk_encryption("", "", "# This is a comment\n# Another comment\n"));
    }
    #[test]
    fn disk_encryption_none() {
        assert!(!parse_disk_encryption("{}", "", ""));
    }

    // --- Firewall ---
    #[test]
    fn firewall_ufw_active() {
        let (enabled, source) = parse_firewall("Status: active\n\nTo                         Action      From\n", "", "");
        assert!(enabled);
        assert_eq!(source, "ufw");
    }
    #[test]
    fn firewall_iptables_rules() {
        let iptables = "Chain INPUT (policy ACCEPT)\ntarget     prot opt source               destination\nACCEPT     all  --  0.0.0.0/0            0.0.0.0/0\nDROP       all  --  0.0.0.0/0            0.0.0.0/0\n";
        let (enabled, source) = parse_firewall("Status: inactive\n", iptables, "");
        assert!(enabled);
        assert_eq!(source, "iptables");
    }
    #[test]
    fn firewall_firewalld_running() {
        let (enabled, source) = parse_firewall("Status: inactive\n", "", "running\n");
        assert!(enabled);
        assert_eq!(source, "firewalld");
    }
    #[test]
    fn firewall_none() {
        let (enabled, _) = parse_firewall("Status: inactive\n", "Chain INPUT\nChain FORWARD\nChain OUTPUT\n", "not running\n");
        assert!(!enabled);
    }

    // --- Screen lock timeout ---
    #[test]
    fn screen_lock_timeout_gnome() {
        let (minutes, source) = parse_screen_lock_timeout("uint32 300\n", "", "", "");
        assert_eq!(minutes, 5);
        assert_eq!(source, "gsettings");
    }
    #[test]
    fn screen_lock_timeout_kde() {
        let (minutes, source) = parse_screen_lock_timeout("", "10\n", "", "");
        assert_eq!(minutes, 10);
        assert_eq!(source, "kreadconfig5");
    }
    #[test]
    fn screen_lock_timeout_cinnamon() {
        let (minutes, source) = parse_screen_lock_timeout("", "", "uint32 600\n", "");
        assert_eq!(minutes, 10);
        assert_eq!(source, "gsettings");
    }
    #[test]
    fn screen_lock_timeout_xfce() {
        let (minutes, source) = parse_screen_lock_timeout("", "", "", "15\n");
        assert_eq!(minutes, 15);
        assert_eq!(source, "xfconf-query");
    }
    #[test]
    fn screen_lock_timeout_none() {
        let (minutes, _) = parse_screen_lock_timeout("", "", "", "");
        assert_eq!(minutes, -1);
    }

    // --- Screen lock password ---
    #[test]
    fn screen_lock_password_gnome_true() {
        let (enabled, source) = parse_screen_lock_password("true\n", "", "", "");
        assert!(enabled);
        assert_eq!(source, "gsettings");
    }
    #[test]
    fn screen_lock_password_gnome_false() {
        let (enabled, _) = parse_screen_lock_password("false\n", "", "", "");
        assert!(!enabled);
    }
    #[test]
    fn screen_lock_password_kde_true() {
        let (enabled, source) = parse_screen_lock_password("", "true\n", "", "");
        assert!(enabled);
        assert_eq!(source, "kreadconfig5");
    }
    #[test]
    fn screen_lock_password_xfce_false() {
        let (enabled, source) = parse_screen_lock_password("", "", "", "false\n");
        assert!(!enabled);
        assert_eq!(source, "xfconf-query");
    }

    // --- OS version ---
    #[test]
    fn os_version_pretty_name() {
        let os_release = "NAME=\"Ubuntu\"\nVERSION=\"22.04.3 LTS\"\nPRETTY_NAME=\"Ubuntu 22.04.3 LTS\"\nVERSION_ID=\"22.04\"\n";
        assert_eq!(parse_os_version(os_release, ""), "Ubuntu 22.04.3 LTS");
    }
    #[test]
    fn os_version_uname_fallback() {
        assert_eq!(parse_os_version("", "5.15.0-91-generic\n"), "5.15.0-91-generic");
    }

    // --- EDR presence ---
    #[test]
    fn edr_clamd() {
        assert!(parse_edr_presence("root 123 clamd\nuser 456 bash\n", 1, ""));
    }
    #[test]
    fn edr_falcon_sensor() {
        assert!(parse_edr_presence("root 100 falcon-sensor\n", 1, ""));
    }
    #[test]
    fn edr_apparmor() {
        assert!(parse_edr_presence("user 123 bash\n", 0, ""));
    }
    #[test]
    fn edr_selinux_enforcing() {
        assert!(parse_edr_presence("user 123 bash\n", 1, "Enforcing\n"));
    }
    #[test]
    fn edr_none() {
        assert!(!parse_edr_presence("user 123 bash\nuser 456 vim\n", 1, "Permissive\n"));
    }

    // --- Password enabled ---
    #[test]
    fn password_enabled_shadow() {
        assert!(parse_password_enabled("tao:$6$abc123:19000:0:99999:7:::", ""));
    }
    #[test]
    fn password_disabled_shadow_locked() {
        assert!(!parse_password_enabled("tao:!:19000:0:99999:7:::", ""));
    }
    #[test]
    fn password_disabled_shadow_star() {
        assert!(!parse_password_enabled("tao:*:19000:0:99999:7:::", ""));
    }
    #[test]
    fn password_enabled_passwd_status() {
        assert!(parse_password_enabled("", "tao P 2024-01-01 0 99999 7 -1\n"));
    }
    #[test]
    fn password_disabled_passwd_status() {
        assert!(!parse_password_enabled("", "tao NP 2024-01-01 0 99999 7 -1\n"));
    }

    // --- Password policy ---
    #[test]
    fn password_min_length_pwquality() {
        assert_eq!(parse_password_min_length("# minlen = 8\nminlen = 12\n", "", ""), 12);
    }
    #[test]
    fn password_min_length_pam() {
        assert_eq!(
            parse_password_min_length(
                "",
                "password requisite pam_pwquality.so retry=3 minlen=10\n",
                ""
            ),
            10
        );
    }
    #[test]
    fn password_min_length_login_defs() {
        assert_eq!(
            parse_password_min_length("", "", "PASS_MAX_DAYS 99999\nPASS_MIN_LEN 8\nPASS_MIN_DAYS 0\n"),
            8
        );
    }
    #[test]
    fn password_min_length_none() {
        assert_eq!(parse_password_min_length("", "", ""), 0);
    }

    // --- Admin members ---
    #[test]
    fn admin_members_sudo() {
        let group = "root:x:0:\ndaemon:x:1:\nsudo:x:27:tao,alice\n";
        assert_eq!(parse_admin_members(group), vec!["tao", "alice"]);
    }
    #[test]
    fn admin_members_wheel() {
        let group = "root:x:0:\nwheel:x:10:bob\n";
        assert_eq!(parse_admin_members(group), vec!["bob"]);
    }
    #[test]
    fn admin_members_empty_group() {
        let group = "root:x:0:\nsudo:x:27:\n";
        assert!(parse_admin_members(group).is_empty());
    }
    #[test]
    fn admin_members_no_sudo_wheel() {
        assert!(parse_admin_members("root:x:0:\ndaemon:x:1:\n").is_empty());
    }

    // --- Hardware info ---
    #[test]
    fn hardware_info_parse() {
        let (v, p, s) = parse_hardware_info("Lenovo\n", "ThinkPad X1\n", "PF1234AB\n");
        assert_eq!(v, "Lenovo");
        assert_eq!(p, "ThinkPad X1");
        assert_eq!(s, "PF1234AB");
    }
    #[test]
    fn hardware_info_empty() {
        let (v, p, s) = parse_hardware_info("", "", "");
        assert!(v.is_empty());
        assert!(p.is_empty());
        assert!(s.is_empty());
    }
}
