use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct AgentConfig {
    pub server_url: String,
    pub agent_id: String,
    pub device_id: String,
    pub key_id: String,
    pub org_id: String,
    pub heartbeat_interval_seconds: u64,
    pub snapshot_interval_seconds: u64,
    pub key_path: String,
}

/// Returns the platform-appropriate config directory:
///   macOS:   ~/Library/Application Support/open-attest/
///   Windows: %APPDATA%/open-attest/
///   Linux:   ~/.config/open-attest/
pub fn config_dir() -> Result<PathBuf> {
    let base = dirs::config_dir().context("Could not determine config directory")?;
    Ok(base.join("open-attest"))
}

/// Returns the config file path.
pub fn config_path() -> Result<PathBuf> {
    Ok(config_dir()?.join("config.json"))
}

/// Check if the config file exists.
pub fn exists() -> Result<bool> {
    Ok(config_path()?.exists())
}

/// Where the managed agent binary lives. Set by 0.6.0+ installers.
/// Pre-0.6.0 installs at `/usr/local/bin/` won't match this path and
/// will be refused by the updater's binary-not-managed guard.
///
///   macOS:   ~/Library/Application Support/open-attest/bin/
///   Linux:   ~/.local/bin/                  (single binary, no subdir)
///   Windows: %LOCALAPPDATA%\open-attest\bin\
pub fn bin_dir() -> Result<PathBuf> {
    #[cfg(target_os = "linux")]
    {
        let home = dirs::home_dir().context("Could not determine home directory")?;
        Ok(home.join(".local").join("bin"))
    }
    #[cfg(not(target_os = "linux"))]
    {
        Ok(config_dir()?.join("bin"))
    }
}

/// Full path to the managed binary (including the `.exe` suffix on Windows).
pub fn managed_binary_path() -> Result<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        Ok(bin_dir()?.join("open-attest.exe"))
    }
    #[cfg(not(target_os = "windows"))]
    {
        Ok(bin_dir()?.join("open-attest"))
    }
}

/// Where the updater stores its persistent state and partial downloads.
/// Currently the same as `config_dir()` — kept as a separate function so
/// future moves (e.g. to a cache dir) don't ripple through the codebase.
pub fn state_dir() -> Result<PathBuf> {
    config_dir()
}

/// Load config from disk.
pub fn load() -> Result<AgentConfig> {
    let path = config_path()?;
    let contents = fs::read_to_string(&path)
        .with_context(|| format!("Failed to read config file: {}", path.display()))?;
    let config: AgentConfig =
        serde_json::from_str(&contents).context("Failed to parse config file")?;
    Ok(config)
}

/// Save config to disk. Creates the config directory if it doesn't exist.
pub fn save(config: &AgentConfig) -> Result<()> {
    let dir = config_dir()?;
    fs::create_dir_all(&dir)
        .with_context(|| format!("Failed to create config directory: {}", dir.display()))?;

    let path = config_path()?;
    let json = serde_json::to_string_pretty(config).context("Failed to serialize config")?;
    fs::write(&path, json)
        .with_context(|| format!("Failed to write config file: {}", path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn save_and_load_roundtrip() {
        let dir = tempfile::tempdir().unwrap();
        let cfg_path = dir.path().join("config.json");

        let config = AgentConfig {
            server_url: "https://example.com".to_string(),
            agent_id: "agent-1".to_string(),
            device_id: "device-1".to_string(),
            key_id: "key-1".to_string(),
            org_id: "org-1".to_string(),
            heartbeat_interval_seconds: 300,
            snapshot_interval_seconds: 3600,
            key_path: "/tmp/test.key".to_string(),
        };

        let json = serde_json::to_string_pretty(&config).unwrap();
        fs::write(&cfg_path, &json).unwrap();

        let loaded: AgentConfig =
            serde_json::from_str(&fs::read_to_string(&cfg_path).unwrap()).unwrap();
        assert_eq!(loaded.server_url, "https://example.com");
        assert_eq!(loaded.agent_id, "agent-1");
        assert_eq!(loaded.heartbeat_interval_seconds, 300);
        assert_eq!(loaded.snapshot_interval_seconds, 3600);
    }

    #[test]
    fn config_dir_exists() {
        let dir = config_dir().unwrap();
        assert!(dir.to_str().unwrap().contains("open-attest"));
    }

    #[test]
    fn managed_binary_path_is_under_bin_dir() {
        let bin = bin_dir().unwrap();
        let mgr = managed_binary_path().unwrap();
        assert!(mgr.starts_with(&bin));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_bin_dir_under_app_support() {
        let bin = bin_dir().unwrap();
        let s = bin.to_string_lossy();
        assert!(s.contains("Application Support/open-attest/bin"), "got {s}");
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn linux_bin_dir_is_local_bin() {
        let bin = bin_dir().unwrap();
        assert!(bin.ends_with(".local/bin"));
    }

    #[cfg(target_os = "windows")]
    #[test]
    fn windows_managed_binary_has_exe() {
        let mgr = managed_binary_path().unwrap();
        assert_eq!(mgr.extension().unwrap_or_default(), "exe");
    }

    #[test]
    fn config_json_has_all_fields() {
        let config = AgentConfig {
            server_url: "https://test.com".to_string(),
            agent_id: "a1".to_string(),
            device_id: "d1".to_string(),
            key_id: "k1".to_string(),
            org_id: "o1".to_string(),
            heartbeat_interval_seconds: 60,
            snapshot_interval_seconds: 120,
            key_path: "/key".to_string(),
        };
        let json = serde_json::to_string(&config).unwrap();
        assert!(json.contains("server_url"));
        assert!(json.contains("agent_id"));
        assert!(json.contains("device_id"));
        assert!(json.contains("key_id"));
        assert!(json.contains("org_id"));
        assert!(json.contains("heartbeat_interval_seconds"));
        assert!(json.contains("snapshot_interval_seconds"));
        assert!(json.contains("key_path"));
    }

    #[test]
    fn config_rejects_invalid_json() {
        let result = serde_json::from_str::<AgentConfig>("not json");
        assert!(result.is_err());
    }

    #[test]
    fn config_rejects_missing_fields() {
        let result = serde_json::from_str::<AgentConfig>(r#"{"server_url":"x"}"#);
        assert!(result.is_err());
    }
}
