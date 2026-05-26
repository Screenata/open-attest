//! Persistent state machine for the updater.
//!
//! See `.context/updater-plan.md` §5.5–5.7 for the algorithm.
//!
//! The state file (`<config_dir>/update_state.json`) tracks where we are in
//! the install -> probation -> confirm/rollback lifecycle. It survives daemon
//! restarts and is the only thing standing between us and a brick.

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::{Path, PathBuf};

/// The single piece of persistent state the updater tracks.
///
/// JSON-tagged by the `phase` field for forward compatibility and so
/// migrations across phase shapes don't require schema versioning.
#[derive(Serialize, Deserialize, Clone, Debug, PartialEq)]
#[serde(tag = "phase")]
pub enum UpdateState {
    /// No update in flight. May still record metadata from the last attempt.
    Idle {
        #[serde(default)]
        last_offer_version: Option<String>,
        #[serde(default)]
        last_attempt_at: Option<DateTime<Utc>>,
        #[serde(default)]
        last_failure: Option<String>,
    },
    /// Binary was successfully swapped on disk. We are waiting for the
    /// supervisor to restart us into the new version.
    Pending {
        target_version: String,
        previous_version: String,
        installed_at: DateTime<Utc>,
    },
    /// Running the new version, watching for crashes. Confirms after 1h +
    /// recent success. Rolls back on boot_count >= 10 or 24h without success.
    Probation {
        version: String,
        previous_version: String,
        probation_started_at: DateTime<Utc>,
        boot_count: u32,
        #[serde(default)]
        last_successful_attestation_at: Option<DateTime<Utc>>,
    },
}

impl Default for UpdateState {
    fn default() -> Self {
        UpdateState::Idle {
            last_offer_version: None,
            last_attempt_at: None,
            last_failure: None,
        }
    }
}

impl UpdateState {
    pub fn is_idle(&self) -> bool {
        matches!(self, UpdateState::Idle { .. })
    }

    pub fn phase_name(&self) -> &'static str {
        match self {
            UpdateState::Idle { .. } => "Idle",
            UpdateState::Pending { .. } => "Pending",
            UpdateState::Probation { .. } => "Probation",
        }
    }
}

pub fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join("update_state.json")
}

/// Load state from disk. Returns `Default` (Idle) if the file is missing or
/// unparseable — we never want a corrupted state file to brick the agent.
pub fn load(state_dir: &Path) -> UpdateState {
    let path = state_path(state_dir);
    match fs::read_to_string(&path) {
        Ok(s) => serde_json::from_str(&s).unwrap_or_default(),
        Err(_) => UpdateState::default(),
    }
}

/// Save state to disk via temp-file + rename. `fs::rename` is atomic on
/// Unix and uses MoveFileExW with REPLACE_EXISTING on Windows.
pub fn save(state_dir: &Path, state: &UpdateState) -> Result<()> {
    fs::create_dir_all(state_dir)
        .with_context(|| format!("create state dir: {}", state_dir.display()))?;
    let final_path = state_path(state_dir);
    let tmp = final_path.with_extension("json.tmp");
    let json = serde_json::to_string_pretty(state).context("serialize state")?;
    fs::write(&tmp, json).with_context(|| format!("write {}", tmp.display()))?;
    fs::rename(&tmp, &final_path)
        .with_context(|| format!("rename {} -> {}", tmp.display(), final_path.display()))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn default_is_idle() {
        assert!(UpdateState::default().is_idle());
    }

    #[test]
    fn missing_file_loads_as_idle() {
        let dir = tempdir().unwrap();
        let s = load(dir.path());
        assert!(s.is_idle());
    }

    #[test]
    fn corrupt_file_loads_as_idle() {
        let dir = tempdir().unwrap();
        fs::write(state_path(dir.path()), "not json").unwrap();
        let s = load(dir.path());
        assert!(s.is_idle());
    }

    #[test]
    fn idle_roundtrip() {
        let dir = tempdir().unwrap();
        let state = UpdateState::Idle {
            last_offer_version: Some("0.6.0".to_string()),
            last_attempt_at: Some(Utc::now()),
            last_failure: Some("test failure".to_string()),
        };
        save(dir.path(), &state).unwrap();
        let loaded = load(dir.path());
        assert_eq!(state, loaded);
    }

    #[test]
    fn pending_roundtrip() {
        let dir = tempdir().unwrap();
        let state = UpdateState::Pending {
            target_version: "0.6.0".to_string(),
            previous_version: "0.5.0".to_string(),
            installed_at: Utc::now(),
        };
        save(dir.path(), &state).unwrap();
        let loaded = load(dir.path());
        assert_eq!(state, loaded);
    }

    #[test]
    fn probation_roundtrip() {
        let dir = tempdir().unwrap();
        let state = UpdateState::Probation {
            version: "0.6.0".to_string(),
            previous_version: "0.5.0".to_string(),
            probation_started_at: Utc::now(),
            boot_count: 3,
            last_successful_attestation_at: Some(Utc::now()),
        };
        save(dir.path(), &state).unwrap();
        let loaded = load(dir.path());
        assert_eq!(state, loaded);
    }

    #[test]
    fn save_creates_state_dir_if_missing() {
        let dir = tempdir().unwrap();
        let nested = dir.path().join("nested").join("dir");
        save(&nested, &UpdateState::default()).unwrap();
        assert!(state_path(&nested).exists());
    }

    #[test]
    fn phase_name_strings_match_serde_tags() {
        let idle = UpdateState::default();
        let pending = UpdateState::Pending {
            target_version: "0.6.0".to_string(),
            previous_version: "0.5.0".to_string(),
            installed_at: Utc::now(),
        };
        let probation = UpdateState::Probation {
            version: "0.6.0".to_string(),
            previous_version: "0.5.0".to_string(),
            probation_started_at: Utc::now(),
            boot_count: 1,
            last_successful_attestation_at: None,
        };
        assert_eq!(idle.phase_name(), "Idle");
        assert_eq!(pending.phase_name(), "Pending");
        assert_eq!(probation.phase_name(), "Probation");
    }
}
