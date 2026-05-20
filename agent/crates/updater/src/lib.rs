//! open-attest auto-updater.
//!
//! Public entry points:
//!  - [`check_and_apply`] — verify and install a server-offered update.
//!    Should be called after each successful attestation/heartbeat. On
//!    success the caller should exit cleanly so the OS supervisor
//!    (launchd / systemd / scheduled task) brings the agent back on the
//!    new binary.
//!  - [`on_daemon_boot`] — called once at the start of the daemon. Handles
//!    the Pending → Probation transition, confirms a successful update,
//!    or rolls back a bad one.
//!  - [`record_successful_attestation`] — called after each successful
//!    attestation/heartbeat. Updates the probation success timestamp.
//!
//! See `.context/updater-plan.md` for the design rationale.

use anyhow::{Context, Result};
use chrono::{DateTime, Duration, Utc};
use open_attest_types::UpdateOffer;
use std::path::{Path, PathBuf};

pub mod download;
pub mod state;
pub mod swap;
pub mod verify;

pub use state::UpdateState;

/// How long the new version must run before we declare the update healthy.
const PROBATION_DURATION_HOURS: i64 = 1;
/// Outer bound — if we never see a recent successful attestation within
/// this window, we roll back even if the binary hasn't crashed.
const PROBATION_TIMEOUT_HOURS: i64 = 24;
/// How recently we need to have had a successful attestation to consider
/// the agent "alive and reaching the server".
const RECENT_SUCCESS_WINDOW_MINUTES: i64 = 10;
/// Boot-count tripwire — guards against fast crash loops where each crash
/// races back through launchd/systemd in seconds.
const BOOT_COUNT_LIMIT: u32 = 10;
/// Minimum gap between failed update attempts.
const RETRY_BACKOFF_HOURS: i64 = 1;

/// Aggregate of everything the updater needs to make a decision. Bundled
/// so callers don't accidentally drop a parameter on the floor.
pub struct UpdateContext<'a> {
    /// Where the JSON state file and `updates/` partial-download dir live.
    pub state_dir: &'a Path,
    /// The managed binary location (e.g. `~/Library/Application Support/open-attest/bin/open-attest`).
    pub bin_path: &'a Path,
    /// What `std::env::current_exe()` returned. Compared to `bin_path` to
    /// detect "binary at unmanaged location" (e.g. legacy `/usr/local/bin`).
    pub current_exe: &'a Path,
    /// Version of the currently running agent (`env!("CARGO_PKG_VERSION")`).
    pub running_version: &'a str,
    /// Rust target triple of the running agent (`env!("BUILD_TARGET")`).
    /// Used as a defense-in-depth check that the server-offered binary
    /// matches our architecture. Empty string means "trust the server".
    pub running_target_triple: &'a str,
    /// Embedded release-signing public key.
    pub release_pubkey: &'a [u8; 32],
}

/// Outcome of `check_and_apply`. The caller cares mainly about
/// `Installed` — when that fires, it should exit cleanly.
#[derive(Debug, PartialEq)]
pub enum UpdateOutcome {
    SkippedAlreadyAtVersion,
    SkippedRateLimited,
    SkippedBinaryNotManaged,
    SkippedNonIdle,
    Installed { version: String },
    Failed { version: String, reason: String },
}

/// Outcome of `on_daemon_boot`. `RolledBack` means the caller should exit
/// cleanly so the supervisor restarts on the now-restored old binary.
#[derive(Debug, PartialEq)]
pub enum BootAction {
    None,
    Confirmed,
    RolledBack,
}

/// Embeds the release-signing public key at compile time. The agent crate
/// uses this constant when constructing the `UpdateContext`.
///
/// The 32-byte raw Ed25519 public key file lives at the repo's
/// `agent/release_pubkey.bin`.
pub const RELEASE_PUBKEY: &[u8; 32] = include_bytes!("../../../release_pubkey.bin");

// ---------------------------------------------------------------------------
// check_and_apply
// ---------------------------------------------------------------------------

pub fn check_and_apply(offer: &UpdateOffer, ctx: &UpdateContext) -> Result<UpdateOutcome> {
    check_and_apply_with_now(offer, ctx, Utc::now())
}

fn check_and_apply_with_now(
    offer: &UpdateOffer,
    ctx: &UpdateContext,
    now: DateTime<Utc>,
) -> Result<UpdateOutcome> {
    // Step 1: only act when fully idle. Pending or Probation means a prior
    // update is still resolving; refuse to start another.
    let st = state::load(ctx.state_dir);
    if !st.is_idle() {
        return Ok(UpdateOutcome::SkippedNonIdle);
    }

    // Steps 2 & 3: version checks. Don't reinstall the same version,
    // and don't downgrade unless force is set (pinning is server-side and
    // sets force=true in the offer).
    if !offer.force {
        if offer.version == ctx.running_version {
            return Ok(UpdateOutcome::SkippedAlreadyAtVersion);
        }
        if version_less_than(&offer.version, ctx.running_version) {
            return Ok(UpdateOutcome::SkippedAlreadyAtVersion);
        }
    }

    // Step 4: binary-at-managed-location guard. Pre-0.6.0 installs at
    // /usr/local/bin will hit this every poll and skip silently — they need
    // a manual reinstall to migrate.
    if ctx.current_exe != ctx.bin_path {
        eprintln!(
            "[updater] refusing to update: binary at unmanaged location {} (managed: {})",
            ctx.current_exe.display(),
            ctx.bin_path.display()
        );
        return Ok(UpdateOutcome::SkippedBinaryNotManaged);
    }

    // Step 5: backoff after a recent failure.
    if let UpdateState::Idle {
        last_attempt_at: Some(t),
        last_failure: Some(_),
        ..
    } = &st
    {
        if now - *t < Duration::hours(RETRY_BACKOFF_HOURS) && !offer.force {
            return Ok(UpdateOutcome::SkippedRateLimited);
        }
    }

    // From here on, any error means we've at least *attempted* this update.
    // Record the attempt before doing work so a crash mid-install still
    // triggers the backoff next time.
    let result = (|| -> Result<()> {
        do_install(offer, ctx).context("install")
    })();

    match result {
        Ok(()) => Ok(UpdateOutcome::Installed {
            version: offer.version.clone(),
        }),
        Err(e) => {
            let reason = format!("{e:#}");
            let _ = state::save(
                ctx.state_dir,
                &UpdateState::Idle {
                    last_offer_version: Some(offer.version.clone()),
                    last_attempt_at: Some(now),
                    last_failure: Some(reason.clone()),
                },
            );
            // Cleanup any partial downloads.
            let _ = std::fs::remove_dir_all(updates_dir(ctx.state_dir));
            Ok(UpdateOutcome::Failed {
                version: offer.version.clone(),
                reason,
            })
        }
    }
}

fn do_install(offer: &UpdateOffer, ctx: &UpdateContext) -> Result<()> {
    // Target-triple guard. The server picks an asset based on what the
    // agent reports as its BUILD_TARGET, so this should already match.
    // We enforce only when both values are non-empty; an empty
    // `running_target_triple` means "trust the server" (tests use this
    // with a synthetic target string).
    if !ctx.running_target_triple.is_empty()
        && offer.target_triple != ctx.running_target_triple
        && !offer.force
    {
        anyhow::bail!(
            "offer target_triple {} does not match this binary ({})",
            offer.target_triple,
            ctx.running_target_triple
        );
    }

    // Step 6: download to <state_dir>/updates/<version>.partial
    let partial = updates_dir(ctx.state_dir).join(format!("{}.partial", offer.version));
    let _ = std::fs::remove_file(&partial);
    download::download_binary(&offer.url, &partial).context("download binary")?;

    // Step 8: sha256
    verify::check_sha256(&partial, &offer.sha256).context("sha256 verification")?;

    // Steps 9 + 10: fetch signature and verify
    let sig_hex = download::download_small(&offer.sig_url).context("download signature")?;
    verify::check_signature(&partial, &sig_hex, ctx.release_pubkey)
        .context("signature verification")?;

    // Step 11 + 12: swap
    swap::make_executable(&partial)?;
    swap::install_swap(&partial, ctx.bin_path).context("install swap")?;

    // Step 13: write Pending state. Caller (daemon) exits 0; supervisor
    // restarts; next boot enters Probation.
    state::save(
        ctx.state_dir,
        &UpdateState::Pending {
            target_version: offer.version.clone(),
            previous_version: ctx.running_version.to_string(),
            installed_at: Utc::now(),
        },
    )?;

    Ok(())
}

fn updates_dir(state_dir: &Path) -> PathBuf {
    state_dir.join("updates")
}

// ---------------------------------------------------------------------------
// on_daemon_boot
// ---------------------------------------------------------------------------

pub fn on_daemon_boot(ctx: &UpdateContext) -> Result<BootAction> {
    on_daemon_boot_with_now(ctx, Utc::now())
}

fn on_daemon_boot_with_now(ctx: &UpdateContext, now: DateTime<Utc>) -> Result<BootAction> {
    let st = state::load(ctx.state_dir);
    let (action, next) = decide_boot(&st, ctx.running_version, now);

    match action {
        BootDecision::None => {}
        BootDecision::EnterProbation => {}
        BootDecision::Confirm => {
            // Probation passed. Clean up .prev binary.
            let _ = std::fs::remove_file(swap::prev_path(ctx.bin_path));
        }
        BootDecision::Rollback { ref reason } => {
            eprintln!("[updater] rolling back: {reason}");
            match swap::rollback(ctx.bin_path) {
                Ok(true) => {}
                Ok(false) => {
                    eprintln!("[updater] no .prev binary; cannot roll back");
                }
                Err(e) => {
                    eprintln!("[updater] rollback failed: {e:#}");
                }
            }
        }
        BootDecision::Reset { ref reason } => {
            eprintln!("[updater] resetting state: {reason}");
        }
    }

    if let Some(next_state) = next {
        state::save(ctx.state_dir, &next_state)?;
    }

    Ok(match action {
        BootDecision::Confirm => BootAction::Confirmed,
        BootDecision::Rollback { .. } => BootAction::RolledBack,
        _ => BootAction::None,
    })
}

#[derive(Debug, PartialEq)]
enum BootDecision {
    None,
    EnterProbation,
    Confirm,
    Rollback { reason: String },
    Reset { reason: String },
}

/// Pure decision function. Returns the action to take and the next state
/// to persist (None means leave the state as-is). Splitting this out
/// makes the rollback/confirm thresholds unit-testable.
fn decide_boot(
    state: &UpdateState,
    running_version: &str,
    now: DateTime<Utc>,
) -> (BootDecision, Option<UpdateState>) {
    match state {
        UpdateState::Idle { .. } => (BootDecision::None, None),

        UpdateState::Pending {
            target_version,
            previous_version,
            ..
        } => {
            if running_version == target_version {
                let next = UpdateState::Probation {
                    version: target_version.clone(),
                    previous_version: previous_version.clone(),
                    probation_started_at: now,
                    boot_count: 1,
                    last_successful_attestation_at: None,
                };
                (BootDecision::EnterProbation, Some(next))
            } else {
                let reason = format!(
                    "Pending target {target_version} but running {running_version}; \
                     supervisor may not have picked up the swap"
                );
                (
                    BootDecision::Reset { reason: reason.clone() },
                    Some(UpdateState::Idle {
                        last_offer_version: Some(target_version.clone()),
                        last_attempt_at: Some(now),
                        last_failure: Some(reason),
                    }),
                )
            }
        }

        UpdateState::Probation {
            version,
            previous_version,
            probation_started_at,
            boot_count,
            last_successful_attestation_at,
        } => {
            // Bump boot_count before risky work elsewhere — caller is
            // responsible for persisting this state regardless of which
            // arm we pick below.
            let bumped_count = boot_count.saturating_add(1);

            // Rollback: boot loop.
            if bumped_count >= BOOT_COUNT_LIMIT {
                let reason = format!(
                    "boot loop: {bumped_count} restarts during probation of {version}"
                );
                return (
                    BootDecision::Rollback {
                        reason: reason.clone(),
                    },
                    Some(UpdateState::Idle {
                        last_offer_version: Some(version.clone()),
                        last_attempt_at: Some(now),
                        last_failure: Some(reason),
                    }),
                );
            }

            let elapsed = now - *probation_started_at;
            let recent_success = last_successful_attestation_at
                .map(|t| now - t < Duration::minutes(RECENT_SUCCESS_WINDOW_MINUTES))
                .unwrap_or(false);

            // Confirm: enough time elapsed AND a recent server success.
            if elapsed >= Duration::hours(PROBATION_DURATION_HOURS) && recent_success {
                return (
                    BootDecision::Confirm,
                    Some(UpdateState::Idle {
                        last_offer_version: Some(version.clone()),
                        last_attempt_at: None,
                        last_failure: None,
                    }),
                );
            }

            // Rollback: probation window exhausted without ever reaching server.
            if elapsed >= Duration::hours(PROBATION_TIMEOUT_HOURS) && !recent_success {
                let reason = format!(
                    "no successful attestation within {PROBATION_TIMEOUT_HOURS}h of installing {version}"
                );
                return (
                    BootDecision::Rollback {
                        reason: reason.clone(),
                    },
                    Some(UpdateState::Idle {
                        last_offer_version: Some(version.clone()),
                        last_attempt_at: Some(now),
                        last_failure: Some(reason),
                    }),
                );
            }

            // Probation continues. Persist the bumped boot_count.
            (
                BootDecision::None,
                Some(UpdateState::Probation {
                    version: version.clone(),
                    previous_version: previous_version.clone(),
                    probation_started_at: *probation_started_at,
                    boot_count: bumped_count,
                    last_successful_attestation_at: *last_successful_attestation_at,
                }),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// record_successful_attestation
// ---------------------------------------------------------------------------

pub fn record_successful_attestation(state_dir: &Path) -> Result<()> {
    let state = state::load(state_dir);
    if let UpdateState::Probation {
        version,
        previous_version,
        probation_started_at,
        boot_count,
        ..
    } = state
    {
        state::save(
            state_dir,
            &UpdateState::Probation {
                version,
                previous_version,
                probation_started_at,
                boot_count,
                last_successful_attestation_at: Some(Utc::now()),
            },
        )?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Tiny semver comparator. Enough for "X.Y.Z" tag versions.
// ---------------------------------------------------------------------------

fn parse_version(s: &str) -> Option<(u64, u64, u64)> {
    let stripped = s.strip_prefix('v').unwrap_or(s);
    let mut it = stripped.split('.');
    let major = it.next()?.parse().ok()?;
    let minor = it.next()?.parse().ok()?;
    let patch_part = it.next()?;
    // Drop any prerelease/build metadata after a `-` or `+`.
    let patch_clean = patch_part
        .split(|c| c == '-' || c == '+')
        .next()?;
    let patch = patch_clean.parse().ok()?;
    if it.next().is_some() {
        return None;
    }
    Some((major, minor, patch))
}

fn version_less_than(a: &str, b: &str) -> bool {
    match (parse_version(a), parse_version(b)) {
        (Some(va), Some(vb)) => va < vb,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> DateTime<Utc> {
        Utc::now()
    }

    // ---------- version comparator ----------

    #[test]
    fn version_parsing_basic() {
        assert_eq!(parse_version("0.6.0"), Some((0, 6, 0)));
        assert_eq!(parse_version("1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("v1.2.3"), Some((1, 2, 3)));
        assert_eq!(parse_version("10.20.30"), Some((10, 20, 30)));
    }

    #[test]
    fn version_parsing_strips_prerelease() {
        assert_eq!(parse_version("1.2.3-rc1"), Some((1, 2, 3)));
        assert_eq!(parse_version("1.2.3+build5"), Some((1, 2, 3)));
    }

    #[test]
    fn version_parsing_rejects_garbage() {
        assert_eq!(parse_version("not a version"), None);
        assert_eq!(parse_version("1.2"), None);
        assert_eq!(parse_version("1.2.3.4"), None);
    }

    #[test]
    fn version_less_than_ordering() {
        assert!(version_less_than("0.5.0", "0.6.0"));
        assert!(version_less_than("0.5.9", "0.6.0"));
        assert!(version_less_than("0.5.0", "1.0.0"));
        assert!(!version_less_than("0.6.0", "0.5.0"));
        assert!(!version_less_than("0.6.0", "0.6.0"));
        assert!(!version_less_than("garbage", "0.6.0"));
    }

    // ---------- decide_boot ----------

    #[test]
    fn idle_state_yields_none() {
        let (action, next) = decide_boot(&UpdateState::default(), "0.6.0", now());
        assert_eq!(action, BootDecision::None);
        assert!(next.is_none());
    }

    #[test]
    fn pending_with_matching_version_enters_probation() {
        let st = UpdateState::Pending {
            target_version: "0.6.0".to_string(),
            previous_version: "0.5.0".to_string(),
            installed_at: now(),
        };
        let (action, next) = decide_boot(&st, "0.6.0", now());
        assert_eq!(action, BootDecision::EnterProbation);
        assert!(matches!(next, Some(UpdateState::Probation { boot_count: 1, .. })));
    }

    #[test]
    fn pending_with_mismatched_version_resets() {
        let st = UpdateState::Pending {
            target_version: "0.6.0".to_string(),
            previous_version: "0.5.0".to_string(),
            installed_at: now(),
        };
        let (action, next) = decide_boot(&st, "0.5.0", now());
        assert!(matches!(action, BootDecision::Reset { .. }));
        assert!(matches!(next, Some(UpdateState::Idle { .. })));
    }

    #[test]
    fn probation_confirms_after_1h_with_recent_success() {
        let started = Utc::now() - Duration::hours(2);
        let st = UpdateState::Probation {
            version: "0.6.0".to_string(),
            previous_version: "0.5.0".to_string(),
            probation_started_at: started,
            boot_count: 1,
            last_successful_attestation_at: Some(Utc::now() - Duration::minutes(5)),
        };
        let (action, next) = decide_boot(&st, "0.6.0", Utc::now());
        assert_eq!(action, BootDecision::Confirm);
        assert!(matches!(next, Some(UpdateState::Idle { .. })));
    }

    #[test]
    fn probation_does_not_confirm_without_recent_success() {
        let started = Utc::now() - Duration::hours(2);
        let st = UpdateState::Probation {
            version: "0.6.0".to_string(),
            previous_version: "0.5.0".to_string(),
            probation_started_at: started,
            boot_count: 1,
            last_successful_attestation_at: None,
        };
        let (action, _) = decide_boot(&st, "0.6.0", Utc::now());
        assert_eq!(action, BootDecision::None);
    }

    #[test]
    fn probation_does_not_confirm_with_old_success() {
        let started = Utc::now() - Duration::hours(2);
        let st = UpdateState::Probation {
            version: "0.6.0".to_string(),
            previous_version: "0.5.0".to_string(),
            probation_started_at: started,
            boot_count: 1,
            last_successful_attestation_at: Some(Utc::now() - Duration::hours(2)),
        };
        let (action, _) = decide_boot(&st, "0.6.0", Utc::now());
        // Stale success means we keep waiting, not confirm.
        assert_eq!(action, BootDecision::None);
    }

    #[test]
    fn probation_does_not_confirm_before_1h() {
        let started = Utc::now() - Duration::minutes(30);
        let st = UpdateState::Probation {
            version: "0.6.0".to_string(),
            previous_version: "0.5.0".to_string(),
            probation_started_at: started,
            boot_count: 1,
            last_successful_attestation_at: Some(Utc::now()),
        };
        let (action, _) = decide_boot(&st, "0.6.0", Utc::now());
        assert_eq!(action, BootDecision::None);
    }

    #[test]
    fn probation_rolls_back_at_boot_count_limit() {
        let st = UpdateState::Probation {
            version: "0.6.0".to_string(),
            previous_version: "0.5.0".to_string(),
            probation_started_at: Utc::now() - Duration::minutes(5),
            boot_count: BOOT_COUNT_LIMIT - 1,
            last_successful_attestation_at: None,
        };
        let (action, _) = decide_boot(&st, "0.6.0", Utc::now());
        assert!(matches!(action, BootDecision::Rollback { .. }));
    }

    #[test]
    fn probation_rolls_back_after_24h_without_success() {
        let started = Utc::now() - Duration::hours(25);
        let st = UpdateState::Probation {
            version: "0.6.0".to_string(),
            previous_version: "0.5.0".to_string(),
            probation_started_at: started,
            boot_count: 1,
            last_successful_attestation_at: None,
        };
        let (action, _) = decide_boot(&st, "0.6.0", Utc::now());
        assert!(matches!(action, BootDecision::Rollback { .. }));
    }

    #[test]
    fn probation_increments_boot_count() {
        let started = Utc::now() - Duration::minutes(10);
        let st = UpdateState::Probation {
            version: "0.6.0".to_string(),
            previous_version: "0.5.0".to_string(),
            probation_started_at: started,
            boot_count: 3,
            last_successful_attestation_at: None,
        };
        let (action, next) = decide_boot(&st, "0.6.0", Utc::now());
        assert_eq!(action, BootDecision::None);
        match next {
            Some(UpdateState::Probation { boot_count, .. }) => assert_eq!(boot_count, 4),
            _ => panic!("expected Probation next state"),
        }
    }
}
