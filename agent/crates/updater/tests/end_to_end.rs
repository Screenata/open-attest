//! Integration tests: full check_and_apply path against a local HTTP server
//! serving a real signed fixture binary.

use ed25519_dalek::{Signer, SigningKey};
use open_attest_types::UpdateOffer;
use open_attest_updater::{
    check_and_apply, on_daemon_boot, record_successful_attestation, swap, BootAction,
    UpdateContext, UpdateOutcome, UpdateState,
};
use rand::RngCore;
use sha2::{Digest, Sha256};
use std::fs;
use std::path::PathBuf;
use std::sync::mpsc;
use std::thread;
use tempfile::tempdir;
use tiny_http::{Header, Method, Response, Server};

fn new_signing_key() -> SigningKey {
    let mut seed = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut seed);
    SigningKey::from_bytes(&seed)
}

struct ReleaseFixture {
    bin_bytes: Vec<u8>,
    sig_hex: String,
    sha256_hex: String,
    pubkey: [u8; 32],
}

impl ReleaseFixture {
    fn new(bin_bytes: Vec<u8>) -> Self {
        let signing = new_signing_key();
        let pubkey: [u8; 32] = signing.verifying_key().to_bytes();
        let sig = signing.sign(&bin_bytes);
        let sig_hex = hex::encode(sig.to_bytes());
        let sha256_hex = hex::encode(Sha256::digest(&bin_bytes));
        ReleaseFixture {
            bin_bytes,
            sig_hex,
            sha256_hex,
            pubkey,
        }
    }
}

/// Tiny multi-route http server. Serves the binary at /bin and the sig
/// at /bin.sig. Stays alive for the test's duration via the returned guard.
struct ServerGuard {
    port: u16,
    _join: thread::JoinHandle<()>,
    _stop: mpsc::Sender<()>,
}

fn start_server(fixture: &ReleaseFixture) -> ServerGuard {
    let server = Server::http("127.0.0.1:0").unwrap();
    let port = server.server_addr().to_ip().unwrap().port();
    let bin = fixture.bin_bytes.clone();
    let sig = fixture.sig_hex.clone();
    let (stop_tx, stop_rx) = mpsc::channel();
    let handle = thread::spawn(move || {
        loop {
            if stop_rx.try_recv().is_ok() {
                break;
            }
            match server.recv_timeout(std::time::Duration::from_millis(50)) {
                Ok(Some(req)) => {
                    let url = req.url().to_string();
                    if req.method() != &Method::Get {
                        let _ = req.respond(Response::empty(405));
                        continue;
                    }
                    let resp = if url.ends_with("/bin.sig") {
                        let mut r = Response::from_data(sig.as_bytes().to_vec());
                        r.add_header(
                            Header::from_bytes(&b"Content-Type"[..], &b"text/plain"[..]).unwrap(),
                        );
                        r
                    } else if url.ends_with("/bin") {
                        let mut r = Response::from_data(bin.clone());
                        r.add_header(
                            Header::from_bytes(
                                &b"Content-Type"[..],
                                &b"application/octet-stream"[..],
                            )
                            .unwrap(),
                        );
                        r
                    } else {
                        Response::from_data(b"not found".to_vec()).with_status_code(404)
                    };
                    let _ = req.respond(resp);
                }
                Ok(None) => {}
                Err(_) => break,
            }
        }
    });
    ServerGuard {
        port,
        _join: handle,
        _stop: stop_tx,
    }
}

fn make_offer(fixture: &ReleaseFixture, port: u16, version: &str) -> UpdateOffer {
    UpdateOffer {
        version: version.to_string(),
        target_triple: "test-target".to_string(),
        url: format!("http://127.0.0.1:{port}/bin"),
        sig_url: format!("http://127.0.0.1:{port}/bin.sig"),
        sha256: fixture.sha256_hex.clone(),
        force: false,
        min_dwell_seconds: 0,
    }
}

struct Dirs {
    state_dir: PathBuf,
    bin_path: PathBuf,
}

fn setup_dirs(initial_bytes: &[u8]) -> (tempfile::TempDir, Dirs) {
    let dir = tempdir().unwrap();
    let state_dir = dir.path().join("state");
    let bin_dir = dir.path().join("bin");
    fs::create_dir_all(&state_dir).unwrap();
    fs::create_dir_all(&bin_dir).unwrap();
    let bin_path = bin_dir.join("open-attest");
    fs::write(&bin_path, initial_bytes).unwrap();
    (
        dir,
        Dirs {
            state_dir,
            bin_path,
        },
    )
}

// =========================================================================
// Tests
// =========================================================================

#[test]
fn happy_path_install_and_confirm() {
    let new_bin = vec![0x42u8; 1_500_000];
    let fixture = ReleaseFixture::new(new_bin.clone());
    let server = start_server(&fixture);

    let (_guard, dirs) = setup_dirs(b"current binary v0.5.0");
    let offer = make_offer(&fixture, server.port, "0.6.0");

    let ctx = UpdateContext {
        state_dir: &dirs.state_dir,
        bin_path: &dirs.bin_path,
        current_exe: &dirs.bin_path, // pretend the running binary is the managed one
        running_version: "0.5.0",
        running_target_triple: "",
        release_pubkey: &fixture.pubkey,
    };

    let outcome = check_and_apply(&offer, &ctx).unwrap();
    assert!(
        matches!(outcome, UpdateOutcome::Installed { ref version } if version == "0.6.0"),
        "expected Installed, got {outcome:?}"
    );

    // Disk side-effects: new binary in place, .prev kept.
    assert_eq!(fs::read(&dirs.bin_path).unwrap(), new_bin);
    let prev_path = swap::prev_path(&dirs.bin_path);
    assert_eq!(fs::read(&prev_path).unwrap(), b"current binary v0.5.0");

    // State file should be Pending.
    let st = open_attest_updater::state::load(&dirs.state_dir);
    assert!(matches!(st, UpdateState::Pending { .. }), "got {st:?}");

    // Simulate supervisor restart on the new version: on_daemon_boot
    // transitions Pending -> Probation.
    let ctx2 = UpdateContext {
        state_dir: &dirs.state_dir,
        bin_path: &dirs.bin_path,
        current_exe: &dirs.bin_path,
        running_version: "0.6.0",
        running_target_triple: "",
        release_pubkey: &fixture.pubkey,
    };
    let action = on_daemon_boot(&ctx2).unwrap();
    assert_eq!(action, BootAction::None);
    let st = open_attest_updater::state::load(&dirs.state_dir);
    assert!(matches!(st, UpdateState::Probation { .. }), "got {st:?}");
}

#[test]
fn rejects_bad_signature() {
    let new_bin = vec![0x42u8; 1_500_000];
    let mut fixture = ReleaseFixture::new(new_bin);
    // Corrupt the signature.
    fixture.sig_hex.replace_range(0..2, "00");
    let server = start_server(&fixture);

    let (_guard, dirs) = setup_dirs(b"current");
    let offer = make_offer(&fixture, server.port, "0.6.0");
    let ctx = UpdateContext {
        state_dir: &dirs.state_dir,
        bin_path: &dirs.bin_path,
        current_exe: &dirs.bin_path,
        running_version: "0.5.0",
        running_target_triple: "",
        release_pubkey: &fixture.pubkey,
    };
    let outcome = check_and_apply(&offer, &ctx).unwrap();
    assert!(
        matches!(outcome, UpdateOutcome::Failed { .. }),
        "expected Failed, got {outcome:?}"
    );
    // Current binary must be untouched.
    assert_eq!(fs::read(&dirs.bin_path).unwrap(), b"current");
}

#[test]
fn rejects_sha256_mismatch() {
    let new_bin = vec![0x42u8; 1_500_000];
    let mut fixture = ReleaseFixture::new(new_bin);
    fixture.sha256_hex = "0".repeat(64);
    let server = start_server(&fixture);

    let (_guard, dirs) = setup_dirs(b"current");
    let offer = make_offer(&fixture, server.port, "0.6.0");
    let ctx = UpdateContext {
        state_dir: &dirs.state_dir,
        bin_path: &dirs.bin_path,
        current_exe: &dirs.bin_path,
        running_version: "0.5.0",
        running_target_triple: "",
        release_pubkey: &fixture.pubkey,
    };
    let outcome = check_and_apply(&offer, &ctx).unwrap();
    assert!(matches!(outcome, UpdateOutcome::Failed { .. }));
    assert_eq!(fs::read(&dirs.bin_path).unwrap(), b"current");
}

#[test]
fn skips_when_binary_not_at_managed_path() {
    let new_bin = vec![0x42u8; 1_500_000];
    let fixture = ReleaseFixture::new(new_bin);
    let server = start_server(&fixture);

    let (_guard, dirs) = setup_dirs(b"current");
    let offer = make_offer(&fixture, server.port, "0.6.0");
    let other = dirs.bin_path.with_file_name("not-managed");
    fs::write(&other, b"impostor").unwrap();
    let ctx = UpdateContext {
        state_dir: &dirs.state_dir,
        bin_path: &dirs.bin_path,
        current_exe: &other,
        running_version: "0.5.0",
        running_target_triple: "",
        release_pubkey: &fixture.pubkey,
    };
    let outcome = check_and_apply(&offer, &ctx).unwrap();
    assert_eq!(outcome, UpdateOutcome::SkippedBinaryNotManaged);
    assert_eq!(fs::read(&dirs.bin_path).unwrap(), b"current");
}

#[test]
fn skips_when_already_at_version() {
    let fixture = ReleaseFixture::new(vec![0u8; 1_500_000]);
    let server = start_server(&fixture);
    let (_guard, dirs) = setup_dirs(b"current");
    let offer = make_offer(&fixture, server.port, "0.6.0");
    let ctx = UpdateContext {
        state_dir: &dirs.state_dir,
        bin_path: &dirs.bin_path,
        current_exe: &dirs.bin_path,
        running_version: "0.6.0",
        running_target_triple: "",
        release_pubkey: &fixture.pubkey,
    };
    assert_eq!(
        check_and_apply(&offer, &ctx).unwrap(),
        UpdateOutcome::SkippedAlreadyAtVersion
    );
}

#[test]
fn record_successful_attestation_updates_probation() {
    let dir = tempdir().unwrap();
    let initial = UpdateState::Probation {
        version: "0.6.0".to_string(),
        previous_version: "0.5.0".to_string(),
        probation_started_at: chrono::Utc::now() - chrono::Duration::minutes(30),
        boot_count: 2,
        last_successful_attestation_at: None,
    };
    open_attest_updater::state::save(dir.path(), &initial).unwrap();

    record_successful_attestation(dir.path()).unwrap();

    match open_attest_updater::state::load(dir.path()) {
        UpdateState::Probation {
            last_successful_attestation_at: Some(_),
            ..
        } => {}
        other => panic!("expected Probation with success timestamp, got {other:?}"),
    }
}

#[test]
fn record_successful_attestation_noop_when_idle() {
    let dir = tempdir().unwrap();
    open_attest_updater::state::save(dir.path(), &UpdateState::default()).unwrap();
    record_successful_attestation(dir.path()).unwrap();
    // Still Idle.
    assert!(open_attest_updater::state::load(dir.path()).is_idle());
}

#[test]
fn full_lifecycle_install_probation_confirm() {
    // Install -> Pending -> Probation -> simulate success -> Confirm.
    let new_bin = vec![0xACu8; 1_500_000];
    let fixture = ReleaseFixture::new(new_bin.clone());
    let server = start_server(&fixture);

    let (_guard, dirs) = setup_dirs(b"v0.5.0");
    let offer = make_offer(&fixture, server.port, "0.6.0");
    let ctx_old = UpdateContext {
        state_dir: &dirs.state_dir,
        bin_path: &dirs.bin_path,
        current_exe: &dirs.bin_path,
        running_version: "0.5.0",
        running_target_triple: "",
        release_pubkey: &fixture.pubkey,
    };
    assert!(matches!(
        check_and_apply(&offer, &ctx_old).unwrap(),
        UpdateOutcome::Installed { .. }
    ));

    // Restart on new binary.
    let ctx_new = UpdateContext {
        state_dir: &dirs.state_dir,
        bin_path: &dirs.bin_path,
        current_exe: &dirs.bin_path,
        running_version: "0.6.0",
        running_target_triple: "",
        release_pubkey: &fixture.pubkey,
    };
    on_daemon_boot(&ctx_new).unwrap();

    // Synthesize "1h+ elapsed, recent success" by directly poking state.
    match open_attest_updater::state::load(&dirs.state_dir) {
        UpdateState::Probation {
            version,
            previous_version,
            boot_count,
            ..
        } => {
            let synthesized = UpdateState::Probation {
                version,
                previous_version,
                probation_started_at: chrono::Utc::now() - chrono::Duration::hours(2),
                boot_count,
                last_successful_attestation_at: Some(chrono::Utc::now() - chrono::Duration::minutes(2)),
            };
            open_attest_updater::state::save(&dirs.state_dir, &synthesized).unwrap();
        }
        other => panic!("expected Probation, got {other:?}"),
    }

    // Next "boot" should confirm and remove .prev.
    let action = on_daemon_boot(&ctx_new).unwrap();
    assert_eq!(action, BootAction::Confirmed);
    assert!(!swap::prev_path(&dirs.bin_path).exists());
    assert!(open_attest_updater::state::load(&dirs.state_dir).is_idle());
}

#[test]
fn rollback_restores_previous_binary() {
    // Boot in probation with boot_count at the limit -> rollback.
    let (_guard, dirs) = setup_dirs(b"bad v0.6.0");
    // Simulate the .prev binary that would exist after a swap.
    fs::write(swap::prev_path(&dirs.bin_path), b"good v0.5.0").unwrap();

    // boot_count = 9 means the *next* boot will tick to 10 and trip rollback.
    // Keep in sync with BOOT_COUNT_LIMIT in lib.rs.
    let state = UpdateState::Probation {
        version: "0.6.0".to_string(),
        previous_version: "0.5.0".to_string(),
        probation_started_at: chrono::Utc::now(),
        boot_count: 9,
        last_successful_attestation_at: None,
    };
    open_attest_updater::state::save(&dirs.state_dir, &state).unwrap();

    let pubkey = [0u8; 32];
    let ctx = UpdateContext {
        state_dir: &dirs.state_dir,
        bin_path: &dirs.bin_path,
        current_exe: &dirs.bin_path,
        running_version: "0.6.0",
        running_target_triple: "",
        release_pubkey: &pubkey,
    };

    let action = on_daemon_boot(&ctx).unwrap();
    assert_eq!(action, BootAction::RolledBack);
    assert_eq!(fs::read(&dirs.bin_path).unwrap(), b"good v0.5.0");
    // Failed copy is kept for forensics.
    assert_eq!(
        fs::read(swap::failed_path(&dirs.bin_path)).unwrap(),
        b"bad v0.6.0"
    );
    assert!(open_attest_updater::state::load(&dirs.state_dir).is_idle());
}
