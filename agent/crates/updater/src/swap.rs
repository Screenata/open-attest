//! Binary swap and rollback operations.
//!
//! Unix path: atomic same-filesystem rename, with copy+rename fallback
//! across filesystems (EXDEV). Windows path is stubbed for v1 — phase 7
//! adds the helper-task swap.

use anyhow::{bail, Context, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Returns `bin_path.prev`, the path used to store the previous binary
/// during probation so we can roll back.
pub fn prev_path(bin_path: &Path) -> PathBuf {
    append_ext(bin_path, "prev")
}

/// Returns `bin_path.failed`, the forensic copy kept after a rollback so
/// we can collect symbols / dumps from the bad binary.
pub fn failed_path(bin_path: &Path) -> PathBuf {
    append_ext(bin_path, "failed")
}

fn append_ext(p: &Path, ext: &str) -> PathBuf {
    let mut s = p.as_os_str().to_owned();
    s.push(".");
    s.push(ext);
    PathBuf::from(s)
}

/// Replaces `dst` with `src` atomically. On Unix this is a single rename
/// when both paths are on the same filesystem. If the rename fails (e.g.
/// EXDEV across mounts), copy the source to a sibling of `dst`, fsync,
/// then rename — atomicity is at the destination, which is what callers
/// care about.
pub fn replace_atomically(src: &Path, dst: &Path) -> Result<()> {
    match fs::rename(src, dst) {
        Ok(()) => return Ok(()),
        Err(e) => {
            // ENOENT on src → real problem, surface it.
            if e.kind() == std::io::ErrorKind::NotFound {
                bail!("source not found: {}: {}", src.display(), e);
            }
        }
    }

    // Fallback: copy to dst-sibling tmp, fsync, then rename.
    let dst_tmp = append_ext(dst, "incoming");
    fs::copy(src, &dst_tmp)
        .with_context(|| format!("copy {} -> {}", src.display(), dst_tmp.display()))?;

    // Best-effort fsync the copy. If this fails, the rename below still
    // succeeds — durability is graceful-degradation.
    if let Ok(f) = fs::File::open(&dst_tmp) {
        let _ = f.sync_all();
    }

    fs::rename(&dst_tmp, dst).with_context(|| {
        format!("rename {} -> {}", dst_tmp.display(), dst.display())
    })?;

    // Best-effort: remove the original src so we don't leave stale partials.
    let _ = fs::remove_file(src);
    Ok(())
}

/// On Unix, sets executable bits on `path` (0755). No-op on Windows
/// (executability is by extension there).
pub fn make_executable(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = fs::metadata(path)
            .with_context(|| format!("stat {}", path.display()))?
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms)
            .with_context(|| format!("chmod 755 {}", path.display()))?;
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Performs the binary swap: current binary → `.prev`, new binary → managed
/// path.
///
/// On Unix this is two `replace_atomically` calls — the running process can
/// keep executing the old inode while the new file takes its place.
///
/// On Windows the running .exe is file-locked so we can't replace it
/// in-process. Instead we stage the verified binary as `bin_path.new` next
/// to it, then register a one-shot scheduled task that runs ~1 minute out
/// to do the moves and re-trigger the main task once the daemon has exited.
pub fn install_swap(new_binary: &Path, bin_path: &Path) -> Result<()> {
    if !new_binary.exists() {
        bail!("new binary missing: {}", new_binary.display());
    }
    if !bin_path.exists() {
        bail!(
            "current binary missing at expected location: {}",
            bin_path.display()
        );
    }

    #[cfg(windows)]
    {
        install_swap_windows(new_binary, bin_path)
    }

    #[cfg(not(windows))]
    {
        let prev = prev_path(bin_path);
        // Remove any stale .prev from a prior aborted swap.
        let _ = fs::remove_file(&prev);

        replace_atomically(bin_path, &prev)
            .with_context(|| "move current binary to .prev")?;
        replace_atomically(new_binary, bin_path)
            .with_context(|| "move new binary into place")?;
        make_executable(bin_path)?;
        Ok(())
    }
}

#[cfg(windows)]
fn install_swap_windows(new_binary: &Path, bin_path: &Path) -> Result<()> {
    use chrono::{Duration as ChronoDuration, Local};
    use std::process::Command;

    // Names must stay in sync with the main scheduled task created in
    // `agent::winsvc::install_task` ("OpenAttestAgent"). If you rename
    // there, rename here too. The swap task is a transient one-shot and
    // we always (re)create it with /F to overwrite.
    const MAIN_TASK_NAME: &str = "OpenAttestAgent";
    const SWAP_TASK_NAME: &str = "OpenAttestAgentSwap";

    let new_path = append_ext(bin_path, "new");
    let _ = fs::remove_file(&new_path);
    replace_atomically(new_binary, &new_path)
        .with_context(|| "stage new binary at .new")?;

    // schtasks /ST accepts HH:MM (and HH:MM:SS in modern Windows). Round
    // up to the next whole minute so the task scheduler accepts the time
    // unconditionally — Windows refuses past-or-now triggers.
    let trigger_at = Local::now() + ChronoDuration::seconds(75);
    let start_time = trigger_at.format("%H:%M").to_string();
    let start_date = trigger_at.format("%m/%d/%Y").to_string();

    let bin_str = bin_path.to_string_lossy().into_owned();
    let prev_str = prev_path(bin_path).to_string_lossy().into_owned();
    let new_str = new_path.to_string_lossy().into_owned();

    // The helper command:
    //   1. Move current -> .prev (replace stale if present)
    //   2. Move .new    -> current
    //   3. Re-trigger the main task so the daemon comes back on the new binary.
    //   4. Best-effort delete this helper task.
    let helper_cmd = format!(
        "del /F /Q \"{prev}\" 2>nul & \
         move /Y \"{bin}\" \"{prev}\" && \
         move /Y \"{new}\" \"{bin}\" && \
         schtasks /Run /TN \"{main}\" & \
         schtasks /Delete /TN \"{swap}\" /F",
        prev = prev_str,
        bin = bin_str,
        new = new_str,
        main = MAIN_TASK_NAME,
        swap = SWAP_TASK_NAME,
    );

    // /SC ONCE /SD /ST gives us a single fire at the chosen wall time. /F
    // overwrites any leftover swap task from a previous attempt.
    let status = Command::new("schtasks")
        .args([
            "/Create",
            "/TN",
            SWAP_TASK_NAME,
            "/TR",
            &format!("cmd /c {}", helper_cmd),
            "/SC",
            "ONCE",
            "/SD",
            &start_date,
            "/ST",
            &start_time,
            "/RL",
            "HIGHEST",
            "/F",
        ])
        .status()
        .context("schtasks /Create failed to launch")?;
    if !status.success() {
        bail!("schtasks /Create returned non-zero exit code");
    }

    Ok(())
}

/// Rolls back from a probation failure: rename current to `.failed`, restore
/// `.prev` over current. Returns Ok(true) if rollback happened, Ok(false) if
/// there was no `.prev` to roll back to.
pub fn rollback(bin_path: &Path) -> Result<bool> {
    let prev = prev_path(bin_path);
    if !prev.exists() {
        return Ok(false);
    }
    let failed = failed_path(bin_path);
    let _ = fs::remove_file(&failed);
    if bin_path.exists() {
        replace_atomically(bin_path, &failed)
            .with_context(|| "move failed binary to .failed")?;
    }
    replace_atomically(&prev, bin_path).with_context(|| "restore .prev")?;
    Ok(true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    fn write(path: &Path, content: &[u8]) {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).unwrap();
        }
        fs::write(path, content).unwrap();
    }

    #[test]
    fn prev_path_appends_dot_prev() {
        assert_eq!(
            prev_path(Path::new("/x/y/open-attest")),
            PathBuf::from("/x/y/open-attest.prev")
        );
        assert_eq!(
            prev_path(Path::new("/x/y/open-attest.exe")),
            PathBuf::from("/x/y/open-attest.exe.prev")
        );
    }

    #[test]
    fn replace_atomically_renames_within_same_fs() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        write(&src, b"new content");
        write(&dst, b"old content");
        replace_atomically(&src, &dst).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"new content");
        assert!(!src.exists());
    }

    #[test]
    fn replace_atomically_creates_when_dst_missing() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("src");
        let dst = dir.path().join("dst");
        write(&src, b"new content");
        replace_atomically(&src, &dst).unwrap();
        assert_eq!(fs::read(&dst).unwrap(), b"new content");
    }

    #[test]
    fn replace_atomically_fails_when_src_missing() {
        let dir = tempdir().unwrap();
        let src = dir.path().join("missing");
        let dst = dir.path().join("dst");
        write(&dst, b"old");
        assert!(replace_atomically(&src, &dst).is_err());
    }

    #[cfg(not(windows))]
    #[test]
    fn install_swap_creates_prev_and_replaces_current() {
        let dir = tempdir().unwrap();
        let bin = dir.path().join("open-attest");
        let new_bin = dir.path().join("updates").join("0.6.0.partial");
        write(&bin, b"v0.5.0");
        write(&new_bin, b"v0.6.0");

        install_swap(&new_bin, &bin).unwrap();
        assert_eq!(fs::read(&bin).unwrap(), b"v0.6.0");
        assert_eq!(fs::read(&prev_path(&bin)).unwrap(), b"v0.5.0");
        assert!(!new_bin.exists());
    }

    #[cfg(not(windows))]
    #[test]
    fn install_swap_overwrites_stale_prev() {
        let dir = tempdir().unwrap();
        let bin = dir.path().join("open-attest");
        let new_bin = dir.path().join("0.6.0.partial");
        write(&bin, b"v0.5.0");
        write(&new_bin, b"v0.6.0");
        // Stale .prev from a previous aborted swap.
        write(&prev_path(&bin), b"stale ancient version");

        install_swap(&new_bin, &bin).unwrap();
        assert_eq!(fs::read(&prev_path(&bin)).unwrap(), b"v0.5.0");
    }

    #[cfg(not(windows))]
    #[test]
    fn rollback_restores_prev_over_current() {
        let dir = tempdir().unwrap();
        let bin = dir.path().join("open-attest");
        write(&bin, b"bad v0.6.0");
        write(&prev_path(&bin), b"good v0.5.0");

        let rolled = rollback(&bin).unwrap();
        assert!(rolled);
        assert_eq!(fs::read(&bin).unwrap(), b"good v0.5.0");
        assert_eq!(fs::read(&failed_path(&bin)).unwrap(), b"bad v0.6.0");
        assert!(!prev_path(&bin).exists());
    }

    #[cfg(not(windows))]
    #[test]
    fn rollback_returns_false_without_prev() {
        let dir = tempdir().unwrap();
        let bin = dir.path().join("open-attest");
        write(&bin, b"v0.6.0");
        let rolled = rollback(&bin).unwrap();
        assert!(!rolled);
        assert_eq!(fs::read(&bin).unwrap(), b"v0.6.0");
    }

    #[cfg(unix)]
    #[test]
    fn make_executable_sets_0755() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempdir().unwrap();
        let p = dir.path().join("f");
        write(&p, b"x");
        make_executable(&p).unwrap();
        let mode = fs::metadata(&p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o755);
    }
}
