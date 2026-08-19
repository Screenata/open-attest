//! Binary swap and rollback operations.
//!
//! Atomic same-filesystem rename, with copy+rename fallback across
//! filesystems (EXDEV). The same path works on Windows: a running .exe is
//! locked against writes and deletes, but *renaming* it is allowed, so the
//! current binary can always be moved aside to make room for the new one.

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
/// Two `replace_atomically` calls. On Unix the running process keeps
/// executing the old inode while the new file takes its place. On Windows
/// the running .exe is file-locked against writes and deletes, but a rename
/// within the same volume succeeds even while the image is mapped — so
/// moving it to `.prev` frees the managed path for the new binary. Either
/// way the new code takes effect on the next daemon start; on Windows the
/// caller is responsible for scheduling that restart (see
/// `winsvc::schedule_restart`), since the ONLOGON task has no supervisor.
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

    let prev = prev_path(bin_path);
    // Remove any stale .prev from a prior aborted swap.
    let _ = fs::remove_file(&prev);

    replace_atomically(bin_path, &prev).with_context(|| "move current binary to .prev")?;
    replace_atomically(new_binary, bin_path).with_context(|| "move new binary into place")?;
    make_executable(bin_path)?;
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
