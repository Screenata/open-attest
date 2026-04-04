mod linux;
mod macos;
mod windows;

use open_attest_types::CheckResult;

/// Collect all endpoint posture checks for the current platform.
pub fn collect_all() -> Vec<CheckResult> {
    #[cfg(target_os = "macos")]
    {
        macos::collect_all()
    }
    #[cfg(target_os = "windows")]
    {
        windows::collect_all()
    }
    #[cfg(target_os = "linux")]
    {
        linux::collect_all()
    }
    #[cfg(not(any(target_os = "macos", target_os = "windows", target_os = "linux")))]
    {
        vec![]
    }
}

// Re-export parsers so tests can access them regardless of platform.
pub use linux::parsers as linux_parsers;
pub use macos::parsers as macos_parsers;
pub use windows::parsers as windows_parsers;
