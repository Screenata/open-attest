mod linux;
mod macos;
mod windows;

use open_attest_types::CheckResult;

/// Hard cap on inventory list lengths. Beyond this we append a sentinel
/// string so the operator can see truncation happened.
pub const MAX_INVENTORY_ENTRIES: usize = 1000;

/// Apply MAX_INVENTORY_ENTRIES to an already sorted+deduped list. Returns the
/// list unchanged if under the cap; otherwise truncates and appends a
/// "…and N more" sentinel.
pub fn truncate_inventory(mut items: Vec<String>) -> Vec<String> {
    if items.len() > MAX_INVENTORY_ENTRIES {
        let extra = items.len() - MAX_INVENTORY_ENTRIES;
        items.truncate(MAX_INVENTORY_ENTRIES);
        items.push(format!("…and {} more", extra));
    }
    items
}

/// Collect cheap endpoint posture checks suitable for every snapshot tick.
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

/// Collect heavy inventory checks (installed apps, etc). Slow — call on a
/// daily cadence, not every snapshot.
pub fn collect_inventory() -> Vec<CheckResult> {
    #[cfg(target_os = "macos")]
    {
        macos::collect_inventory()
    }
    #[cfg(target_os = "windows")]
    {
        windows::collect_inventory()
    }
    #[cfg(target_os = "linux")]
    {
        linux::collect_inventory()
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncate_under_cap_unchanged() {
        let v: Vec<String> = (0..5).map(|i| format!("item{}", i)).collect();
        let out = truncate_inventory(v.clone());
        assert_eq!(out, v);
    }

    #[test]
    fn truncate_at_cap_unchanged() {
        let v: Vec<String> = (0..MAX_INVENTORY_ENTRIES).map(|i| format!("item{}", i)).collect();
        let out = truncate_inventory(v.clone());
        assert_eq!(out.len(), MAX_INVENTORY_ENTRIES);
        assert!(!out.last().unwrap().starts_with("…and"));
    }

    #[test]
    fn truncate_over_cap_appends_sentinel() {
        let v: Vec<String> = (0..MAX_INVENTORY_ENTRIES + 7).map(|i| format!("item{}", i)).collect();
        let out = truncate_inventory(v);
        assert_eq!(out.len(), MAX_INVENTORY_ENTRIES + 1);
        assert_eq!(out.last().unwrap(), "…and 7 more");
    }
}
