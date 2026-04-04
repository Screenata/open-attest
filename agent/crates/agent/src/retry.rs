use anyhow::Result;
use std::fs;
use std::path::{Path, PathBuf};

pub struct RetryQueue {
    dir: PathBuf,
}

impl RetryQueue {
    pub fn new(dir: &Path) -> Result<Self> {
        fs::create_dir_all(dir)?;
        Ok(Self {
            dir: dir.to_path_buf(),
        })
    }

    /// Save a failed attestation payload for later retry
    pub fn enqueue(&self, attestation_json: &str) -> Result<()> {
        let filename = format!("{}.json", uuid::Uuid::now_v7());
        let path = self.dir.join(filename);
        fs::write(&path, attestation_json)?;
        Ok(())
    }

    /// Get all pending retry items, oldest first
    pub fn pending(&self) -> Result<Vec<(PathBuf, String)>> {
        let mut entries: Vec<_> = fs::read_dir(&self.dir)?
            .filter_map(|e| e.ok())
            .filter(|e| e.path().extension().map_or(false, |ext| ext == "json"))
            .collect();

        // Sort by filename (UUID v7 is time-ordered)
        entries.sort_by_key(|e| e.file_name());

        let mut results = vec![];
        for entry in entries {
            let content = fs::read_to_string(entry.path())?;
            results.push((entry.path(), content));
        }
        Ok(results)
    }

    /// Remove a successfully delivered item
    pub fn remove(&self, path: &Path) -> Result<()> {
        if path.exists() {
            fs::remove_file(path)?;
        }
        Ok(())
    }

    /// Count pending items
    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        fs::read_dir(&self.dir)
            .map(|entries| {
                entries
                    .filter_map(|e| e.ok())
                    .filter(|e| e.path().extension().map_or(false, |ext| ext == "json"))
                    .count()
            })
            .unwrap_or(0)
    }

    /// Evict items older than max_age_secs (based on file modification time)
    pub fn evict_old(&self, max_age_secs: u64) -> Result<usize> {
        let now = std::time::SystemTime::now();
        let mut evicted = 0;

        for entry in fs::read_dir(&self.dir)?.filter_map(|e| e.ok()) {
            if let Ok(metadata) = entry.metadata() {
                if let Ok(modified) = metadata.modified() {
                    if let Ok(age) = now.duration_since(modified) {
                        if age.as_secs() > max_age_secs {
                            let _ = fs::remove_file(entry.path());
                            evicted += 1;
                        }
                    }
                }
            }
        }
        Ok(evicted)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn enqueue_and_drain() {
        let dir = TempDir::new().unwrap();
        let queue = RetryQueue::new(dir.path()).unwrap();

        queue.enqueue(r#"{"test": 1}"#).unwrap();
        queue.enqueue(r#"{"test": 2}"#).unwrap();

        assert_eq!(queue.len(), 2);

        let items = queue.pending().unwrap();
        assert_eq!(items.len(), 2);
        assert!(items[0].1.contains("test"));

        queue.remove(&items[0].0).unwrap();
        assert_eq!(queue.len(), 1);
    }

    #[test]
    fn empty_queue() {
        let dir = TempDir::new().unwrap();
        let queue = RetryQueue::new(dir.path()).unwrap();
        assert_eq!(queue.len(), 0);
        assert!(queue.pending().unwrap().is_empty());
    }
}
