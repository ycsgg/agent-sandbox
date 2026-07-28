//! Bounded cache inspection helpers.

#![forbid(unsafe_code)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Cache inspection error.
#[derive(Debug, thiserror::Error)]
#[error("cannot inspect cache path {path}: {source}")]
pub struct CacheError {
    /// Path being inspected.
    pub path: PathBuf,
    /// Filesystem error.
    pub source: std::io::Error,
}

/// Cache disk usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CacheStatus {
    /// Number of regular files.
    pub files: u64,
    /// Total regular-file bytes.
    pub bytes: u64,
}

/// Cache object family understood by wrapper pruning.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CacheKind {
    /// OCI image reference.
    Image,
    /// Named environment snapshot.
    Environment,
}

/// One cache object and its LRU metadata.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CacheEntry {
    /// Object family.
    pub kind: CacheKind,
    /// Image reference or environment name.
    pub key: String,
    /// Best-effort logical bytes.
    pub size_bytes: u64,
    /// Most recent known successful use.
    pub last_used_at: DateTime<Utc>,
    /// Whether policy excludes this entry from deletion.
    pub protected: bool,
}

/// Deterministic prune selection before any destructive operation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrunePlan {
    /// Logical bytes before pruning.
    pub before_bytes: u64,
    /// Configured logical-byte target.
    pub maximum_bytes: u64,
    /// Entries selected in deletion order.
    pub selected: Vec<CacheEntry>,
    /// Logical bytes expected after selected deletions.
    pub projected_bytes: u64,
    /// Whether deletable entries can satisfy the target.
    pub target_met: bool,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Recursively measure regular files without following symlinks.
pub fn status(root: impl AsRef<Path>) -> Result<CacheStatus, CacheError> {
    let root = root.as_ref();
    if !root.exists() {
        return Ok(CacheStatus { files: 0, bytes: 0 });
    }
    let mut pending = vec![root.to_path_buf()];
    let mut result = CacheStatus { files: 0, bytes: 0 };
    while let Some(directory) = pending.pop() {
        let entries = fs::read_dir(&directory).map_err(|source| CacheError {
            path: directory.clone(),
            source,
        })?;
        for entry in entries {
            let entry = entry.map_err(|source| CacheError {
                path: directory.clone(),
                source,
            })?;
            let path = entry.path();
            let metadata = fs::symlink_metadata(&path).map_err(|source| CacheError {
                path: path.clone(),
                source,
            })?;
            if metadata.is_dir() {
                pending.push(path);
            } else if metadata.is_file() {
                result.files = result.files.saturating_add(1);
                result.bytes = result.bytes.saturating_add(metadata.len());
            }
        }
    }
    Ok(result)
}

/// Select expired entries and then least-recently-used entries until under quota.
///
/// Protected entries always contribute to total size but are never selected.
pub fn plan_prune(
    entries: &[CacheEntry],
    maximum_bytes: u64,
    older_than: Option<DateTime<Utc>>,
) -> PrunePlan {
    let before_bytes = entries
        .iter()
        .fold(0_u64, |total, entry| total.saturating_add(entry.size_bytes));
    let mut candidates = entries
        .iter()
        .filter(|entry| !entry.protected)
        .cloned()
        .collect::<Vec<_>>();
    candidates.sort_by(|left, right| {
        left.last_used_at
            .cmp(&right.last_used_at)
            .then_with(|| cache_kind_order(left.kind).cmp(&cache_kind_order(right.kind)))
            .then_with(|| left.key.cmp(&right.key))
    });

    let mut projected_bytes = before_bytes;
    let mut selected = Vec::new();
    for entry in candidates {
        let expired = older_than.is_some_and(|cutoff| entry.last_used_at <= cutoff);
        if expired || projected_bytes > maximum_bytes {
            projected_bytes = projected_bytes.saturating_sub(entry.size_bytes);
            selected.push(entry);
        }
    }
    PrunePlan {
        before_bytes,
        maximum_bytes,
        selected,
        projected_bytes,
        target_met: projected_bytes <= maximum_bytes,
    }
}

fn cache_kind_order(kind: CacheKind) -> u8 {
    match kind {
        CacheKind::Environment => 0,
        CacheKind::Image => 1,
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use chrono::Duration;

    use super::*;

    #[test]
    fn chooses_lru_entries_and_preserves_protected_entries() {
        let now = Utc::now();
        let entries = vec![
            entry("old", 40, now - Duration::days(3), false),
            entry("protected", 80, now - Duration::days(5), true),
            entry("new", 30, now - Duration::hours(1), false),
        ];
        let plan = plan_prune(&entries, 100, None);
        assert_eq!(
            plan.selected
                .iter()
                .map(|entry| entry.key.as_str())
                .collect::<Vec<_>>(),
            vec!["old", "new"]
        );
        assert_eq!(plan.projected_bytes, 80);
        assert!(plan.target_met);
    }

    #[test]
    fn expiration_applies_even_when_already_below_quota() {
        let now = Utc::now();
        let entries = vec![entry("stale", 10, now - Duration::days(30), false)];
        let plan = plan_prune(&entries, 100, Some(now - Duration::days(7)));
        assert_eq!(plan.selected.len(), 1);
        assert_eq!(plan.projected_bytes, 0);
    }

    #[test]
    fn reports_when_protected_bytes_prevent_quota() {
        let now = Utc::now();
        let entries = vec![entry("protected", 100, now, true)];
        let plan = plan_prune(&entries, 50, None);
        assert!(!plan.target_met);
        assert!(plan.selected.is_empty());
    }

    fn entry(
        key: &str,
        size_bytes: u64,
        last_used_at: DateTime<Utc>,
        protected: bool,
    ) -> CacheEntry {
        CacheEntry {
            kind: CacheKind::Image,
            key: key.into(),
            size_bytes,
            last_used_at,
            protected,
        }
    }
}
