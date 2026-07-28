//! Bounded cache inspection helpers.

#![forbid(unsafe_code)]

use std::{
    fs,
    path::{Path, PathBuf},
};

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
