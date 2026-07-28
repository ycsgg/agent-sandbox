//! Safe, bounded project traversal for copy-mode sandboxes.

#![forbid(unsafe_code)]

use std::{
    fs,
    path::{Component, Path, PathBuf},
};

use ignore::WalkBuilder;

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

const DEFAULT_IGNORED_DIRECTORIES: &[&str] = &[
    ".git",
    "node_modules",
    "target",
    "dist",
    "build",
    "coverage",
];

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Project-transfer result type.
pub type Result<T> = std::result::Result<T, TransferError>;

/// Safe-walker error.
#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    /// A filesystem operation failed.
    #[error("cannot inspect {path}: {source}")]
    Io {
        /// Path being inspected.
        path: PathBuf,
        /// Underlying error.
        source: std::io::Error,
    },

    /// A special filesystem object cannot be copied.
    #[error("refusing unsupported filesystem object {0}")]
    SpecialFile(PathBuf),

    /// A symlink is unsafe or points outside the project.
    #[error("refusing symlink {path}: {reason}")]
    UnsafeSymlink {
        /// Link path.
        path: PathBuf,
        /// Rejection reason.
        reason: String,
    },

    /// A configured transfer cap was exceeded.
    #[error("{kind} limit exceeded at {path}: {actual} > {limit}")]
    Limit {
        /// Limit category.
        kind: &'static str,
        /// Entry that crossed the limit.
        path: PathBuf,
        /// Observed amount.
        actual: u64,
        /// Configured limit.
        limit: u64,
    },

    /// An ignore-aware directory walk failed.
    #[error("cannot walk project: {0}")]
    Walk(#[from] ignore::Error),
}

/// Safe-walker resource limits.
#[derive(Debug, Clone, Copy)]
pub struct TransferLimits {
    /// Maximum number of entries.
    pub max_entries: u64,
    /// Maximum bytes in one file.
    pub max_file_size: u64,
    /// Maximum total regular-file bytes.
    pub max_total_size: u64,
}

/// One validated transfer entry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Entry {
    /// Directory relative to the project root.
    Directory {
        /// Relative path.
        path: PathBuf,
        /// Unix permission bits.
        mode: u32,
    },
    /// Regular file.
    File {
        /// Relative path.
        path: PathBuf,
        /// Host source path.
        source: PathBuf,
        /// File size.
        size: u64,
        /// Unix permission bits.
        mode: u32,
    },
    /// Relative symlink whose lexical and resolved targets stay within the project.
    Symlink {
        /// Relative link path.
        path: PathBuf,
        /// Original relative link target.
        target: PathBuf,
    },
}

/// Fully validated copy plan.
#[derive(Debug, Clone)]
pub struct TransferPlan {
    /// Canonical project root.
    pub root: PathBuf,
    /// Deterministically ordered entries.
    pub entries: Vec<Entry>,
    /// Total regular-file bytes.
    pub total_size: u64,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Build a safe copy plan with the default high-cost directory ignores.
pub fn plan(project: impl AsRef<Path>, limits: TransferLimits) -> Result<TransferPlan> {
    plan_with_ignores(project, limits, DEFAULT_IGNORED_DIRECTORIES)
}

/// Build a safe copy plan using explicit ignored directory basenames.
pub fn plan_with_ignores(
    project: impl AsRef<Path>,
    limits: TransferLimits,
    ignored_directories: &[&str],
) -> Result<TransferPlan> {
    let requested = project.as_ref();
    let root = requested
        .canonicalize()
        .map_err(|source| TransferError::Io {
            path: requested.to_path_buf(),
            source,
        })?;
    let mut entries = Vec::new();
    let mut total_size = 0_u64;
    let ignored_directories = ignored_directories
        .iter()
        .map(|name| (*name).to_owned())
        .collect::<Vec<_>>();
    let filter_root = root.clone();
    let mut walker = WalkBuilder::new(&root);
    walker
        .hidden(false)
        .parents(false)
        .ignore(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(true)
        .require_git(false)
        .follow_links(false)
        .same_file_system(true)
        .add_custom_ignore_filename(".agent-sandbox-ignore")
        .filter_entry(move |entry| {
            entry.path() == filter_root
                || !entry.file_type().is_some_and(|kind| kind.is_dir())
                || !entry
                    .file_name()
                    .to_str()
                    .is_some_and(|name| ignored_directories.iter().any(|ignored| ignored == name))
        });

    for walked in walker.build() {
        let walked = walked?;
        let host_path = walked.into_path();
        if host_path == root {
            continue;
        }
        let relative = host_path
            .strip_prefix(&root)
            .expect("walked child remains below root")
            .to_path_buf();
        let metadata = fs::symlink_metadata(&host_path).map_err(|source| TransferError::Io {
            path: host_path.clone(),
            source,
        })?;
        let file_type = metadata.file_type();
        let next_count = entries.len() as u64 + 1;
        if next_count > limits.max_entries {
            return Err(TransferError::Limit {
                kind: "entry count",
                path: relative,
                actual: next_count,
                limit: limits.max_entries,
            });
        }

        if file_type.is_dir() {
            entries.push(Entry::Directory {
                path: relative,
                mode: unix_mode(&metadata),
            });
        } else if file_type.is_file() {
            if metadata.len() > limits.max_file_size {
                return Err(TransferError::Limit {
                    kind: "single file size",
                    path: relative,
                    actual: metadata.len(),
                    limit: limits.max_file_size,
                });
            }
            total_size =
                total_size
                    .checked_add(metadata.len())
                    .ok_or_else(|| TransferError::Limit {
                        kind: "total size",
                        path: relative.clone(),
                        actual: u64::MAX,
                        limit: limits.max_total_size,
                    })?;
            if total_size > limits.max_total_size {
                return Err(TransferError::Limit {
                    kind: "total size",
                    path: relative,
                    actual: total_size,
                    limit: limits.max_total_size,
                });
            }
            entries.push(Entry::File {
                path: relative,
                source: host_path,
                size: metadata.len(),
                mode: unix_mode(&metadata),
            });
        } else if file_type.is_symlink() {
            let target = fs::read_link(&host_path).map_err(|source| TransferError::Io {
                path: host_path.clone(),
                source,
            })?;
            validate_symlink(&root, &host_path, &target)?;
            entries.push(Entry::Symlink {
                path: relative,
                target,
            });
        } else {
            return Err(TransferError::SpecialFile(relative));
        }
    }

    entries.sort_by(|left, right| entry_path(left).cmp(entry_path(right)));
    Ok(TransferPlan {
        root,
        entries,
        total_size,
    })
}

fn entry_path(entry: &Entry) -> &Path {
    match entry {
        Entry::Directory { path, .. } | Entry::File { path, .. } | Entry::Symlink { path, .. } => {
            path
        }
    }
}

fn validate_symlink(root: &Path, link: &Path, target: &Path) -> Result<()> {
    if target.is_absolute() {
        return Err(TransferError::UnsafeSymlink {
            path: link.to_path_buf(),
            reason: "absolute targets are not portable to the guest".into(),
        });
    }
    let parent = link.parent().expect("project child has a parent");
    let lexical = normalize(parent.join(target));
    if !lexical.starts_with(root) {
        return Err(TransferError::UnsafeSymlink {
            path: link.to_path_buf(),
            reason: format!("target {} escapes the project root", target.display()),
        });
    }
    if lexical.exists() {
        let resolved = lexical.canonicalize().map_err(|source| TransferError::Io {
            path: lexical.clone(),
            source,
        })?;
        if !resolved.starts_with(root) {
            return Err(TransferError::UnsafeSymlink {
                path: link.to_path_buf(),
                reason: format!(
                    "resolved target {} escapes the project root",
                    resolved.display()
                ),
            });
        }
    }
    Ok(())
}

fn normalize(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::ParentDir => {
                normalized.pop();
            }
            Component::CurDir => {}
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

#[cfg(unix)]
fn unix_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn unix_mode(metadata: &fs::Metadata) -> u32 {
    if metadata.permissions().readonly() {
        0o444
    } else {
        0o644
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    fn limits() -> TransferLimits {
        TransferLimits {
            max_entries: 100,
            max_file_size: 1024,
            max_total_size: 4096,
        }
    }

    #[test]
    fn ignores_default_build_directories() {
        let root = tempdir().unwrap();
        fs::create_dir(root.path().join(".git")).unwrap();
        fs::write(root.path().join(".git/config"), "secret").unwrap();
        fs::write(root.path().join("Cargo.toml"), "[package]").unwrap();

        let plan = plan(root.path(), limits()).unwrap();
        assert_eq!(plan.entries.len(), 1);
    }

    #[test]
    fn respects_git_and_agent_sandbox_ignore_files() {
        let root = tempdir().unwrap();
        for directory in ["microsandbox", "generated"] {
            fs::create_dir(root.path().join(directory)).unwrap();
            fs::write(root.path().join(directory).join("large.bin"), [0_u8; 16]).unwrap();
        }
        fs::write(root.path().join(".gitignore"), "/microsandbox/\n").unwrap();
        fs::write(root.path().join(".agent-sandbox-ignore"), "/generated/\n").unwrap();
        fs::write(root.path().join("source.rs"), "fn main() {}\n").unwrap();

        let plan = plan(root.path(), limits()).unwrap();
        assert!(
            plan.entries
                .iter()
                .all(|entry| !entry_path(entry).starts_with("microsandbox"))
        );
        assert!(
            plan.entries
                .iter()
                .all(|entry| !entry_path(entry).starts_with("generated"))
        );
        assert!(
            plan.entries
                .iter()
                .any(|entry| entry_path(entry) == Path::new("source.rs"))
        );
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape() {
        use std::os::unix::fs::symlink;

        let root = tempdir().unwrap();
        symlink("../../etc/passwd", root.path().join("escape")).unwrap();
        assert!(matches!(
            plan(root.path(), limits()),
            Err(TransferError::UnsafeSymlink { .. })
        ));
    }

    #[test]
    fn enforces_total_size() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("large"), vec![0_u8; 10]).unwrap();
        let mut limits = limits();
        limits.max_total_size = 5;
        assert!(matches!(
            plan(root.path(), limits),
            Err(TransferError::Limit {
                kind: "total size",
                ..
            })
        ));
    }
}
