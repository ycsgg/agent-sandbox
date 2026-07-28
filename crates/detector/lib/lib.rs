//! Static project environment detection.

#![forbid(unsafe_code)]

use std::{
    fs,
    path::{Path, PathBuf},
};

use serde::{Deserialize, Serialize};

//--------------------------------------------------------------------------------------------------
// Constants
//--------------------------------------------------------------------------------------------------

/// Maximum declaration file size read by a detector.
pub const MAX_DECLARATION_SIZE: u64 = 1024 * 1024;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Detector result type.
pub type Result<T> = std::result::Result<T, DetectError>;

/// A project detection error.
#[derive(Debug, thiserror::Error)]
pub enum DetectError {
    /// Project path could not be resolved.
    #[error("cannot resolve project path {path}: {source}")]
    Project {
        /// Requested path.
        path: PathBuf,
        /// Underlying filesystem error.
        source: std::io::Error,
    },
}

/// A detected language and optional version.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Language {
    /// Canonical language/runtime name.
    pub name: String,
    /// Version extracted from a declaration.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
    /// Declaration filename.
    pub source: String,
}

/// A detected package manager.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackageManager {
    /// Package manager name.
    pub name: String,
    /// Declared version if present.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,
}

/// Complete static project detection.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Detection {
    /// Languages in deterministic priority order.
    pub languages: Vec<Language>,
    /// Package managers found in the project root.
    pub package_managers: Vec<PackageManager>,
    /// Fast-path environment that `--env auto` will select.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub suggested_environment: Option<String>,
    /// Non-fatal parse and size warnings.
    pub warnings: Vec<String>,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Detect Go, Rust, and Node.js/TypeScript declarations without executing project code.
pub fn detect(project: impl AsRef<Path>) -> Result<Detection> {
    let requested = project.as_ref();
    let project = requested
        .canonicalize()
        .map_err(|source| DetectError::Project {
            path: requested.to_path_buf(),
            source,
        })?;

    let mut languages = Vec::new();
    let mut package_managers = Vec::new();
    let mut warnings = Vec::new();

    detect_go(
        &project,
        &mut languages,
        &mut package_managers,
        &mut warnings,
    );
    detect_rust(
        &project,
        &mut languages,
        &mut package_managers,
        &mut warnings,
    );
    detect_node(
        &project,
        &mut languages,
        &mut package_managers,
        &mut warnings,
    );

    let suggested_environment = suggest(&languages);
    Ok(Detection {
        languages,
        package_managers,
        suggested_environment,
        warnings,
    })
}

fn detect_go(
    project: &Path,
    languages: &mut Vec<Language>,
    managers: &mut Vec<PackageManager>,
    warnings: &mut Vec<String>,
) {
    let source = if project.join("go.work").is_file() {
        "go.work"
    } else if project.join("go.mod").is_file() {
        "go.mod"
    } else {
        return;
    };
    let version = read_limited(&project.join(source), warnings).and_then(|text| {
        text.lines()
            .map(str::trim)
            .find_map(|line| line.strip_prefix("go ").map(clean_version))
    });
    languages.push(Language {
        name: "go".into(),
        version,
        source: source.into(),
    });
    managers.push(PackageManager {
        name: "go".into(),
        version: None,
    });
}

fn detect_rust(
    project: &Path,
    languages: &mut Vec<Language>,
    managers: &mut Vec<PackageManager>,
    warnings: &mut Vec<String>,
) {
    let (source, version) = if project.join("rust-toolchain.toml").is_file() {
        let source = "rust-toolchain.toml";
        let version = read_limited(&project.join(source), warnings).and_then(|text| {
            match toml::from_str::<toml::Value>(&text) {
                Ok(value) => value
                    .get("toolchain")
                    .and_then(|toolchain| toolchain.get("channel"))
                    .and_then(toml::Value::as_str)
                    .map(clean_version),
                Err(error) => {
                    warnings.push(format!("{source}: {error}"));
                    None
                }
            }
        });
        (source, version)
    } else if project.join("rust-toolchain").is_file() {
        let source = "rust-toolchain";
        let version = read_limited(&project.join(source), warnings).and_then(|text| {
            text.lines()
                .map(str::trim)
                .find(|line| !line.is_empty())
                .map(clean_version)
        });
        (source, version)
    } else if project.join("Cargo.toml").is_file() {
        let source = "Cargo.toml";
        let version = read_limited(&project.join(source), warnings).and_then(|text| {
            match toml::from_str::<toml::Value>(&text) {
                Ok(value) => value
                    .get("package")
                    .and_then(|package| package.get("rust-version"))
                    .and_then(toml::Value::as_str)
                    .map(clean_version),
                Err(error) => {
                    warnings.push(format!("{source}: {error}"));
                    None
                }
            }
        });
        (source, version)
    } else {
        return;
    };

    languages.push(Language {
        name: "rust".into(),
        version,
        source: source.into(),
    });
    managers.push(PackageManager {
        name: "cargo".into(),
        version: None,
    });
}

fn detect_node(
    project: &Path,
    languages: &mut Vec<Language>,
    managers: &mut Vec<PackageManager>,
    warnings: &mut Vec<String>,
) {
    let has_package = project.join("package.json").is_file();
    let has_typescript = project.join("tsconfig.json").is_file()
        || project.join("tsconfig.base.json").is_file()
        || project.join("deno.json").is_file();
    if !has_package && !has_typescript && !project.join(".nvmrc").is_file() {
        return;
    }

    let mut package_manager = None;
    let (source, version) = if project.join(".nvmrc").is_file() {
        let source = ".nvmrc";
        let version = first_nonempty(project, source, warnings).map(|value| clean_version(&value));
        (source, version)
    } else if project.join(".node-version").is_file() {
        let source = ".node-version";
        let version = first_nonempty(project, source, warnings).map(|value| clean_version(&value));
        (source, version)
    } else if has_package {
        let source = "package.json";
        let version =
            read_limited(&project.join(source), warnings).and_then(
                |text| match serde_json::from_str::<serde_json::Value>(&text) {
                    Ok(value) => {
                        package_manager = value
                            .get("packageManager")
                            .and_then(serde_json::Value::as_str)
                            .map(parse_package_manager);
                        value
                            .get("engines")
                            .and_then(|engines| engines.get("node"))
                            .and_then(serde_json::Value::as_str)
                            .and_then(extract_semver)
                    }
                    Err(error) => {
                        warnings.push(format!("{source}: {error}"));
                        None
                    }
                },
            );
        (source, version)
    } else {
        ("tsconfig.json", None)
    };

    languages.push(Language {
        name: if has_typescript {
            "typescript".into()
        } else {
            "node".into()
        },
        version,
        source: source.into(),
    });

    if let Some(manager) = package_manager {
        push_manager(managers, manager);
    } else {
        for (file, name) in [
            ("pnpm-lock.yaml", "pnpm"),
            ("yarn.lock", "yarn"),
            ("bun.lock", "bun"),
            ("bun.lockb", "bun"),
            ("package-lock.json", "npm"),
        ] {
            if project.join(file).is_file() {
                push_manager(
                    managers,
                    PackageManager {
                        name: name.into(),
                        version: None,
                    },
                );
                return;
            }
        }
        push_manager(
            managers,
            PackageManager {
                name: "npm".into(),
                version: None,
            },
        );
    }
}

fn read_limited(path: &Path, warnings: &mut Vec<String>) -> Option<String> {
    let metadata = match fs::metadata(path) {
        Ok(metadata) => metadata,
        Err(error) => {
            warnings.push(format!("{}: {error}", path.display()));
            return None;
        }
    };
    if metadata.len() > MAX_DECLARATION_SIZE {
        warnings.push(format!(
            "{} exceeds the {} byte detector limit",
            path.file_name().unwrap_or_default().to_string_lossy(),
            MAX_DECLARATION_SIZE
        ));
        return None;
    }
    match fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(error) => {
            warnings.push(format!("{}: {error}", path.display()));
            None
        }
    }
}

fn first_nonempty(project: &Path, source: &str, warnings: &mut Vec<String>) -> Option<String> {
    read_limited(&project.join(source), warnings).and_then(|text| {
        text.lines()
            .map(str::trim)
            .find(|line| !line.is_empty())
            .map(str::to_owned)
    })
}

fn clean_version(value: &str) -> String {
    value
        .trim()
        .trim_start_matches(|character: char| {
            matches!(character, 'v' | '^' | '~' | '=' | '>' | '<' | ' ')
        })
        .split_whitespace()
        .next()
        .unwrap_or(value)
        .to_owned()
}

fn extract_semver(value: &str) -> Option<String> {
    let start = value.find(|character: char| character.is_ascii_digit())?;
    let tail = &value[start..];
    let end = tail
        .find(|character: char| !(character.is_ascii_digit() || character == '.'))
        .unwrap_or(tail.len());
    let version = tail[..end].trim_end_matches('.');
    (!version.is_empty()).then(|| version.to_owned())
}

fn parse_package_manager(value: &str) -> PackageManager {
    let (name, version) = value
        .split_once('@')
        .map(|(name, version)| (name, Some(version.to_owned())))
        .unwrap_or((value, None));
    PackageManager {
        name: name.to_owned(),
        version,
    }
}

fn push_manager(managers: &mut Vec<PackageManager>, manager: PackageManager) {
    if !managers
        .iter()
        .any(|existing| existing.name == manager.name)
    {
        managers.push(manager);
    }
}

fn suggest(languages: &[Language]) -> Option<String> {
    if languages.len() != 1 {
        return None;
    }
    let language = &languages[0];
    let name = if language.name == "typescript" {
        "node"
    } else {
        &language.name
    };
    Some(match &language.version {
        Some(version) => format!("{name}@{version}"),
        None => format!("{name}@latest"),
    })
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn detects_node_and_package_manager_version() {
        let dir = tempdir().unwrap();
        fs::write(
            dir.path().join("package.json"),
            r#"{"engines":{"node":">=22.1"},"packageManager":"pnpm@10.2.0"}"#,
        )
        .unwrap();
        fs::write(dir.path().join("tsconfig.json"), "{}").unwrap();

        let detection = detect(dir.path()).unwrap();
        assert_eq!(detection.languages[0].name, "typescript");
        assert_eq!(detection.languages[0].version.as_deref(), Some("22.1"));
        assert_eq!(detection.package_managers[0].name, "pnpm");
        assert_eq!(
            detection.suggested_environment.as_deref(),
            Some("node@22.1")
        );
    }

    #[test]
    fn reports_oversized_declarations_without_reading_them() {
        let dir = tempdir().unwrap();
        let file = fs::File::create(dir.path().join("go.mod")).unwrap();
        file.set_len(MAX_DECLARATION_SIZE + 1).unwrap();

        let detection = detect(dir.path()).unwrap();
        assert_eq!(detection.languages[0].name, "go");
        assert_eq!(detection.languages[0].version, None);
        assert_eq!(detection.warnings.len(), 1);
    }
}
