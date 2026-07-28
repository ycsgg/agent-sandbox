//! Environment selection and OCI fast-path resolution.

#![forbid(unsafe_code)]

use std::path::Path;

use agent_sandbox_detector::{Detection, detect};
use agent_sandbox_runtime::RootSource;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Environment resolution error.
#[derive(Debug, thiserror::Error)]
pub enum EnvironmentError {
    /// Static project detection failed.
    #[error(transparent)]
    Detect(#[from] agent_sandbox_detector::DetectError),

    /// An environment expression is not supported.
    #[error("{0}")]
    Unsupported(String),
}

/// Root selection inputs in documented precedence order.
#[derive(Debug, Clone, Default)]
pub struct EnvironmentRequest {
    /// Explicit OCI image.
    pub image: Option<String>,
    /// Explicit Microsandbox snapshot.
    pub snapshot: Option<String>,
    /// `auto`, a language expression, or a named environment.
    pub environment: Option<String>,
}

/// Resolved root source plus optional detector evidence.
#[derive(Debug, Clone)]
pub struct ResolvedEnvironment {
    /// Runtime root source.
    pub root: RootSource,
    /// Detection result used for `auto`.
    pub detection: Option<Detection>,
    /// Human-readable resolution source.
    pub source: String,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

/// Resolve an explicit image, snapshot, or built-in language environment.
pub fn resolve(
    request: &EnvironmentRequest,
    project: &Path,
) -> Result<ResolvedEnvironment, EnvironmentError> {
    if let Some(image) = nonempty(request.image.as_deref()) {
        return Ok(ResolvedEnvironment {
            root: RootSource::Image(image.to_owned()),
            detection: None,
            source: "--image".into(),
        });
    }
    if let Some(snapshot) = nonempty(request.snapshot.as_deref()) {
        return Ok(ResolvedEnvironment {
            root: RootSource::Snapshot(snapshot.to_owned()),
            detection: None,
            source: "--snapshot".into(),
        });
    }

    let expression = request.environment.as_deref().unwrap_or("auto");
    if expression == "auto" {
        let detection = detect(project)?;
        let suggested = detection.suggested_environment.as_deref().ok_or_else(|| {
            if detection.languages.is_empty() {
                EnvironmentError::Unsupported(
                    "could not detect Go, Rust, or Node.js; pass --image or --env LANG@VERSION"
                        .into(),
                )
            } else {
                EnvironmentError::Unsupported(format!(
                    "project declares multiple runtimes ({}); pass a combined --image",
                    detection
                        .languages
                        .iter()
                        .map(|language| language.name.as_str())
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
            }
        })?;
        return Ok(ResolvedEnvironment {
            root: RootSource::Image(resolve_language(suggested)?),
            detection: Some(detection),
            source: "--env auto".into(),
        });
    }

    Ok(ResolvedEnvironment {
        root: RootSource::Image(resolve_language(expression)?),
        detection: None,
        source: "--env".into(),
    })
}

/// Map a built-in `LANG@VERSION` expression to an official OCI image.
pub fn resolve_language(expression: &str) -> Result<String, EnvironmentError> {
    let (language, version) = expression.split_once('@').ok_or_else(|| {
        EnvironmentError::Unsupported(format!(
            "unknown named environment {expression:?}; expected go@VERSION, rust@VERSION, or node@VERSION"
        ))
    })?;
    let version = if version.is_empty() {
        "latest"
    } else {
        version
    };
    if version
        .chars()
        .any(|character| !(character.is_ascii_alphanumeric() || ".-_".contains(character)))
    {
        return Err(EnvironmentError::Unsupported(format!(
            "invalid toolchain version {version:?}"
        )));
    }
    let image = match language {
        "go" | "golang" => image_tag("golang", version),
        "rust" => image_tag("rust", version),
        "node" | "nodejs" | "typescript" | "ts" => image_tag("node", version),
        other => {
            return Err(EnvironmentError::Unsupported(format!(
                "unsupported built-in environment {other:?}; pass --image for arbitrary OCI images"
            )));
        }
    };
    Ok(image)
}

fn image_tag(repository: &str, version: &str) -> String {
    if version == "latest" {
        format!("{repository}:latest")
    } else {
        format!("{repository}:{version}-bookworm")
    }
}

fn nonempty(value: Option<&str>) -> Option<&str> {
    value.filter(|value| !value.trim().is_empty())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_official_fast_path_images() {
        assert_eq!(resolve_language("go@1.24").unwrap(), "golang:1.24-bookworm");
        assert_eq!(resolve_language("node@22").unwrap(), "node:22-bookworm");
        assert_eq!(resolve_language("rust@1.88").unwrap(), "rust:1.88-bookworm");
    }

    #[test]
    fn rejects_image_tag_injection() {
        assert!(resolve_language("node@22/../../bad").is_err());
    }
}
