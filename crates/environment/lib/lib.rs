//! Environment selection and OCI fast-path resolution.

#![forbid(unsafe_code)]

use std::path::Path;

use agent_sandbox_detector::{Detection, detect};
use agent_sandbox_runtime::RootSource;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

/// Version of the deterministic environment-build input format.
pub const BUILD_MANIFEST_VERSION: u32 = 1;

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

/// Supported toolchain family.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum ToolchainKind {
    /// Go compiler and tools.
    Go,
    /// Rustup, Cargo, and Rust compiler.
    Rust,
    /// Node.js and npm.
    Node,
}

/// One normalized toolchain build input.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ToolchainSpec {
    /// Toolchain family.
    pub kind: ToolchainKind,
    /// Exact normalized semantic version.
    pub version: String,
}

/// Validated, deterministic managed-environment build.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentBuild {
    /// User-facing environment name.
    pub name: String,
    /// Base OCI image.
    pub base: String,
    /// Content-addressed base manifest digest once the runtime has resolved it.
    pub base_digest: Option<String>,
    /// Canonically ordered toolchains.
    pub toolchains: Vec<ToolchainSpec>,
    /// Microsandbox guest architecture.
    pub arch: String,
    /// SHA-256 digest over all reproducibility inputs.
    pub cache_key: String,
    /// Collision-resistant runtime snapshot name.
    pub snapshot: String,
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
            root: RootSource::Image(normalize_image_reference(image)),
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
    Ok(normalize_image_reference(&image))
}

/// Expand Docker Hub's familiar image syntax to its current registry endpoint.
///
/// OCI clients do not all implement Docker's implicit registry and `library/`
/// rules. In particular, treating a bare name as `index.docker.io` can select
/// the legacy website endpoint instead of the registry API.
pub fn normalize_image_reference(image: &str) -> String {
    const DOCKER_HUB: &str = "registry-1.docker.io";

    let Some((first, remainder)) = image.split_once('/') else {
        return format!("{DOCKER_HUB}/library/{image}");
    };

    if matches!(first, "docker.io" | "index.docker.io" | DOCKER_HUB) {
        return if remainder.contains('/') {
            format!("{DOCKER_HUB}/{remainder}")
        } else {
            format!("{DOCKER_HUB}/library/{remainder}")
        };
    }

    if first == "localhost" || first.contains('.') || first.contains(':') {
        image.into()
    } else {
        format!("{DOCKER_HUB}/{image}")
    }
}

/// Validate and normalize one named environment build request.
pub fn build_request(
    name: &str,
    base: &str,
    toolchains: &[String],
) -> Result<EnvironmentBuild, EnvironmentError> {
    validate_name(name)?;
    let base = normalize_image_reference(base);
    validate_base(&base)?;
    if toolchains.is_empty() {
        return Err(EnvironmentError::Unsupported(
            "at least one --toolchain LANG@VERSION is required".into(),
        ));
    }
    let mut toolchains = toolchains
        .iter()
        .map(|expression| parse_toolchain(expression))
        .collect::<Result<Vec<_>, _>>()?;
    toolchains.sort();
    toolchains.dedup();
    let arch = guest_arch()?;
    Ok(recompute_cache_key(EnvironmentBuild {
        name: name.into(),
        base,
        base_digest: None,
        toolchains,
        arch: arch.into(),
        cache_key: String::new(),
        snapshot: String::new(),
    }))
}

/// Replace a mutable image reference with the runtime-resolved manifest digest.
pub fn pin_base_digest(
    mut build: EnvironmentBuild,
    digest: &str,
) -> Result<EnvironmentBuild, EnvironmentError> {
    let valid = digest
        .strip_prefix("sha256:")
        .is_some_and(|hex| hex.len() == 64 && hex.bytes().all(|byte| byte.is_ascii_hexdigit()));
    if !valid {
        return Err(EnvironmentError::Unsupported(format!(
            "runtime returned an invalid OCI manifest digest {digest:?}"
        )));
    }
    build.base_digest = Some(digest.to_ascii_lowercase());
    Ok(recompute_cache_key(build))
}

/// Render the trusted POSIX guest provisioning script for a validated build.
pub fn provisioning_script(build: &EnvironmentBuild) -> String {
    let mut script = String::from(
        r#"set -eu
export RUSTUP_HOME=/opt/asbx/rustup
export CARGO_HOME=/opt/asbx/cargo
export PATH="/usr/local/go/bin:$CARGO_HOME/bin:/usr/local/bin:$PATH"
asbx_libc=gnu
if command -v apt-get >/dev/null 2>&1; then
  export DEBIAN_FRONTEND=noninteractive
  apt-get update
  apt-get install -y --no-install-recommends ca-certificates curl tar gzip xz-utils
  rm -rf /var/lib/apt/lists/*
elif command -v apk >/dev/null 2>&1; then
  asbx_libc=musl
  apk add --no-cache ca-certificates curl tar gzip xz
elif command -v dnf >/dev/null 2>&1; then
  dnf install -y ca-certificates curl tar gzip xz
  dnf clean all
elif command -v microdnf >/dev/null 2>&1; then
  microdnf install -y ca-certificates curl tar gzip xz
  microdnf clean all
else
  for utility in curl tar gzip xz; do
    command -v "$utility" >/dev/null 2>&1 || {
      echo "unsupported base image: missing package manager and $utility" >&2
      exit 64
    }
  done
fi
temporary="${TMPDIR:-/tmp}/asbx-toolchains"
rm -rf "$temporary"
mkdir -p "$temporary"
trap 'rm -rf "$temporary"' EXIT
"#,
    );
    let (go_arch, node_arch, rust_arch) = match build.arch.as_str() {
        "x86_64" => ("amd64", "x64", "x86_64"),
        "aarch64" => ("arm64", "arm64", "aarch64"),
        _ => unreachable!("build_request validates the guest architecture"),
    };
    if build
        .toolchains
        .iter()
        .any(|toolchain| toolchain.kind == ToolchainKind::Node)
    {
        script.push_str(
            r#"
if [ "$asbx_libc" = musl ]; then
  echo "exact Node.js toolchains require a glibc base image; use Ubuntu, Debian, or another glibc image" >&2
  exit 65
fi
"#,
        );
    }
    for toolchain in &build.toolchains {
        match toolchain.kind {
            ToolchainKind::Go => {
                script.push_str(&format!(
                    r#"
curl --fail --location --retry 3 --output "$temporary/go.tar.gz" \
  "https://go.dev/dl/go{}.linux-{}.tar.gz"
rm -rf /usr/local/go
tar -xzf "$temporary/go.tar.gz" -C /usr/local
ln -sf /usr/local/go/bin/go /usr/local/bin/go
ln -sf /usr/local/go/bin/gofmt /usr/local/bin/gofmt
go version
"#,
                    toolchain.version, go_arch
                ));
            }
            ToolchainKind::Rust => {
                script.push_str(&format!(
                    r#"
curl --proto '=https' --tlsv1.2 --fail --silent --show-error \
  "https://static.rust-lang.org/rustup/dist/{}-unknown-linux-$asbx_libc/rustup-init" \
  --output "$temporary/rustup-init"
chmod 0755 "$temporary/rustup-init"
rust_target="{}-unknown-linux-$asbx_libc"
attempt=1
while ! "$temporary/rustup-init" -y --no-modify-path --profile minimal \
  --default-host "$rust_target" --default-toolchain "{}"; do
  if [ "$attempt" -ge 3 ]; then
    echo "rustup installation failed after $attempt attempts" >&2
    exit 69
  fi
  attempt=$((attempt + 1))
  sleep 2
done
for binary in cargo rustc rustup rustfmt; do
  if [ -x "$CARGO_HOME/bin/$binary" ]; then
    ln -sf "$CARGO_HOME/bin/$binary" "/usr/local/bin/$binary"
  fi
done
rustc --version
cargo --version
"#,
                    rust_arch, rust_arch, toolchain.version
                ));
            }
            ToolchainKind::Node => {
                script.push_str(&format!(
                    r#"
curl --fail --location --retry 3 --output "$temporary/node.tar.xz" \
  "https://nodejs.org/dist/v{0}/node-v{0}-linux-{1}.tar.xz"
tar -xJf "$temporary/node.tar.xz" -C /usr/local --strip-components=1
node --version
npm --version
"#,
                    toolchain.version, node_arch
                ));
            }
        }
    }
    script
}

/// Canonical `LANG@VERSION` strings suitable for persistence and display.
pub fn toolchain_expressions(build: &EnvironmentBuild) -> Vec<String> {
    build
        .toolchains
        .iter()
        .map(|toolchain| {
            format!(
                "{}@{}",
                match toolchain.kind {
                    ToolchainKind::Go => "go",
                    ToolchainKind::Rust => "rust",
                    ToolchainKind::Node => "node",
                },
                toolchain.version
            )
        })
        .collect()
}

fn parse_toolchain(expression: &str) -> Result<ToolchainSpec, EnvironmentError> {
    let (kind, version) = expression.split_once('@').ok_or_else(|| {
        EnvironmentError::Unsupported(format!(
            "invalid toolchain {expression:?}; expected go@VERSION, rust@VERSION, or node@VERSION"
        ))
    })?;
    let kind = match kind.to_ascii_lowercase().as_str() {
        "go" | "golang" => ToolchainKind::Go,
        "rust" => ToolchainKind::Rust,
        "node" | "nodejs" | "typescript" | "ts" => ToolchainKind::Node,
        _ => {
            return Err(EnvironmentError::Unsupported(format!(
                "unsupported toolchain family {kind:?}"
            )));
        }
    };
    let version = normalize_version(kind, version)?;
    Ok(ToolchainSpec { kind, version })
}

fn normalize_version(kind: ToolchainKind, value: &str) -> Result<String, EnvironmentError> {
    let value = value
        .strip_prefix("go")
        .or_else(|| value.strip_prefix('v'))
        .unwrap_or(value);
    let mut parts = value.split('.').collect::<Vec<_>>();
    let expected_minimum = if kind == ToolchainKind::Node { 1 } else { 2 };
    if parts.len() < expected_minimum
        || parts.len() > 3
        || parts
            .iter()
            .any(|part| part.is_empty() || !part.bytes().all(|byte| byte.is_ascii_digit()))
    {
        return Err(EnvironmentError::Unsupported(format!(
            "invalid toolchain version {value:?}; use a numeric release with at most three components"
        )));
    }
    while parts.len() < 3 {
        parts.push("0");
    }
    Ok(parts.join("."))
}

fn validate_name(name: &str) -> Result<(), EnvironmentError> {
    let valid = (1..=64).contains(&name.len())
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'));
    if !valid {
        return Err(EnvironmentError::Unsupported(format!(
            "invalid environment name {name:?}; use 1-64 ASCII letters, digits, '.', '_' or '-'"
        )));
    }
    Ok(())
}

fn validate_base(base: &str) -> Result<(), EnvironmentError> {
    let valid = !base.is_empty()
        && base.len() <= 255
        && base.bytes().all(|byte| {
            byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_' | b':' | b'/' | b'@')
        });
    if !valid {
        return Err(EnvironmentError::Unsupported(format!(
            "invalid base image reference {base:?}"
        )));
    }
    Ok(())
}

fn guest_arch() -> Result<&'static str, EnvironmentError> {
    match std::env::consts::ARCH {
        "x86_64" => Ok("x86_64"),
        "aarch64" => Ok("aarch64"),
        arch => Err(EnvironmentError::Unsupported(format!(
            "managed environment builds are not yet available on host architecture {arch:?}"
        ))),
    }
}

fn recompute_cache_key(mut build: EnvironmentBuild) -> EnvironmentBuild {
    let base_identity = build.base_digest.as_deref().unwrap_or(&build.base);
    let manifest = serde_json::json!({
        "manifest_version": BUILD_MANIFEST_VERSION,
        "base_identity": base_identity,
        "arch": build.arch,
        "toolchains": build.toolchains,
    });
    build.cache_key = hex::encode(Sha256::digest(
        serde_json::to_vec(&manifest)
            .expect("environment build manifest only contains serializable values"),
    ));
    build.snapshot = format!("asbx-env-{}-{}", build.name, &build.cache_key[..16]);
    build
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
        assert_eq!(
            resolve_language("go@1.24").unwrap(),
            "registry-1.docker.io/library/golang:1.24-bookworm"
        );
        assert_eq!(
            resolve_language("node@22").unwrap(),
            "registry-1.docker.io/library/node:22-bookworm"
        );
        assert_eq!(
            resolve_language("rust@1.88").unwrap(),
            "registry-1.docker.io/library/rust:1.88-bookworm"
        );
    }

    #[test]
    fn normalizes_docker_hub_references_without_rewriting_other_registries() {
        assert_eq!(
            normalize_image_reference("alpine:3.20"),
            "registry-1.docker.io/library/alpine:3.20"
        );
        assert_eq!(
            normalize_image_reference("acme/tool:latest"),
            "registry-1.docker.io/acme/tool:latest"
        );
        assert_eq!(
            normalize_image_reference("docker.io/alpine@sha256:abc"),
            "registry-1.docker.io/library/alpine@sha256:abc"
        );
        assert_eq!(
            normalize_image_reference("index.docker.io/library/alpine"),
            "registry-1.docker.io/library/alpine"
        );
        assert_eq!(
            normalize_image_reference("ghcr.io/acme/tool:latest"),
            "ghcr.io/acme/tool:latest"
        );
        assert_eq!(
            normalize_image_reference("localhost:5000/acme/tool"),
            "localhost:5000/acme/tool"
        );
    }

    #[test]
    fn rejects_image_tag_injection() {
        assert!(resolve_language("node@22/../../bad").is_err());
    }

    #[test]
    fn managed_build_is_normalized_and_deterministic() {
        let digest = format!("sha256:{}", "a".repeat(64));
        let left = pin_base_digest(
            build_request(
                "audit",
                "ubuntu:24.04",
                &["node@22".into(), "go@1.24".into(), "go@1.24.0".into()],
            )
            .unwrap(),
            &digest,
        )
        .unwrap();
        let right = pin_base_digest(
            build_request(
                "audit",
                "ubuntu:latest",
                &["go@1.24.0".into(), "node@22.0.0".into()],
            )
            .unwrap(),
            &digest,
        )
        .unwrap();
        assert_eq!(left.cache_key, right.cache_key);
        assert_eq!(
            toolchain_expressions(&left),
            vec!["go@1.24.0", "node@22.0.0"]
        );
        assert!(left.snapshot.starts_with("asbx-env-audit-"));
    }

    #[test]
    fn provisioning_script_has_portable_distro_and_arch_branches() {
        let build = build_request("full", "alpine:3.22", &["rust@1.88".into()]).unwrap();
        let script = provisioning_script(&build);
        assert!(script.contains("command -v apt-get"));
        assert!(script.contains("command -v apk"));
        assert!(script.contains("rustup-init"));
        assert!(!script.contains("sudo"));
    }

    #[test]
    fn rejects_shell_metacharacters_in_build_inputs() {
        assert!(build_request("bad/name", "ubuntu:24.04", &["go@1.24".into()]).is_err());
        assert!(build_request("safe", "ubuntu:24.04;id", &["go@1.24".into()]).is_err());
        assert!(build_request("safe", "ubuntu:24.04", &["node@22$(id)".into()]).is_err());
    }
}
