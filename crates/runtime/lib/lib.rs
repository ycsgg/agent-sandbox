//! Runtime-neutral sandbox contracts.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Result type returned by runtime backends.
pub type Result<T> = std::result::Result<T, RuntimeError>;

/// A runtime backend error with operation context.
#[derive(Debug, thiserror::Error)]
pub enum RuntimeError {
    /// The requested sandbox no longer exists.
    #[error("sandbox not found: {0}")]
    NotFound(String),

    /// The backend rejected or failed an operation.
    #[error("{operation}: {message}")]
    Backend {
        /// Operation being attempted.
        operation: &'static str,
        /// Backend-provided detail.
        message: String,
    },

    /// The requested feature is not implemented by the backend.
    #[error("runtime feature is unsupported: {0}")]
    Unsupported(String),
}

/// Network exposure selected for a sandbox.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkMode {
    /// No guest network device.
    Off,
    /// Public Internet only; private, host, link-local, and metadata addresses are denied.
    Public,
    /// Registry endpoints inferred from project declarations.
    Dependencies,
    /// A deny-by-default custom rule set.
    Rules,
    /// Unrestricted networking. This is intentionally high risk.
    All,
}

/// Action applied by a custom network rule.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NetworkRuleAction {
    /// Permit matching traffic.
    Allow,
    /// Drop matching traffic.
    Deny,
}

/// Destination matched by a custom egress rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum NetworkRuleTarget {
    /// Exact DNS name.
    Domain(String),
    /// Apex DNS name and all subdomains.
    DomainSuffix(String),
    /// IP address or CIDR.
    Cidr(String),
    /// Public destinations on one inclusive TCP/UDP port range.
    PublicPort {
        /// First port.
        start: u16,
        /// Last port.
        end: u16,
    },
    /// Private address groups.
    Private,
    /// The host gateway.
    Host,
    /// Cloud metadata endpoints.
    Metadata,
}

/// One ordered custom network rule.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkRule {
    /// Allow or deny action.
    pub action: NetworkRuleAction,
    /// Destination matcher.
    pub target: NetworkRuleTarget,
}

/// Project exposure mode.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ProjectMode {
    /// Copy validated project files to a private guest disk.
    Copy,
    /// Bind the project read-only at `/workspace`.
    MountReadOnly,
    /// Bind the project read-write at `/workspace`.
    MountReadWrite,
}

/// Host workspace exposure passed to a runtime backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "kebab-case")]
pub enum WorkspaceSpec {
    /// No project is exposed, as used by trusted environment builders.
    None,
    /// Project files are copied after VM creation.
    Copy,
    /// A host directory is mounted at `/workspace`.
    Mount {
        /// Canonical host directory.
        host: PathBuf,
        /// Prevent all guest writes.
        read_only: bool,
        /// Guest growth quota in MiB for writable mounts.
        write_quota_mib: Option<u32>,
    },
}

/// Guest security profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum SecurityMode {
    /// Microsandbox's default profile.
    Default,
    /// Drops mount-administration privileges in the guest.
    Restricted,
}

/// Root filesystem source.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "value", rename_all = "kebab-case")]
pub enum RootSource {
    /// An OCI image reference.
    Image(String),
    /// A Microsandbox snapshot name or path.
    Snapshot(String),
}

/// A loopback TCP port publication.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct PortMapping {
    /// Guest TCP port.
    pub guest_port: u16,
    /// Host loopback port.
    pub host_port: u16,
}

/// Effective sandbox creation request after policy enforcement.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CreateSpec {
    /// Stable sandbox identifier.
    pub id: String,
    /// Root filesystem source.
    pub root: RootSource,
    /// Number of guest virtual CPUs.
    pub cpus: u8,
    /// Guest memory in MiB.
    pub memory_mib: u32,
    /// Writable root disk in MiB.
    pub disk_mib: u32,
    /// Optional guest user.
    pub user: Option<String>,
    /// Guest security profile.
    pub security: SecurityMode,
    /// Effective network mode.
    pub network: NetworkMode,
    /// Ordered custom/dependency network rules.
    pub network_rules: Vec<NetworkRule>,
    /// Project copy or mount exposure.
    pub workspace: WorkspaceSpec,
    /// Explicit environment injected into the guest.
    pub env: Vec<(String, String)>,
    /// Published loopback ports.
    pub ports: Vec<PortMapping>,
    /// Runtime-enforced maximum lifetime.
    pub max_duration: Duration,
    /// Whether backend state should disappear once the VM stops.
    pub ephemeral: bool,
    /// Whether the sandbox survives the creating CLI process.
    pub detached: bool,
}

/// Guest command request.
#[derive(Debug, Clone)]
pub struct ExecRequest {
    /// Executable path or command name.
    pub command: String,
    /// Command arguments.
    pub args: Vec<String>,
    /// Guest working directory.
    pub cwd: Option<String>,
    /// Optional guest user override.
    pub user: Option<String>,
    /// Explicit command environment.
    pub env: Vec<(String, String)>,
    /// Backend command timeout.
    pub timeout: Option<Duration>,
    /// Allocate a pseudo-terminal.
    pub tty: bool,
}

/// A streaming command event.
#[derive(Debug)]
pub enum ExecEvent {
    /// Guest process started.
    Started {
        /// Guest PID.
        pid: u32,
    },
    /// Raw standard-output bytes.
    Stdout(Bytes),
    /// Raw standard-error bytes.
    Stderr(Bytes),
    /// Output bytes were discarded to preserve bounded host memory under backpressure.
    OutputTruncated {
        /// Affected guest stream.
        stream: OutputStream,
        /// Number of discarded bytes since the previous notice.
        dropped_bytes: u64,
    },
    /// The wrapper stopped a guest process after its execution deadline.
    TimedOut {
        /// Configured execution deadline.
        after: Duration,
        /// Whether the runtime had to terminate the whole sandbox as a fallback.
        sandbox_terminated: bool,
    },
    /// Guest process exited.
    Exited {
        /// Guest exit code.
        code: i32,
    },
    /// Guest process could not be spawned.
    Failed(String),
}

/// Guest output stream identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OutputStream {
    /// Standard output.
    Stdout,
    /// Standard error.
    Stderr,
}

/// Receiver returned for streaming execution.
pub type ExecStream = mpsc::Receiver<Result<ExecEvent>>;

/// Runtime-visible sandbox information.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SandboxInfo {
    /// Sandbox identifier.
    pub id: String,
    /// Runtime status.
    pub status: String,
    /// Creation time when known.
    pub created_at: Option<DateTime<Utc>>,
}

/// Runtime snapshot metadata used for managed environments and cache policy.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SnapshotInfo {
    /// Human-readable snapshot name.
    pub name: String,
    /// Content-addressed manifest digest.
    pub digest: String,
    /// Pinned base image reference.
    pub image: String,
    /// Content-addressed base image manifest digest.
    pub image_manifest_digest: String,
    /// Apparent writable-layer bytes.
    pub size_bytes: u64,
    /// Creation time when available.
    pub created_at: Option<DateTime<Utc>>,
    /// Snapshot labels.
    pub labels: BTreeMap<String, String>,
}

/// Runtime OCI image-cache metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ImageInfo {
    /// OCI reference.
    pub reference: String,
    /// Content-addressed OCI manifest digest.
    pub manifest_digest: Option<String>,
    /// Logical image bytes.
    pub size_bytes: u64,
    /// Most recent cache use time.
    pub last_used_at: Option<DateTime<Utc>>,
    /// Initial cache creation time.
    pub created_at: Option<DateTime<Utc>>,
}

/// Guest filesystem entry.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GuestEntry {
    /// Absolute guest path.
    pub path: String,
    /// Whether this entry is a directory.
    pub directory: bool,
    /// Whether this entry is a symbolic link.
    pub symlink: bool,
    /// File size.
    pub size: u64,
    /// Unix permission bits.
    pub mode: u32,
}

//--------------------------------------------------------------------------------------------------
// Traits
//--------------------------------------------------------------------------------------------------

/// Pluggable microVM runtime used by the core orchestration layer.
#[async_trait]
pub trait SandboxRuntime: Send + Sync {
    /// Create and start a sandbox.
    async fn create(&self, spec: &CreateSpec) -> Result<SandboxInfo>;

    /// Stream a command in a running sandbox.
    async fn exec_stream(&self, sandbox: &str, request: ExecRequest) -> Result<ExecStream>;

    /// Attach the current terminal to a command.
    async fn attach(&self, sandbox: &str, request: ExecRequest) -> Result<i32>;

    /// Create a guest directory and its parents.
    async fn mkdir(&self, sandbox: &str, guest_path: &str) -> Result<()>;

    /// Upload one regular file.
    async fn put_file(
        &self,
        sandbox: &str,
        host_path: &Path,
        guest_path: &str,
        mode: u32,
    ) -> Result<()>;

    /// Create one guest symlink.
    async fn symlink(&self, sandbox: &str, target: &str, guest_path: &str) -> Result<()>;

    /// Set Unix permission bits on a guest path.
    async fn set_mode(&self, sandbox: &str, guest_path: &str, mode: u32) -> Result<()>;

    /// List a guest directory.
    async fn list_dir(&self, sandbox: &str, guest_path: &str) -> Result<Vec<GuestEntry>>;

    /// Download one regular guest file.
    async fn get_file(&self, sandbox: &str, guest_path: &str, host_path: &Path) -> Result<()>;

    /// Gracefully stop a sandbox, escalating when necessary.
    async fn stop(&self, sandbox: &str) -> Result<()>;

    /// Force-kill a sandbox.
    async fn kill(&self, sandbox: &str) -> Result<()>;

    /// Remove stopped sandbox state.
    async fn remove(&self, sandbox: &str) -> Result<()>;

    /// List backend sandboxes.
    async fn list(&self) -> Result<Vec<SandboxInfo>>;

    /// Inspect one backend sandbox.
    async fn inspect(&self, sandbox: &str) -> Result<SandboxInfo>;

    /// Check whether runtime prerequisites are ready.
    async fn doctor(&self) -> Result<Vec<(String, bool, String)>>;

    /// Create a disk snapshot from a stopped sandbox.
    async fn create_snapshot(
        &self,
        name: &str,
        sandbox: &str,
        labels: &BTreeMap<String, String>,
    ) -> Result<SnapshotInfo>;

    /// List runtime snapshots.
    async fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>>;

    /// Inspect one runtime snapshot.
    async fn inspect_snapshot(&self, name: &str) -> Result<SnapshotInfo>;

    /// Remove one runtime snapshot.
    async fn remove_snapshot(&self, name: &str) -> Result<()>;

    /// List cached OCI image references.
    async fn list_images(&self) -> Result<Vec<ImageInfo>>;

    /// Remove one cached OCI image reference if unused.
    async fn remove_image(&self, reference: &str) -> Result<()>;
}
