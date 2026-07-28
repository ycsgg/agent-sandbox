//! Runtime-neutral sandbox contracts.

#![forbid(unsafe_code)]

use std::{path::Path, time::Duration};

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
    /// Unrestricted networking. This is intentionally high risk.
    All,
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
}
