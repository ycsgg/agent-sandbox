//! Runtime-neutral sandbox contracts.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fmt,
    net::SocketAddr,
    path::{Path, PathBuf},
    str::FromStr,
    time::Duration,
};

use async_trait::async_trait;
use bytes::Bytes;
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;

mod registry;

pub use registry::RuntimeRegistry;

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

    /// Runtime selection or configuration is invalid.
    #[error("invalid runtime configuration: {0}")]
    Configuration(String),
}

/// Stable runtime backend identifier.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(transparent)]
pub struct BackendId(String);

impl BackendId {
    /// Microsandbox backend identifier.
    pub const MICROSANDBOX: &'static str = "microsandbox";
    /// QEMU backend identifier.
    pub const QEMU: &'static str = "qemu";

    /// Parse and validate a backend identifier.
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty()
            || value.len() > 32
            || value.chars().any(|character| {
                !(character.is_ascii_lowercase() || character.is_ascii_digit() || character == '-')
            })
        {
            return Err(RuntimeError::Configuration(format!(
                "backend identifier {value:?} must contain 1-32 lowercase ASCII letters, digits, or hyphens"
            )));
        }
        Ok(Self(value))
    }

    /// Borrow the canonical identifier.
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// Construct the Microsandbox identifier.
    pub fn microsandbox() -> Self {
        Self(Self::MICROSANDBOX.into())
    }

    /// Construct the QEMU identifier.
    pub fn qemu() -> Self {
        Self(Self::QEMU.into())
    }
}

impl Default for BackendId {
    fn default() -> Self {
        Self::microsandbox()
    }
}

impl fmt::Display for BackendId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl FromStr for BackendId {
    type Err = RuntimeError;

    fn from_str(value: &str) -> Result<Self> {
        Self::new(value)
    }
}

/// A boot-source family accepted by a runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum BootSourceKind {
    /// OCI image reference.
    OciImage,
    /// Backend snapshot.
    Snapshot,
    /// Bootable machine disk.
    DiskImage,
    /// Direct kernel boot, optionally with a disk and initrd.
    DirectKernel,
}

/// Independently discoverable runtime operation.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum RuntimeFeature {
    /// Stream non-interactive guest commands.
    Exec,
    /// Attach an interactive terminal.
    Attach,
    /// Transfer guest files.
    FileTransfer,
    /// Mount a host workspace read-only.
    ReadOnlyMount,
    /// Mount a host workspace read-write.
    ReadWriteMount,
    /// Publish guest TCP ports on host loopback.
    PortForward,
    /// Enforce custom egress rules.
    NetworkRules,
    /// Create and manage backend snapshots.
    Snapshots,
    /// Manage cached OCI images.
    ImageCache,
    /// Expose a serial log.
    SerialLog,
    /// Expose a QMP-compatible machine control channel.
    MachineControl,
    /// Expose a loopback-only GDB remote stub.
    GdbStub,
}

/// Static feature declaration for one backend.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackendCapabilities {
    /// Backend identifier.
    pub backend: BackendId,
    /// Supported boot-source families.
    pub boot_sources: Vec<BootSourceKind>,
    /// Supported runtime operations.
    pub features: Vec<RuntimeFeature>,
    /// Supported guest architecture names.
    pub architectures: Vec<String>,
    /// Supported accelerator names.
    pub accelerators: Vec<String>,
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
    /// Do not expose a host project to the guest.
    None,
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
#[non_exhaustive]
pub enum RootSource {
    /// An OCI image reference.
    Image(String),
    /// A Microsandbox snapshot name or path.
    Snapshot(String),
    /// A bootable virtual-machine definition.
    Machine(Box<MachineBootSpec>),
}

/// QEMU-compatible virtual disk image format.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DiskImageFormat {
    /// Raw block image.
    Raw,
    /// QEMU copy-on-write image version 2.
    Qcow2,
}

/// One host disk image attached to a virtual machine.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiskImageSpec {
    /// Host image path.
    pub path: PathBuf,
    /// On-disk image format.
    pub format: DiskImageFormat,
    /// Prevent guest writes to the source image.
    pub read_only: bool,
}

/// Generic system-machine boot inputs used by full-system backends.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineBootSpec {
    /// Guest architecture such as `x86_64`, `aarch64`, or `riscv64`.
    pub architecture: String,
    /// Optional machine type override.
    pub machine: Option<String>,
    /// Optional virtual CPU model override.
    pub cpu: Option<String>,
    /// Optional accelerator override (`auto`, `kvm`, `hvf`, `whpx`, or `tcg`).
    pub accelerator: Option<String>,
    /// Optional bootable root disk.
    pub disk: Option<DiskImageSpec>,
    /// Optional direct-boot kernel image.
    pub kernel: Option<PathBuf>,
    /// Optional direct-boot initramfs.
    pub initrd: Option<PathBuf>,
    /// Optional device-tree blob.
    pub dtb: Option<PathBuf>,
    /// Optional platform firmware image.
    pub firmware: Option<PathBuf>,
    /// Kernel command-line suffix.
    pub kernel_append: Vec<String>,
    /// Optional debugger endpoint and initial pause.
    pub debug: Option<MachineDebugSpec>,
}

/// Generic full-system debugger settings.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct MachineDebugSpec {
    /// Requested loopback GDB port, or zero for automatic allocation.
    pub gdb_port: u16,
    /// Start CPUs paused until a debugger or machine-control client resumes them.
    pub pause_at_boot: bool,
}

/// Remote debugger protocol exposed by a runtime.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
#[non_exhaustive]
pub enum DebugProtocol {
    /// GDB remote serial protocol over TCP.
    GdbRemote,
}

/// Typed debugger connection context supplied by a runtime capability.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugContext {
    /// Runtime backend that owns the target.
    pub backend: BackendId,
    /// Remote debugging protocol.
    pub protocol: DebugProtocol,
    /// Host endpoint. Agent-facing consumers should normally require loopback.
    pub endpoint: SocketAddr,
    /// Guest architecture.
    pub architecture: String,
    /// Selected accelerator when applicable.
    pub accelerator: Option<String>,
    /// Current runtime status.
    pub status: String,
    /// Whether the guest was intentionally paused before its first instruction.
    pub paused_at_boot: Option<bool>,
    /// Whether address randomization is known to be disabled.
    pub kaslr_disabled: Option<bool>,
    /// Boot executable reported for context only; consumers must not load it implicitly.
    pub boot_kernel: Option<PathBuf>,
}

impl DebugContext {
    /// Whether runtime state still owns live VM resources.
    pub fn is_active(&self) -> bool {
        !matches!(self.status.as_str(), "created" | "stopped" | "crashed")
    }
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
    /// Runtime backend selected after host-policy enforcement.
    pub backend: BackendId,
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
    /// Requested maximum lifetime. The wrapper lease always enforces this
    /// during reconciliation; a backend may add its own independent backstop.
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
    /// Owning runtime backend.
    pub backend: BackendId,
    /// Runtime status.
    pub status: String,
    /// Creation time when known.
    pub created_at: Option<DateTime<Utc>>,
    /// Backend-specific, reader-facing endpoints and diagnostics.
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub metadata: BTreeMap<String, String>,
}

impl SandboxInfo {
    /// Whether backend state still owns live VM resources.
    ///
    /// Full-system backends may legitimately be paused or suspended, so
    /// callers must not equate "active" with the literal status `running`.
    pub fn is_active(&self) -> bool {
        !matches!(self.status.as_str(), "created" | "stopped" | "crashed")
    }
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

/// Streams non-interactive commands in a running sandbox.
#[async_trait]
pub trait CommandRuntime: Send + Sync {
    /// Stream a command in a running sandbox.
    async fn exec_stream(&self, sandbox: &str, request: ExecRequest) -> Result<ExecStream>;
}

/// Attaches an interactive terminal to a running sandbox.
#[async_trait]
pub trait TerminalRuntime: Send + Sync {
    /// Attach the current terminal to a command.
    async fn attach(&self, sandbox: &str, request: ExecRequest) -> Result<i32>;
}

/// Transfers files between the host and a running sandbox.
#[async_trait]
pub trait FileTransferRuntime: Send + Sync {
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
}

/// Creates and manages reusable runtime snapshots.
#[async_trait]
pub trait SnapshotRuntime: Send + Sync {
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
}

/// Inspects and prunes a runtime's image cache.
#[async_trait]
pub trait ImageRuntime: Send + Sync {
    /// List cached OCI image references.
    async fn list_images(&self) -> Result<Vec<ImageInfo>>;

    /// Remove one cached OCI image reference if unused.
    async fn remove_image(&self, reference: &str) -> Result<()>;
}

/// Supplies a typed remote-debugging context for a running sandbox.
#[async_trait]
pub trait DebugRuntime: Send + Sync {
    /// Resolve the current debugger endpoint and target properties.
    async fn debug_context(&self, sandbox: &str) -> Result<DebugContext>;
}

/// Pluggable sandbox lifecycle with optional, independently implemented
/// capabilities.
///
/// New backends implement this small lifecycle contract and opt into only the
/// operation traits they actually support. Adding a new optional operation does
/// not force unrelated backends to add placeholder methods.
#[async_trait]
pub trait SandboxRuntime: Send + Sync {
    /// Stable backend identifier.
    fn backend_id(&self) -> BackendId;

    /// Static backend capabilities.
    fn capabilities(&self) -> BackendCapabilities;

    /// Non-interactive command capability, when supported.
    fn command_runtime(&self) -> Option<&dyn CommandRuntime> {
        None
    }

    /// Interactive terminal capability, when supported.
    fn terminal_runtime(&self) -> Option<&dyn TerminalRuntime> {
        None
    }

    /// Guest file-transfer capability, when supported.
    fn file_transfer_runtime(&self) -> Option<&dyn FileTransferRuntime> {
        None
    }

    /// Snapshot-store capability, when supported.
    fn snapshot_runtime(&self) -> Option<&dyn SnapshotRuntime> {
        None
    }

    /// Image-cache capability, when supported.
    fn image_runtime(&self) -> Option<&dyn ImageRuntime> {
        None
    }

    /// Remote-debugging capability, when supported.
    fn debug_runtime(&self) -> Option<&dyn DebugRuntime> {
        None
    }

    /// Create and start a sandbox.
    async fn create(&self, spec: &CreateSpec) -> Result<SandboxInfo>;

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

impl dyn SandboxRuntime {
    /// Return the command capability or a backend-specific unsupported error.
    pub fn require_command_runtime(&self) -> Result<&dyn CommandRuntime> {
        self.command_runtime()
            .ok_or_else(|| self.unsupported(RuntimeFeature::Exec))
    }

    /// Return the terminal capability or a backend-specific unsupported error.
    pub fn require_terminal_runtime(&self) -> Result<&dyn TerminalRuntime> {
        self.terminal_runtime()
            .ok_or_else(|| self.unsupported(RuntimeFeature::Attach))
    }

    /// Return the file-transfer capability or a backend-specific unsupported error.
    pub fn require_file_transfer_runtime(&self) -> Result<&dyn FileTransferRuntime> {
        self.file_transfer_runtime()
            .ok_or_else(|| self.unsupported(RuntimeFeature::FileTransfer))
    }

    /// Return the snapshot capability or a backend-specific unsupported error.
    pub fn require_snapshot_runtime(&self) -> Result<&dyn SnapshotRuntime> {
        self.snapshot_runtime()
            .ok_or_else(|| self.unsupported(RuntimeFeature::Snapshots))
    }

    /// Return the image-cache capability or a backend-specific unsupported error.
    pub fn require_image_runtime(&self) -> Result<&dyn ImageRuntime> {
        self.image_runtime()
            .ok_or_else(|| self.unsupported(RuntimeFeature::ImageCache))
    }

    /// Return the remote-debugging capability or a backend-specific unsupported error.
    pub fn require_debug_runtime(&self) -> Result<&dyn DebugRuntime> {
        self.debug_runtime()
            .ok_or_else(|| self.unsupported(RuntimeFeature::GdbStub))
    }

    fn unsupported(&self, feature: RuntimeFeature) -> RuntimeError {
        RuntimeError::Unsupported(format!(
            "backend {} does not support {feature:?}",
            self.backend_id()
        ))
    }
}
