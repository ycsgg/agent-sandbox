//! Host policy loading and effective-spec enforcement.

#![forbid(unsafe_code)]

use std::{
    collections::HashSet,
    env, fmt, fs,
    path::{Path, PathBuf},
    time::Duration,
};

use agent_sandbox_runtime::{
    BackendId, NetworkMode, NetworkRule, NetworkRuleAction, NetworkRuleTarget, PortMapping,
    ProjectMode, RootSource, SecurityMode,
};
use ipnet::IpNet;
use serde::Deserialize;
use url::Url;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Policy result type.
pub type Result<T> = std::result::Result<T, PolicyError>;

/// Policy validation or configuration error.
#[derive(Debug, thiserror::Error)]
pub enum PolicyError {
    /// Configuration could not be read.
    #[error("cannot read config {path}: {source}")]
    ReadConfig {
        /// Config path.
        path: PathBuf,
        /// Filesystem error.
        source: std::io::Error,
    },

    /// Configuration is malformed.
    #[error("cannot parse config {path}: {source}")]
    ParseConfig {
        /// Config path.
        path: PathBuf,
        /// TOML error.
        source: toml::de::Error,
    },

    /// A value is malformed.
    #[error("invalid {field} value {value:?}: {reason}")]
    InvalidValue {
        /// Field name.
        field: &'static str,
        /// User value.
        value: String,
        /// Expected form.
        reason: String,
    },

    /// Project path is outside configured roots.
    #[error("project {project} is outside authorized workspace roots: {roots}")]
    WorkspaceDenied {
        /// Canonical project path.
        project: PathBuf,
        /// Displayed roots.
        roots: String,
    },

    /// A requested value exceeds a host cap.
    #[error("{field} request {requested} exceeds host maximum {maximum}")]
    LimitExceeded {
        /// Limited field.
        field: &'static str,
        /// Requested amount.
        requested: String,
        /// Maximum amount.
        maximum: String,
    },

    /// A high-risk mode is disabled by host configuration.
    #[error("{0}")]
    Forbidden(String),
}

/// Host configuration.
#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct HostConfig {
    /// Runtime lifetime and concurrency settings.
    pub runtime: RuntimeConfig,
    /// QEMU backend process and guest-transport settings.
    pub qemu: QemuConfig,
    /// Android Cuttlefish backend settings.
    pub cuttlefish: CuttlefishConfig,
    /// Android SDK Emulator backend settings.
    pub android_emulator: AndroidEmulatorConfig,
    /// Host HTTP proxy settings used by registry and other wrapper clients.
    pub proxy: ProxyConfig,
    /// Authorized workspace roots.
    pub workspace: WorkspaceConfig,
    /// Network policy gates.
    pub network: NetworkConfig,
    /// Resource defaults and emergency caps.
    pub resources: ResourceConfig,
    /// Output limits.
    pub output: OutputConfig,
    /// Project-transfer limits.
    pub transfer: TransferConfig,
    /// Wrapper-managed cache quota.
    pub cache: CacheConfig,
}

/// Runtime host settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct RuntimeConfig {
    /// Backend name.
    pub backend: String,
    /// Maximum concurrent sandboxes attributed to the wrapper.
    pub max_concurrent_sandboxes: usize,
    /// Reserved-memory emergency cap.
    pub max_reserved_memory: String,
    /// Default session TTL.
    pub default_ttl: String,
    /// Maximum runtime TTL.
    pub max_ttl: String,
}

/// QEMU backend host settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct QemuConfig {
    /// Explicit `qemu-system-*` executable.
    pub binary: Option<PathBuf>,
    /// Explicit OpenSSH client executable.
    pub ssh_binary: Option<PathBuf>,
    /// Default SSH login. Omit to disable guest command/file transport.
    pub ssh_user: Option<String>,
    /// Optional SSH private key.
    pub ssh_key: Option<PathBuf>,
    /// QMP and optional SSH readiness deadline.
    pub boot_timeout: String,
    /// Graceful ACPI shutdown deadline.
    pub shutdown_timeout: String,
}

/// Android Cuttlefish backend settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CuttlefishConfig {
    /// Combined Cuttlefish host-tools and Android device-images directory.
    pub artifacts: Option<PathBuf>,
    /// Device launch and ADB readiness deadline.
    pub boot_timeout: String,
    /// Device shutdown deadline.
    pub shutdown_timeout: String,
}

/// Android SDK Emulator backend settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AndroidEmulatorConfig {
    /// Android SDK root override.
    pub sdk_root: Option<PathBuf>,
    /// Android Emulator executable override.
    pub emulator: Option<PathBuf>,
    /// ADB executable override.
    pub adb: Option<PathBuf>,
    /// Default source AVD name.
    pub avd: Option<String>,
    /// Device boot and ADB readiness deadline.
    pub boot_timeout: String,
    /// Device shutdown deadline.
    pub shutdown_timeout: String,
    /// Graphics backend: auto, host, software, swiftshader, swangle, or lavapipe.
    pub gpu: String,
}

/// Host HTTP proxy settings.
#[derive(Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ProxyConfig {
    /// Inherit standard proxy variables from the invoking process.
    pub inherit_env: bool,
    /// Explicit proxy for plain HTTP requests.
    pub http: Option<String>,
    /// Explicit proxy for HTTPS requests.
    pub https: Option<String>,
    /// Explicit proxy for both HTTP and HTTPS when a scheme-specific value is absent.
    pub all: Option<String>,
    /// Hosts that bypass the proxy, joined into `NO_PROXY`.
    pub no_proxy: Vec<String>,
    /// Forward the resolved proxy variables into guest commands.
    pub inject_guest: bool,
}

/// Resolved standard proxy variables.
#[derive(Clone, Default, PartialEq, Eq)]
pub struct ProxyEnvironment {
    http: Option<String>,
    https: Option<String>,
    all: Option<String>,
    no_proxy: Option<String>,
}

/// Workspace boundary settings.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct WorkspaceConfig {
    /// Canonical roots under which projects may be copied or mounted.
    pub roots: Vec<PathBuf>,
    /// Whether writable mounts may be explicitly requested.
    pub allow_rw_mount: bool,
    /// Maximum guest growth allowed through one writable project mount.
    pub rw_mount_quota: String,
}

/// Network gates.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct NetworkConfig {
    /// Default network mode.
    pub default: String,
    /// Whether unrestricted networking is permitted.
    pub allow_all_mode: bool,
    /// Reserved for private/host rule overrides.
    pub allow_private_override: bool,
    /// Whether published ports may bind non-loopback addresses.
    pub allow_non_loopback_publish: bool,
    /// Maximum number of custom egress rules.
    pub max_custom_rules: usize,
}

/// Resource defaults and caps.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct ResourceConfig {
    /// Default CPU count.
    pub default_cpus: u8,
    /// Default memory size.
    pub default_memory: String,
    /// Default writable disk size.
    pub default_disk: String,
    /// CPU emergency cap.
    pub max_cpus: u8,
    /// Memory emergency cap.
    pub max_memory: String,
    /// Writable disk emergency cap.
    pub max_disk: String,
}

/// Streaming and retained-output limits.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct OutputConfig {
    /// In-memory stdout/stderr tail.
    pub memory_tail: String,
    /// Maximum retained log file size.
    pub max_log_disk: String,
    /// Maximum artifact bytes copied to the host.
    pub max_artifact_total: String,
}

/// Safe project-walker limits.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct TransferConfig {
    /// Maximum transferred entries.
    pub max_files: u64,
    /// Maximum size of one regular file.
    pub max_file_size: String,
    /// Maximum total regular-file bytes.
    pub max_total_size: String,
}

/// Cache quota defaults.
#[derive(Debug, Clone, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct CacheConfig {
    /// Maximum logical bytes retained by default.
    pub max_size: String,
}

/// User-selectable sandbox settings before policy enforcement.
#[derive(Debug, Clone)]
pub struct RequestedSpec {
    /// Selected runtime backend.
    pub backend: BackendId,
    /// Root source selected by environment resolution.
    pub root: RootSource,
    /// Project path.
    pub project: PathBuf,
    /// CPU request.
    pub cpus: Option<u8>,
    /// Memory request such as `2G`.
    pub memory: Option<String>,
    /// Disk request such as `16G`.
    pub disk: Option<String>,
    /// Guest user.
    pub user: Option<String>,
    /// Guest security profile.
    pub security: SecurityMode,
    /// Network mode, or host default.
    pub network: Option<NetworkMode>,
    /// Ordered custom or dependency egress rules.
    pub network_rules: Vec<NetworkRule>,
    /// Project copy or mount mode.
    pub project_mode: ProjectMode,
    /// Command timeout, or none.
    pub timeout: Option<Duration>,
    /// Session TTL, or host default.
    pub ttl: Option<Duration>,
    /// Explicit guest environment.
    pub env: Vec<(String, String)>,
    /// Requested TCP publications.
    pub ports: Vec<PortMapping>,
}

/// Policy-approved values.
#[derive(Debug, Clone)]
pub struct EffectiveSpec {
    /// Selected runtime backend.
    pub backend: BackendId,
    /// Canonical project path.
    pub project: PathBuf,
    /// Root filesystem source.
    pub root: RootSource,
    /// Virtual CPU count.
    pub cpus: u8,
    /// Guest memory in MiB.
    pub memory_mib: u32,
    /// Writable root disk in MiB.
    pub disk_mib: u32,
    /// Guest user.
    pub user: Option<String>,
    /// Guest security mode.
    pub security: SecurityMode,
    /// Effective network mode.
    pub network: NetworkMode,
    /// Policy-approved custom/dependency egress rules.
    pub network_rules: Vec<NetworkRule>,
    /// Effective project exposure mode.
    pub project_mode: ProjectMode,
    /// Guest growth quota for a writable project mount.
    pub rw_mount_quota_mib: Option<u32>,
    /// Effective command timeout.
    pub timeout: Option<Duration>,
    /// Effective session TTL.
    pub ttl: Duration,
    /// Maximum host-permitted TTL.
    pub max_ttl: Duration,
    /// Explicit guest environment.
    pub env: Vec<(String, String)>,
    /// Loopback port publications.
    pub ports: Vec<PortMapping>,
    /// In-memory output tail bytes.
    pub memory_tail_bytes: usize,
    /// Artifact byte cap.
    pub max_artifact_bytes: u64,
    /// Project walker limits.
    pub transfer_limits: EffectiveTransferLimits,
    /// Wrapper-wide reserved-memory cap in MiB.
    pub max_reserved_memory_mib: u32,
}

/// Parsed transfer caps.
#[derive(Debug, Clone, Copy)]
pub struct EffectiveTransferLimits {
    /// Maximum entries.
    pub max_files: u64,
    /// Maximum bytes in one file.
    pub max_file_size: u64,
    /// Maximum total bytes.
    pub max_total_size: u64,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

impl Default for RuntimeConfig {
    fn default() -> Self {
        Self {
            backend: "microsandbox".into(),
            max_concurrent_sandboxes: 4,
            max_reserved_memory: "12G".into(),
            default_ttl: "30m".into(),
            max_ttl: "8h".into(),
        }
    }
}

impl Default for QemuConfig {
    fn default() -> Self {
        Self {
            binary: None,
            ssh_binary: None,
            ssh_user: None,
            ssh_key: None,
            boot_timeout: "2m".into(),
            shutdown_timeout: "10s".into(),
        }
    }
}

impl Default for CuttlefishConfig {
    fn default() -> Self {
        Self {
            artifacts: None,
            boot_timeout: "5m".into(),
            shutdown_timeout: "30s".into(),
        }
    }
}

impl Default for AndroidEmulatorConfig {
    fn default() -> Self {
        Self {
            sdk_root: None,
            emulator: None,
            adb: None,
            avd: None,
            boot_timeout: "5m".into(),
            shutdown_timeout: "30s".into(),
            gpu: "auto".into(),
        }
    }
}

impl Default for ProxyConfig {
    fn default() -> Self {
        Self {
            inherit_env: true,
            http: None,
            https: None,
            all: None,
            no_proxy: Vec::new(),
            inject_guest: false,
        }
    }
}

impl fmt::Debug for ProxyConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ProxyConfig")
            .field("inherit_env", &self.inherit_env)
            .field("http", &self.http.as_ref().map(|_| "<redacted>"))
            .field("https", &self.https.as_ref().map(|_| "<redacted>"))
            .field("all", &self.all.as_ref().map(|_| "<redacted>"))
            .field("no_proxy", &self.no_proxy)
            .field("inject_guest", &self.inject_guest)
            .finish()
    }
}

impl Default for NetworkConfig {
    fn default() -> Self {
        Self {
            default: "public".into(),
            allow_all_mode: false,
            allow_private_override: false,
            allow_non_loopback_publish: false,
            max_custom_rules: 64,
        }
    }
}

impl Default for WorkspaceConfig {
    fn default() -> Self {
        Self {
            roots: Vec::new(),
            allow_rw_mount: false,
            rw_mount_quota: "2G".into(),
        }
    }
}

impl Default for ResourceConfig {
    fn default() -> Self {
        Self {
            default_cpus: 2,
            default_memory: "2G".into(),
            default_disk: "16G".into(),
            max_cpus: 8,
            max_memory: "16G".into(),
            max_disk: "64G".into(),
        }
    }
}

impl Default for OutputConfig {
    fn default() -> Self {
        Self {
            memory_tail: "2M".into(),
            max_log_disk: "128M".into(),
            max_artifact_total: "2G".into(),
        }
    }
}

impl Default for TransferConfig {
    fn default() -> Self {
        Self {
            max_files: 100_000,
            max_file_size: "1G".into(),
            max_total_size: "8G".into(),
        }
    }
}

impl Default for CacheConfig {
    fn default() -> Self {
        Self {
            max_size: "50G".into(),
        }
    }
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl HostConfig {
    /// Load configuration from `ASBX_CONFIG` or the platform config directory.
    ///
    /// A missing file yields secure defaults. The host process environment is
    /// not forwarded to a guest unless `proxy.inject_guest` is explicitly set.
    pub fn load() -> Result<Self> {
        let path = env::var_os("ASBX_CONFIG").map(PathBuf::from).or_else(|| {
            dirs::home_dir().map(|home| home.join(".agent-sandbox").join("config.toml"))
        });
        match path {
            Some(path) if path.exists() => Self::load_from(path),
            _ => Ok(Self::default()),
        }
    }

    /// Load an explicit config file.
    pub fn load_from(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let text = fs::read_to_string(path).map_err(|source| PolicyError::ReadConfig {
            path: path.to_path_buf(),
            source,
        })?;
        let config: Self = toml::from_str(&text).map_err(|source| PolicyError::ParseConfig {
            path: path.to_path_buf(),
            source,
        })?;
        config.proxy.validate()?;
        Ok(config)
    }

    /// Validate a request and calculate all effective values.
    pub fn enforce(
        &self,
        requested: RequestedSpec,
        invocation_root: &Path,
    ) -> Result<EffectiveSpec> {
        if !matches!(
            self.runtime.backend.as_str(),
            BackendId::MICROSANDBOX
                | BackendId::QEMU
                | BackendId::CUTTLEFISH
                | BackendId::ANDROID_EMULATOR
        ) {
            return Err(PolicyError::Forbidden(format!(
                "unsupported runtime backend {:?}",
                self.runtime.backend
            )));
        }
        if !matches!(
            requested.backend.as_str(),
            BackendId::MICROSANDBOX
                | BackendId::QEMU
                | BackendId::CUTTLEFISH
                | BackendId::ANDROID_EMULATOR
        ) {
            return Err(PolicyError::Forbidden(format!(
                "unsupported runtime backend {:?}",
                requested.backend
            )));
        }
        match (requested.backend.as_str(), &requested.root) {
            (
                BackendId::MICROSANDBOX,
                RootSource::Machine(_) | RootSource::Android(_) | RootSource::AndroidEmulator(_),
            ) => {
                return Err(PolicyError::Forbidden(
                    "the selected boot source does not belong to the microsandbox backend".into(),
                ));
            }
            (
                BackendId::QEMU,
                RootSource::Image(_)
                | RootSource::Snapshot(_)
                | RootSource::Android(_)
                | RootSource::AndroidEmulator(_),
            ) => {
                return Err(PolicyError::Forbidden(
                    "the qemu backend requires a machine boot source".into(),
                ));
            }
            (
                BackendId::CUTTLEFISH,
                RootSource::Image(_)
                | RootSource::Snapshot(_)
                | RootSource::Machine(_)
                | RootSource::AndroidEmulator(_),
            ) => {
                return Err(PolicyError::Forbidden(
                    "the cuttlefish backend requires Android artifacts".into(),
                ));
            }
            (
                BackendId::ANDROID_EMULATOR,
                RootSource::Image(_)
                | RootSource::Snapshot(_)
                | RootSource::Machine(_)
                | RootSource::Android(_),
            ) => {
                return Err(PolicyError::Forbidden(
                    "the android-emulator backend requires an Android Virtual Device".into(),
                ));
            }
            _ => {}
        }
        let project =
            requested
                .project
                .canonicalize()
                .map_err(|error| PolicyError::InvalidValue {
                    field: "project",
                    value: requested.project.display().to_string(),
                    reason: error.to_string(),
                })?;
        if !project.is_dir() {
            return Err(PolicyError::InvalidValue {
                field: "project",
                value: project.display().to_string(),
                reason: "must be a directory".into(),
            });
        }
        self.authorize_project(&project, invocation_root)?;

        let cpus = requested.cpus.unwrap_or(self.resources.default_cpus);
        if cpus == 0 || cpus > self.resources.max_cpus {
            return Err(PolicyError::LimitExceeded {
                field: "cpus",
                requested: cpus.to_string(),
                maximum: self.resources.max_cpus.to_string(),
            });
        }

        let memory_mib = parse_size_mib(
            requested
                .memory
                .as_deref()
                .unwrap_or(&self.resources.default_memory),
            "memory",
        )?;
        let max_memory = parse_size_mib(&self.resources.max_memory, "max_memory")?;
        enforce_limit("memory", memory_mib, max_memory)?;

        let disk_mib = parse_size_mib(
            requested
                .disk
                .as_deref()
                .unwrap_or(&self.resources.default_disk),
            "disk",
        )?;
        let max_disk = parse_size_mib(&self.resources.max_disk, "max_disk")?;
        enforce_limit("disk", disk_mib, max_disk)?;

        let network = requested
            .network
            .unwrap_or(parse_network(&self.network.default)?);
        if network == NetworkMode::All && !self.network.allow_all_mode {
            return Err(PolicyError::Forbidden(
                "network mode 'all' is disabled by host configuration".into(),
            ));
        }
        if requested.backend.as_str() == BackendId::CUTTLEFISH
            && !matches!(network, NetworkMode::Off | NetworkMode::All)
        {
            return Err(PolicyError::Forbidden(
                "the cuttlefish backend supports network modes 'off' and host-gated 'all' only"
                    .into(),
            ));
        }
        if requested.backend.as_str() == BackendId::ANDROID_EMULATOR && network != NetworkMode::All
        {
            return Err(PolicyError::Forbidden(
                "the android-emulator backend currently supports only explicitly host-gated network mode 'all'"
                    .into(),
            ));
        }
        let network_rules = self.validate_network_rules(network, requested.network_rules)?;

        if matches!(
            requested.backend.as_str(),
            BackendId::CUTTLEFISH | BackendId::ANDROID_EMULATOR
        ) && !matches!(
            requested.project_mode,
            ProjectMode::None | ProjectMode::Copy
        ) {
            return Err(PolicyError::Forbidden(
                "Android backends support project modes 'none' and 'copy' only".into(),
            ));
        }
        if matches!(
            requested.backend.as_str(),
            BackendId::CUTTLEFISH | BackendId::ANDROID_EMULATOR
        ) && !requested.ports.is_empty()
        {
            return Err(PolicyError::Forbidden(
                "Android backends do not yet support guest port publication".into(),
            ));
        }
        if matches!(
            requested.backend.as_str(),
            BackendId::CUTTLEFISH | BackendId::ANDROID_EMULATOR
        ) && requested.security != SecurityMode::Default
        {
            return Err(PolicyError::Forbidden(
                "Android backends do not implement the restricted security profile".into(),
            ));
        }

        let rw_mount_quota_mib = match requested.project_mode {
            ProjectMode::None | ProjectMode::Copy | ProjectMode::MountReadOnly => None,
            ProjectMode::MountReadWrite => {
                if !self.workspace.allow_rw_mount {
                    return Err(PolicyError::Forbidden(
                        "project mode 'mount-rw' is disabled by host configuration".into(),
                    ));
                }
                let quota = parse_size_mib(&self.workspace.rw_mount_quota, "rw_mount_quota")?;
                if quota == 0 {
                    return Err(PolicyError::InvalidValue {
                        field: "rw_mount_quota",
                        value: self.workspace.rw_mount_quota.clone(),
                        reason: "must be greater than zero".into(),
                    });
                }
                Some(quota)
            }
        };

        let default_ttl = parse_duration(&self.runtime.default_ttl)?;
        let max_ttl = parse_duration(&self.runtime.max_ttl)?;
        let ttl = requested.ttl.unwrap_or(default_ttl);
        if ttl.is_zero() || ttl > max_ttl {
            return Err(PolicyError::LimitExceeded {
                field: "ttl",
                requested: format_duration(ttl),
                maximum: format_duration(max_ttl),
            });
        }

        validate_environment(&requested.env)?;
        let mut environment = requested.env;
        if self.proxy.inject_guest {
            let proxy = self.proxy.environment()?;
            inject_environment(&mut environment, "HTTP_PROXY", proxy.http());
            inject_environment(&mut environment, "HTTPS_PROXY", proxy.https());
            inject_environment(&mut environment, "ALL_PROXY", proxy.all());
            inject_environment(&mut environment, "NO_PROXY", proxy.no_proxy());
        }

        let memory_tail = parse_bytes(&self.output.memory_tail, "memory_tail")?;
        let memory_tail_bytes =
            usize::try_from(memory_tail).map_err(|_| PolicyError::InvalidValue {
                field: "memory_tail",
                value: self.output.memory_tail.clone(),
                reason: "does not fit this host's address space".into(),
            })?;

        Ok(EffectiveSpec {
            backend: requested.backend,
            project,
            root: requested.root,
            cpus,
            memory_mib,
            disk_mib,
            user: requested.user,
            security: requested.security,
            network,
            network_rules,
            project_mode: requested.project_mode,
            rw_mount_quota_mib,
            timeout: requested.timeout,
            ttl,
            max_ttl,
            env: environment,
            ports: requested.ports,
            memory_tail_bytes,
            max_artifact_bytes: parse_bytes(&self.output.max_artifact_total, "max_artifact_total")?,
            transfer_limits: EffectiveTransferLimits {
                max_files: self.transfer.max_files,
                max_file_size: parse_bytes(&self.transfer.max_file_size, "max_file_size")?,
                max_total_size: parse_bytes(&self.transfer.max_total_size, "max_total_size")?,
            },
            max_reserved_memory_mib: parse_size_mib(
                &self.runtime.max_reserved_memory,
                "max_reserved_memory",
            )?,
        })
    }

    fn authorize_project(&self, project: &Path, invocation_root: &Path) -> Result<()> {
        let configured = if self.workspace.roots.is_empty() {
            vec![invocation_root.to_path_buf()]
        } else {
            self.workspace.roots.clone()
        };
        let roots: Vec<PathBuf> = configured
            .iter()
            .filter_map(|root| root.canonicalize().ok())
            .collect();
        if roots.iter().any(|root| project.starts_with(root)) {
            return Ok(());
        }
        Err(PolicyError::WorkspaceDenied {
            project: project.to_path_buf(),
            roots: roots
                .iter()
                .map(|root| root.display().to_string())
                .collect::<Vec<_>>()
                .join(", "),
        })
    }

    fn validate_network_rules(
        &self,
        mode: NetworkMode,
        mut rules: Vec<NetworkRule>,
    ) -> Result<Vec<NetworkRule>> {
        if rules.len() > self.network.max_custom_rules {
            return Err(PolicyError::LimitExceeded {
                field: "network rule count",
                requested: rules.len().to_string(),
                maximum: self.network.max_custom_rules.to_string(),
            });
        }
        if !matches!(mode, NetworkMode::Rules | NetworkMode::Dependencies) && !rules.is_empty() {
            return Err(PolicyError::InvalidValue {
                field: "network rules",
                value: format!("{} rule(s)", rules.len()),
                reason: "rules require --network rules or --network dependencies".into(),
            });
        }
        if mode == NetworkMode::Rules && rules.is_empty() {
            return Err(PolicyError::InvalidValue {
                field: "network rules",
                value: "empty".into(),
                reason: "--network rules requires at least one allow or deny rule".into(),
            });
        }
        for rule in &mut rules {
            validate_network_rule(rule, self.network.allow_private_override)?;
            normalize_network_rule(rule);
        }
        rules.sort_by_key(|rule| match rule.action {
            NetworkRuleAction::Deny => 0_u8,
            NetworkRuleAction::Allow => 1,
        });
        Ok(rules)
    }
}

impl ProxyConfig {
    /// Resolve explicit settings over optional process-environment values.
    pub fn environment(&self) -> Result<ProxyEnvironment> {
        self.environment_with(|upper, lower| env::var(upper).ok().or_else(|| env::var(lower).ok()))
    }

    /// Whether applying this configuration requires a clean child process.
    pub fn requires_reexec(&self) -> bool {
        !self.inherit_env
            || self.http.is_some()
            || self.https.is_some()
            || self.all.is_some()
            || !self.no_proxy.is_empty()
    }

    fn validate(&self) -> Result<()> {
        if let Some(value) = self.http.as_deref() {
            validate_proxy_url("proxy.http", value)?;
        }
        if let Some(value) = self.https.as_deref() {
            validate_proxy_url("proxy.https", value)?;
        }
        if let Some(value) = self.all.as_deref() {
            validate_proxy_url("proxy.all", value)?;
        }
        for value in &self.no_proxy {
            let valid = !value.is_empty()
                && value.trim() == value
                && !value.contains(',')
                && !value.chars().any(char::is_control);
            if !valid {
                return Err(PolicyError::InvalidValue {
                    field: "proxy.no_proxy",
                    value: value.clone(),
                    reason: "entries must be non-empty, comma-free values without surrounding whitespace"
                        .into(),
                });
            }
        }
        Ok(())
    }

    fn environment_with(
        &self,
        read: impl Fn(&str, &str) -> Option<String>,
    ) -> Result<ProxyEnvironment> {
        self.validate()?;
        let inherited = |upper, lower| self.inherit_env.then(|| read(upper, lower)).flatten();
        Ok(ProxyEnvironment {
            http: self
                .http
                .clone()
                .or_else(|| inherited("HTTP_PROXY", "http_proxy")),
            https: self
                .https
                .clone()
                .or_else(|| inherited("HTTPS_PROXY", "https_proxy")),
            all: self
                .all
                .clone()
                .or_else(|| inherited("ALL_PROXY", "all_proxy")),
            no_proxy: if self.no_proxy.is_empty() {
                inherited("NO_PROXY", "no_proxy")
            } else {
                Some(self.no_proxy.join(","))
            },
        })
    }
}

impl ProxyEnvironment {
    /// Effective `HTTP_PROXY`.
    pub fn http(&self) -> Option<&str> {
        self.http.as_deref()
    }

    /// Effective `HTTPS_PROXY`.
    pub fn https(&self) -> Option<&str> {
        self.https.as_deref()
    }

    /// Effective `ALL_PROXY`.
    pub fn all(&self) -> Option<&str> {
        self.all.as_deref()
    }

    /// Effective `NO_PROXY`.
    pub fn no_proxy(&self) -> Option<&str> {
        self.no_proxy.as_deref()
    }

    /// Whether no HTTP proxy is active.
    pub fn is_direct(&self) -> bool {
        self.http.is_none() && self.https.is_none() && self.all.is_none()
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn validate_proxy_url(field: &'static str, value: &str) -> Result<()> {
    let valid = Url::parse(value).ok().is_some_and(|url| {
        matches!(url.scheme(), "http" | "https")
            && url.host().is_some()
            && url.path() == "/"
            && url.query().is_none()
            && url.fragment().is_none()
    });
    if !valid {
        return Err(PolicyError::InvalidValue {
            field,
            value: "<redacted>".into(),
            reason: "expected an absolute http:// or https:// proxy URL with a host".into(),
        });
    }
    Ok(())
}

fn inject_environment(environment: &mut Vec<(String, String)>, key: &str, value: Option<&str>) {
    if let Some(value) = value
        && !environment
            .iter()
            .any(|(existing, _)| existing.eq_ignore_ascii_case(key))
    {
        environment.push((key.into(), value.into()));
    }
}

/// Parse a duration using `ms`, `s`, `m`, `h`, or `d`.
pub fn parse_duration(value: &str) -> Result<Duration> {
    let split = value
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(value.len());
    let (number, unit) = value.split_at(split);
    let amount = number
        .parse::<u64>()
        .map_err(|_| PolicyError::InvalidValue {
            field: "duration",
            value: value.into(),
            reason: "expected a positive integer followed by ms, s, m, h, or d".into(),
        })?;
    let millis = match unit {
        "ms" => amount,
        "s" | "" => amount.saturating_mul(1_000),
        "m" => amount.saturating_mul(60_000),
        "h" => amount.saturating_mul(3_600_000),
        "d" => amount.saturating_mul(86_400_000),
        _ => {
            return Err(PolicyError::InvalidValue {
                field: "duration",
                value: value.into(),
                reason: "expected ms, s, m, h, or d".into(),
            });
        }
    };
    Ok(Duration::from_millis(millis))
}

/// Parse byte units with binary multipliers.
pub fn parse_bytes(value: &str, field: &'static str) -> Result<u64> {
    let normalized = value.trim().to_ascii_uppercase();
    let split = normalized
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(normalized.len());
    let (number, unit) = normalized.split_at(split);
    let amount = number
        .parse::<u64>()
        .map_err(|_| PolicyError::InvalidValue {
            field,
            value: value.into(),
            reason: "expected an integer and optional K, M, G, or T suffix".into(),
        })?;
    let multiplier = match unit.trim_end_matches('B') {
        "" => 1,
        "K" | "KI" => 1024,
        "M" | "MI" => 1024_u64.pow(2),
        "G" | "GI" => 1024_u64.pow(3),
        "T" | "TI" => 1024_u64.pow(4),
        _ => {
            return Err(PolicyError::InvalidValue {
                field,
                value: value.into(),
                reason: "expected K, M, G, or T suffix".into(),
            });
        }
    };
    amount
        .checked_mul(multiplier)
        .ok_or_else(|| PolicyError::InvalidValue {
            field,
            value: value.into(),
            reason: "size overflows u64".into(),
        })
}

fn parse_size_mib(value: &str, field: &'static str) -> Result<u32> {
    let bytes = parse_bytes(value, field)?;
    let mib = bytes.div_ceil(1024_u64.pow(2));
    u32::try_from(mib).map_err(|_| PolicyError::InvalidValue {
        field,
        value: value.into(),
        reason: "size exceeds the backend MiB range".into(),
    })
}

fn parse_network(value: &str) -> Result<NetworkMode> {
    match value {
        "off" => Ok(NetworkMode::Off),
        "public" => Ok(NetworkMode::Public),
        "dependencies" => Ok(NetworkMode::Dependencies),
        "rules" => Ok(NetworkMode::Rules),
        "all" => Ok(NetworkMode::All),
        _ => Err(PolicyError::InvalidValue {
            field: "network.default",
            value: value.into(),
            reason: "expected off, public, dependencies, rules, or all".into(),
        }),
    }
}

fn validate_network_rule(rule: &NetworkRule, allow_private_override: bool) -> Result<()> {
    match &rule.target {
        NetworkRuleTarget::Domain(value) | NetworkRuleTarget::DomainSuffix(value) => {
            validate_domain(value)?;
        }
        NetworkRuleTarget::Cidr(value) => {
            let network = value
                .parse::<IpNet>()
                .map_err(|error| PolicyError::InvalidValue {
                    field: "network CIDR",
                    value: value.clone(),
                    reason: error.to_string(),
                })?;
            if rule.action == NetworkRuleAction::Allow
                && !allow_private_override
                && overlaps_protected_network(network)
            {
                return Err(PolicyError::Forbidden(format!(
                    "allowing protected/private CIDR {value:?} requires network.allow_private_override = true"
                )));
            }
        }
        NetworkRuleTarget::PublicPort { start, end } => {
            if *start == 0 || start > end {
                return Err(PolicyError::InvalidValue {
                    field: "network port",
                    value: format!("{start}-{end}"),
                    reason: "ports must be an ascending range between 1 and 65535".into(),
                });
            }
        }
        NetworkRuleTarget::Private | NetworkRuleTarget::Host | NetworkRuleTarget::Metadata
            if rule.action == NetworkRuleAction::Allow && !allow_private_override =>
        {
            return Err(PolicyError::Forbidden(
                "allowing private, host, or metadata destinations requires network.allow_private_override = true"
                    .into(),
            ));
        }
        NetworkRuleTarget::Private | NetworkRuleTarget::Host | NetworkRuleTarget::Metadata => {}
    }
    Ok(())
}

fn normalize_network_rule(rule: &mut NetworkRule) {
    match &mut rule.target {
        NetworkRuleTarget::Domain(value) | NetworkRuleTarget::DomainSuffix(value) => {
            *value = value.trim_matches('.').to_ascii_lowercase();
        }
        NetworkRuleTarget::Cidr(value) => {
            *value = value
                .parse::<IpNet>()
                .expect("CIDR was validated before normalization")
                .to_string();
        }
        NetworkRuleTarget::PublicPort { .. }
        | NetworkRuleTarget::Private
        | NetworkRuleTarget::Host
        | NetworkRuleTarget::Metadata => {}
    }
}

fn validate_domain(value: &str) -> Result<()> {
    let value = value.trim_matches('.');
    let valid = !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        });
    if !valid {
        return Err(PolicyError::InvalidValue {
            field: "network domain",
            value: value.into(),
            reason: "expected an ASCII DNS name without wildcards".into(),
        });
    }
    Ok(())
}

fn overlaps_protected_network(network: IpNet) -> bool {
    const PROTECTED: &[&str] = &[
        "0.0.0.0/8",
        "10.0.0.0/8",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "224.0.0.0/4",
        "::/128",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "ff00::/8",
    ];
    PROTECTED.iter().any(|protected| {
        let protected = protected
            .parse::<IpNet>()
            .expect("hard-coded protected CIDR is valid");
        network.contains(&protected.network()) || protected.contains(&network.network())
    })
}

fn enforce_limit(field: &'static str, requested: u32, maximum: u32) -> Result<()> {
    if requested > maximum {
        return Err(PolicyError::LimitExceeded {
            field,
            requested: format!("{requested} MiB"),
            maximum: format!("{maximum} MiB"),
        });
    }
    Ok(())
}

fn validate_environment(environment: &[(String, String)]) -> Result<()> {
    let mut seen = HashSet::new();
    for (key, _) in environment {
        let valid = !key.is_empty()
            && !key.starts_with("MSB_")
            && key
                .chars()
                .all(|character| character == '_' || character.is_ascii_alphanumeric())
            && !key.starts_with(|character: char| character.is_ascii_digit());
        if !valid {
            return Err(PolicyError::InvalidValue {
                field: "env-var",
                value: key.clone(),
                reason: "expected a unique shell variable name without the reserved MSB_ prefix"
                    .into(),
            });
        }
        if !seen.insert(key) {
            return Err(PolicyError::InvalidValue {
                field: "env-var",
                value: key.clone(),
                reason: "duplicate key".into(),
            });
        }
    }
    Ok(())
}

fn format_duration(duration: Duration) -> String {
    format!("{}s", duration.as_secs())
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use agent_sandbox_runtime::{AndroidAvdSpec, AndroidBootSpec, MachineBootSpec, RootSource};
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn parses_documented_sizes_and_durations() {
        assert_eq!(parse_bytes("2G", "test").unwrap(), 2 * 1024_u64.pow(3));
        assert_eq!(parse_duration("30m").unwrap(), Duration::from_secs(1800));
    }

    #[test]
    fn example_config_includes_valid_android_emulator_defaults() {
        let config: HostConfig =
            toml::from_str(include_str!("../../../config.example.toml")).unwrap();
        assert_eq!(config.android_emulator.boot_timeout, "5m");
        assert_eq!(config.android_emulator.gpu, "auto");
    }

    #[test]
    fn invocation_root_is_the_default_boundary() {
        let root = tempdir().unwrap();
        let project = root.path().join("project");
        fs::create_dir(&project).unwrap();
        let request = request(project);
        assert!(HostConfig::default().enforce(request, root.path()).is_ok());
    }

    #[test]
    fn writable_mount_requires_explicit_host_gate_and_gets_a_quota() {
        let root = tempdir().unwrap();
        let project = root.path().join("project");
        fs::create_dir(&project).unwrap();
        let mut requested = request(project.clone());
        requested.project_mode = ProjectMode::MountReadWrite;
        assert!(matches!(
            HostConfig::default().enforce(requested.clone(), root.path()),
            Err(PolicyError::Forbidden(_))
        ));

        let mut config = HostConfig::default();
        config.workspace.allow_rw_mount = true;
        config.workspace.rw_mount_quota = "512M".into();
        let effective = config.enforce(requested, root.path()).unwrap();
        assert_eq!(effective.rw_mount_quota_mib, Some(512));
    }

    #[test]
    fn network_denies_are_ordered_before_allows() {
        let root = tempdir().unwrap();
        let project = root.path().join("project");
        fs::create_dir(&project).unwrap();
        let mut requested = request(project);
        requested.network = Some(NetworkMode::Rules);
        requested.network_rules = vec![
            NetworkRule {
                action: NetworkRuleAction::Allow,
                target: NetworkRuleTarget::DomainSuffix(".EXAMPLE.COM.".into()),
            },
            NetworkRule {
                action: NetworkRuleAction::Deny,
                target: NetworkRuleTarget::Domain("blocked.example.com".into()),
            },
        ];
        let effective = HostConfig::default()
            .enforce(requested, root.path())
            .unwrap();
        assert_eq!(effective.network_rules[0].action, NetworkRuleAction::Deny);
        assert_eq!(
            effective.network_rules[1].target,
            NetworkRuleTarget::DomainSuffix("example.com".into())
        );
    }

    #[test]
    fn protected_cidr_requires_explicit_host_gate() {
        let root = tempdir().unwrap();
        let project = root.path().join("project");
        fs::create_dir(&project).unwrap();
        let mut requested = request(project);
        requested.network = Some(NetworkMode::Rules);
        requested.network_rules.push(NetworkRule {
            action: NetworkRuleAction::Allow,
            target: NetworkRuleTarget::Cidr("169.254.169.254/32".into()),
        });
        assert!(matches!(
            HostConfig::default().enforce(requested, root.path()),
            Err(PolicyError::Forbidden(_))
        ));
    }

    #[test]
    fn backend_and_boot_source_must_match() {
        let root = tempdir().unwrap();
        let project = root.path().join("project");
        fs::create_dir(&project).unwrap();
        let mut requested = request(project.clone());
        requested.backend = BackendId::qemu();
        assert!(matches!(
            HostConfig::default().enforce(requested, root.path()),
            Err(PolicyError::Forbidden(_))
        ));

        let mut requested = request(project);
        requested.backend = BackendId::qemu();
        requested.root = RootSource::Machine(Box::new(MachineBootSpec {
            architecture: "aarch64".into(),
            machine: None,
            cpu: None,
            accelerator: None,
            disk: None,
            kernel: Some(PathBuf::from("Image")),
            initrd: None,
            dtb: None,
            firmware: None,
            kernel_append: vec![],
            debug: None,
        }));
        requested.project_mode = ProjectMode::None;
        requested.network = Some(NetworkMode::Off);
        let effective = HostConfig::default()
            .enforce(requested, root.path())
            .unwrap();
        assert_eq!(effective.backend, BackendId::qemu());
    }

    #[test]
    fn cuttlefish_accepts_android_artifacts_with_offline_copy_mode() {
        let root = tempdir().unwrap();
        let project = root.path().join("project");
        fs::create_dir(&project).unwrap();
        let mut requested = request(project);
        requested.backend = BackendId::cuttlefish();
        requested.root = RootSource::Android(Box::new(AndroidBootSpec {
            artifacts: PathBuf::from("/opt/android/cuttlefish"),
        }));
        requested.network = Some(NetworkMode::Off);

        let effective = HostConfig::default()
            .enforce(requested, root.path())
            .unwrap();
        assert_eq!(effective.backend, BackendId::cuttlefish());
        assert_eq!(effective.network, NetworkMode::Off);
        assert_eq!(effective.project_mode, ProjectMode::Copy);
    }

    #[test]
    fn cuttlefish_rejects_filtered_network_and_host_mounts() {
        let root = tempdir().unwrap();
        let project = root.path().join("project");
        fs::create_dir(&project).unwrap();
        let mut requested = request(project);
        requested.backend = BackendId::cuttlefish();
        requested.root = RootSource::Android(Box::new(AndroidBootSpec {
            artifacts: PathBuf::from("/opt/android/cuttlefish"),
        }));
        requested.network = Some(NetworkMode::Public);
        assert!(matches!(
            HostConfig::default().enforce(requested.clone(), root.path()),
            Err(PolicyError::Forbidden(_))
        ));

        requested.network = Some(NetworkMode::Off);
        requested.project_mode = ProjectMode::MountReadOnly;
        assert!(matches!(
            HostConfig::default().enforce(requested, root.path()),
            Err(PolicyError::Forbidden(_))
        ));
    }

    #[test]
    fn android_emulator_requires_host_gated_unrestricted_networking() {
        let root = tempdir().unwrap();
        let project = root.path().join("project");
        fs::create_dir(&project).unwrap();
        let mut requested = request(project);
        requested.backend = BackendId::android_emulator();
        requested.root = RootSource::AndroidEmulator(Box::new(AndroidAvdSpec {
            name: "TestPhone".into(),
        }));
        requested.network = Some(NetworkMode::All);

        assert!(matches!(
            HostConfig::default().enforce(requested.clone(), root.path()),
            Err(PolicyError::Forbidden(_))
        ));

        let mut config = HostConfig::default();
        config.network.allow_all_mode = true;
        let effective = config.enforce(requested, root.path()).unwrap();
        assert_eq!(effective.backend, BackendId::android_emulator());
        assert_eq!(effective.network, NetworkMode::All);
        assert_eq!(effective.project_mode, ProjectMode::Copy);
    }

    #[test]
    fn android_emulator_rejects_filtered_network_and_host_mounts() {
        let root = tempdir().unwrap();
        let project = root.path().join("project");
        fs::create_dir(&project).unwrap();
        let mut requested = request(project);
        requested.backend = BackendId::android_emulator();
        requested.root = RootSource::AndroidEmulator(Box::new(AndroidAvdSpec {
            name: "TestPhone".into(),
        }));
        requested.network = Some(NetworkMode::Off);
        assert!(matches!(
            HostConfig::default().enforce(requested.clone(), root.path()),
            Err(PolicyError::Forbidden(_))
        ));

        let mut config = HostConfig::default();
        config.network.allow_all_mode = true;
        requested.network = Some(NetworkMode::All);
        requested.project_mode = ProjectMode::MountReadOnly;
        assert!(matches!(
            config.enforce(requested, root.path()),
            Err(PolicyError::Forbidden(_))
        ));
    }

    #[test]
    fn explicit_proxy_settings_override_inherited_values() {
        let proxy = ProxyConfig {
            inherit_env: true,
            http: Some("http://127.0.0.1:7890".into()),
            https: None,
            all: None,
            no_proxy: vec!["localhost".into(), "127.0.0.1".into()],
            inject_guest: false,
        };
        let environment = proxy
            .environment_with(|upper, _| Some(format!("http://inherited-{upper}:8080")))
            .unwrap();

        assert_eq!(environment.http(), Some("http://127.0.0.1:7890"));
        assert_eq!(
            environment.https(),
            Some("http://inherited-HTTPS_PROXY:8080")
        );
        assert_eq!(environment.all(), Some("http://inherited-ALL_PROXY:8080"));
        assert_eq!(environment.no_proxy(), Some("localhost,127.0.0.1"));
    }

    #[test]
    fn invalid_proxy_urls_are_rejected_without_exposing_credentials() {
        let proxy = ProxyConfig {
            http: Some("socks5://secret:token@127.0.0.1:7891".into()),
            ..ProxyConfig::default()
        };
        let error = match proxy.environment() {
            Ok(_) => panic!("SOCKS proxy unexpectedly passed validation"),
            Err(error) => error.to_string(),
        };
        assert!(error.contains("proxy.http"));
        assert!(!error.contains("secret"));
        assert!(!error.contains("token"));
    }

    #[test]
    fn guest_proxy_injection_preserves_explicit_guest_values() {
        let root = tempdir().unwrap();
        let project = root.path().join("project");
        fs::create_dir(&project).unwrap();
        let mut requested = request(project);
        requested
            .env
            .push(("http_proxy".into(), "http://guest-explicit:8080".into()));

        let config = HostConfig {
            proxy: ProxyConfig {
                inherit_env: false,
                http: Some("http://host-proxy:7890".into()),
                https: Some("http://host-proxy:7890".into()),
                no_proxy: vec!["localhost".into()],
                inject_guest: true,
                ..ProxyConfig::default()
            },
            ..HostConfig::default()
        };

        let effective = config.enforce(requested, root.path()).unwrap();
        assert!(
            effective
                .env
                .contains(&("http_proxy".into(), "http://guest-explicit:8080".into()))
        );
        assert!(!effective.env.iter().any(|(key, _)| key == "HTTP_PROXY"));
        assert!(
            effective
                .env
                .contains(&("HTTPS_PROXY".into(), "http://host-proxy:7890".into()))
        );
        assert!(
            effective
                .env
                .contains(&("NO_PROXY".into(), "localhost".into()))
        );
    }

    fn request(project: PathBuf) -> RequestedSpec {
        RequestedSpec {
            backend: BackendId::microsandbox(),
            root: RootSource::Image("alpine".into()),
            project,
            cpus: None,
            memory: None,
            disk: None,
            user: None,
            security: SecurityMode::Default,
            network: None,
            network_rules: vec![],
            project_mode: ProjectMode::Copy,
            timeout: None,
            ttl: None,
            env: vec![],
            ports: vec![],
        }
    }
}
