//! Agent Sandbox orchestration and lifecycle management.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet, VecDeque},
    net::{Ipv4Addr, TcpListener},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use agent_sandbox_cache::{CacheEntry, CacheKind, PrunePlan, plan_prune};
use agent_sandbox_environment::{
    EnvironmentBuild, EnvironmentRequest, ResolvedEnvironment, build_request, pin_base_digest,
    provisioning_script, resolve, toolchain_expressions,
};
use agent_sandbox_policy::{EffectiveSpec, HostConfig, RequestedSpec};
use agent_sandbox_runtime::{
    BackendId, CreateSpec, DebugContext, ExecRequest, ExecStream, ImageInfo, MachineBootSpec,
    NetworkMode, NetworkRule, NetworkRuleAction, NetworkRuleTarget, PortMapping, ProjectMode,
    RootSource, SandboxInfo, SandboxRuntime, SecurityMode, WorkspaceSpec,
};
use agent_sandbox_state::{
    EnvironmentRecord, ReservationRecord, SessionRecord, StateError, StateStore,
};
use agent_sandbox_transfer::{Entry, TransferLimits, TransferPlan};
use chrono::Utc;
use serde::Serialize;
use ulid::Ulid;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Core operation result type.
pub type Result<T> = std::result::Result<T, CoreError>;

/// Orchestration error.
#[derive(Debug, thiserror::Error)]
pub enum CoreError {
    /// Host policy rejected the request.
    #[error(transparent)]
    Policy(#[from] agent_sandbox_policy::PolicyError),
    /// Environment resolution failed.
    #[error(transparent)]
    Environment(#[from] agent_sandbox_environment::EnvironmentError),
    /// Static environment detection failed.
    #[error(transparent)]
    Detect(#[from] agent_sandbox_detector::DetectError),
    /// Runtime backend failed.
    #[error(transparent)]
    Runtime(#[from] agent_sandbox_runtime::RuntimeError),
    /// Wrapper state failed.
    #[error(transparent)]
    State(#[from] agent_sandbox_state::StateError),
    /// Project traversal failed.
    #[error(transparent)]
    Transfer(#[from] agent_sandbox_transfer::TransferError),
    /// Session metadata serialization failed.
    #[error("cannot serialize session metadata: {0}")]
    Json(#[from] serde_json::Error),
    /// A host I/O operation failed.
    #[error("{operation} {path}: {source}")]
    Io {
        /// Operation description.
        operation: &'static str,
        /// Affected path.
        path: PathBuf,
        /// Filesystem error.
        source: std::io::Error,
    },
    /// A guest or host path violated its boundary.
    #[error("{0}")]
    UnsafePath(String),
    /// Cleanup failed after both graceful and forceful attempts.
    #[error("cannot clean up sandbox {id}: {message}")]
    Cleanup {
        /// Sandbox identifier.
        id: String,
        /// Runtime detail.
        message: String,
    },
    /// The requested lifecycle transition is ambiguous or unsafe.
    #[error("{0}")]
    InvalidOperation(String),
}

/// CLI-level sandbox options before environment and host policy resolution.
#[derive(Debug, Clone)]
pub struct SandboxOptions {
    /// Explicit backend, or the host-configured default.
    pub backend: Option<BackendId>,
    /// Explicit full-system machine boot inputs.
    pub machine: Option<MachineBootSpec>,
    /// Project directory.
    pub project: PathBuf,
    /// Explicit OCI image.
    pub image: Option<String>,
    /// Explicit Microsandbox snapshot.
    pub snapshot: Option<String>,
    /// `auto` or a `LANG@VERSION` expression.
    pub environment: Option<String>,
    /// Virtual CPU request.
    pub cpus: Option<u8>,
    /// Memory size request.
    pub memory: Option<String>,
    /// Writable disk request.
    pub disk: Option<String>,
    /// Guest user.
    pub user: Option<String>,
    /// Guest security profile.
    pub security: SecurityMode,
    /// Network mode.
    pub network: Option<NetworkMode>,
    /// Explicit custom network rules.
    pub network_rules: Vec<NetworkRule>,
    /// Project copy or mount mode.
    pub project_mode: ProjectMode,
    /// Command timeout.
    pub timeout: Option<Duration>,
    /// Sandbox TTL.
    pub ttl: Option<Duration>,
    /// Explicit guest environment variables.
    pub env: Vec<(String, String)>,
    /// Requested published ports.
    pub ports: Vec<RequestedPort>,
}

/// Guest port with an optional fixed host loopback port.
#[derive(Debug, Clone, Copy)]
pub struct RequestedPort {
    /// Guest TCP port.
    pub guest_port: u16,
    /// Host loopback port, or random when absent.
    pub host_port: Option<u16>,
}

/// Result of creating a one-shot or persistent sandbox.
#[derive(Debug, Clone, Serialize)]
pub struct OpenedSandbox {
    /// Sandbox identifier.
    pub id: String,
    /// Selected runtime backend.
    pub backend: BackendId,
    /// Resolved root source.
    pub root: RootSource,
    /// Effective project exposure mode.
    pub project_mode: ProjectMode,
    /// Effective network mode.
    pub network: NetworkMode,
    /// Published loopback ports.
    pub ports: Vec<PortMapping>,
    /// Effective wrapper lease TTL.
    #[serde(skip)]
    pub ttl: Duration,
    /// Bounded output-tail capacity.
    #[serde(skip)]
    pub memory_tail_bytes: usize,
}

/// Resource and reproducibility inputs for a managed environment build.
#[derive(Debug, Clone)]
pub struct EnvironmentBuildOptions {
    /// User-facing environment name.
    pub name: String,
    /// Base OCI image.
    pub base: String,
    /// One or more `LANG@VERSION` toolchains.
    pub toolchains: Vec<String>,
    /// Builder virtual CPUs.
    pub cpus: Option<u8>,
    /// Builder memory.
    pub memory: Option<String>,
    /// Builder writable root disk.
    pub disk: Option<String>,
    /// Replace an existing name or rebuild an identical cache key.
    pub force: bool,
}

/// Result of preparing a managed environment.
pub enum PreparedEnvironment {
    /// A matching healthy snapshot already exists.
    Cached(EnvironmentRecord),
    /// A builder VM is running and streaming provisioning output.
    Building(Box<EnvironmentBuilder>),
}

/// In-progress managed environment build.
pub struct EnvironmentBuilder {
    /// Builder sandbox identifier.
    pub id: String,
    /// Validated deterministic build inputs.
    pub build: EnvironmentBuild,
    /// Provisioning command stream, available exactly once.
    stream: Option<ExecStream>,
    /// Bounded output-tail capacity.
    pub memory_tail_bytes: usize,
    previous: Option<EnvironmentRecord>,
    force: bool,
}

/// Runtime and wrapper records contributing to logical cache usage.
#[derive(Debug, Clone, Serialize)]
pub struct CacheInventory {
    /// Cached OCI images.
    pub images: Vec<ImageInfo>,
    /// Named environment snapshots.
    pub environments: Vec<EnvironmentRecord>,
    /// Sum of reported logical bytes.
    pub logical_bytes: u64,
}

/// Cache pruning policy selected by a caller.
#[derive(Debug, Clone)]
pub struct CachePruneOptions {
    /// Target logical cache size.
    pub maximum_bytes: u64,
    /// Remove entries unused for at least this duration.
    pub older_than: Option<Duration>,
    /// Allow deletion of named environment snapshots.
    pub include_environments: bool,
    /// Plan without changing runtime or state.
    pub dry_run: bool,
}

/// One failed cache deletion that did not stop independent cleanup.
#[derive(Debug, Clone, Serialize)]
pub struct CachePruneFailure {
    /// Object selected by the plan.
    pub entry: CacheEntry,
    /// Runtime or state error.
    pub message: String,
}

/// Cache pruning execution report.
#[derive(Debug, Clone, Serialize)]
pub struct CachePruneReport {
    /// Deterministic LRU plan.
    pub plan: PrunePlan,
    /// Successfully removed objects.
    pub removed: Vec<CacheEntry>,
    /// Objects that could not be removed.
    pub failures: Vec<CachePruneFailure>,
    /// Best estimate after successful removals.
    pub after_bytes: u64,
    /// Whether successful deletions reached the target.
    pub target_met: bool,
    /// Whether this was non-mutating.
    pub dry_run: bool,
}

impl EnvironmentBuilder {
    /// Take ownership of the provisioning output stream.
    pub fn take_stream(&mut self) -> Result<ExecStream> {
        self.stream.take().ok_or_else(|| {
            CoreError::InvalidOperation("environment builder stream was already consumed".into())
        })
    }
}

/// Artifact metadata below `/out`.
#[derive(Debug, Clone, Serialize)]
pub struct Artifact {
    /// Absolute guest path.
    pub path: String,
    /// Regular-file size.
    pub size: u64,
    /// Unix permission bits.
    pub mode: u32,
}

/// A wrapper session with runtime status.
#[derive(Debug, Clone, Serialize)]
pub struct SessionView {
    /// Durable wrapper lease.
    pub session: SessionRecord,
    /// Runtime state when it can be inspected.
    pub runtime: Option<SandboxInfo>,
}

/// Main orchestration service.
pub struct AgentSandbox {
    runtime: Arc<dyn SandboxRuntime>,
    state: StateStore,
    config: HostConfig,
    invocation_root: PathBuf,
}

//--------------------------------------------------------------------------------------------------
// Methods
//--------------------------------------------------------------------------------------------------

impl AgentSandbox {
    /// Construct the service from explicit dependencies.
    pub fn new(
        runtime: Arc<dyn SandboxRuntime>,
        state: StateStore,
        config: HostConfig,
        invocation_root: impl AsRef<Path>,
    ) -> Result<Self> {
        let requested = invocation_root.as_ref();
        let invocation_root = requested.canonicalize().map_err(|source| CoreError::Io {
            operation: "resolve invocation root",
            path: requested.to_path_buf(),
            source,
        })?;
        Ok(Self {
            runtime,
            state,
            config,
            invocation_root,
        })
    }

    /// Detect statically declared project environments.
    pub fn detect(&self, project: impl AsRef<Path>) -> Result<agent_sandbox_detector::Detection> {
        Ok(agent_sandbox_detector::detect(project)?)
    }

    /// Prepare a reusable environment, returning a cache hit or a live builder stream.
    pub async fn prepare_environment(
        &self,
        options: EnvironmentBuildOptions,
    ) -> Result<PreparedEnvironment> {
        let mut build = build_request(&options.name, &options.base, &options.toolchains)?;
        let previous = match self.state.get_environment(&build.name) {
            Ok(record) => Some(record),
            Err(StateError::EnvironmentNotFound(_)) => None,
            Err(error) => return Err(error.into()),
        };
        let requested_toolchains = toolchain_expressions(&build);
        let same_inputs = previous.as_ref().is_some_and(|record| {
            record.base == build.base
                && record.toolchains == requested_toolchains
                && record.arch == build.arch
        });
        if previous.is_some() && !same_inputs && !options.force {
            return Err(CoreError::InvalidOperation(format!(
                "environment {:?} already exists with different build inputs; pass --force to replace it",
                build.name
            )));
        }
        let base_digest = self.cached_image_digest(&build.base).await?.or_else(|| {
            previous
                .as_ref()
                .filter(|_| same_inputs)
                .map(|record| record.base_digest.clone())
                .filter(|digest| !digest.is_empty())
        });
        if let Some(digest) = base_digest {
            build = pin_base_digest(build, &digest)?;
        }
        if let Some(record) = &previous {
            if record.cache_key != build.cache_key && !options.force {
                return Err(CoreError::InvalidOperation(format!(
                    "environment {:?} was built with a different base digest or builder manifest; pass --force to replace it",
                    build.name
                )));
            }
            if record.cache_key == build.cache_key && !options.force {
                match self
                    .runtime
                    .require_snapshot_runtime()?
                    .inspect_snapshot(&record.snapshot)
                    .await
                {
                    Ok(_) => {
                        return Ok(PreparedEnvironment::Cached(
                            self.state.touch_environment(&record.name, Utc::now())?,
                        ));
                    }
                    Err(agent_sandbox_runtime::RuntimeError::NotFound(_)) => {
                        self.state.remove_environment(&record.name)?;
                    }
                    Err(error) => return Err(error.into()),
                }
            }
        } else if !options.force && build.base_digest.is_some() {
            match self
                .runtime
                .require_snapshot_runtime()?
                .inspect_snapshot(&build.snapshot)
                .await
            {
                Ok(snapshot)
                    if snapshot.labels.get("asbx.managed").map(String::as_str)
                        == Some("environment")
                        && snapshot.labels.get("asbx.cache_key").map(String::as_str)
                            == Some(build.cache_key.as_str()) =>
                {
                    let now = Utc::now();
                    let record = EnvironmentRecord {
                        name: build.name.clone(),
                        snapshot: build.snapshot.clone(),
                        cache_key: build.cache_key.clone(),
                        base: build.base.clone(),
                        base_digest: build
                            .base_digest
                            .clone()
                            .expect("snapshot lookup requires a pinned base digest"),
                        arch: build.arch.clone(),
                        toolchains: toolchain_expressions(&build),
                        created_at: snapshot.created_at.unwrap_or(now),
                        last_used_at: now,
                        size_bytes: snapshot.size_bytes,
                    };
                    self.state.upsert_environment(&record)?;
                    return Ok(PreparedEnvironment::Cached(record));
                }
                Ok(_) => {
                    return Err(CoreError::InvalidOperation(format!(
                        "snapshot {:?} already exists but is not owned by this environment build; pass --force to replace it",
                        build.snapshot
                    )));
                }
                Err(agent_sandbox_runtime::RuntimeError::NotFound(_)) => {}
                Err(error) => return Err(error.into()),
            }
        }

        let effective = self.config.enforce(
            RequestedSpec {
                backend: BackendId::microsandbox(),
                root: RootSource::Image(build.base.clone()),
                project: self.invocation_root.clone(),
                cpus: options.cpus,
                memory: options.memory,
                disk: options.disk,
                user: None,
                security: SecurityMode::Restricted,
                network: Some(NetworkMode::Public),
                network_rules: vec![],
                project_mode: ProjectMode::Copy,
                timeout: None,
                ttl: None,
                env: vec![],
                ports: vec![],
            },
            &self.invocation_root,
        )?;
        let id = format!(
            "asbx_builder_{}",
            Ulid::new().to_string().to_ascii_lowercase()
        );
        let mut spec = runtime_spec(&id, &effective, false);
        spec.workspace = WorkspaceSpec::None;
        spec.ephemeral = false;
        let now = Utc::now();
        self.state.reserve(
            &ReservationRecord {
                id: id.clone(),
                memory_mib: effective.memory_mib,
                expires_at: now
                    + chrono::Duration::from_std(effective.ttl).unwrap_or(chrono::Duration::MAX),
                active: false,
            },
            self.config.runtime.max_concurrent_sandboxes,
            effective.max_reserved_memory_mib,
        )?;
        if let Err(error) = self.runtime.create(&spec).await {
            let _ = self.state.release(&id);
            return Err(error.into());
        }
        if let Err(error) = self.state.activate(&id) {
            let _ = self.cleanup(&id).await;
            return Err(error.into());
        }
        let digest = match self.cached_image_digest(&build.base).await {
            Ok(Some(digest)) => digest,
            Ok(None) => {
                return Err(self
                    .builder_failure(
                        &id,
                        format!(
                            "runtime did not expose a manifest digest for base image {:?}",
                            build.base
                        ),
                    )
                    .await);
            }
            Err(error) => return Err(self.builder_failure(&id, error).await),
        };
        build = match pin_base_digest(build, &digest) {
            Ok(build) => build,
            Err(error) => return Err(self.builder_failure(&id, error).await),
        };
        let stream = match self
            .runtime
            .require_command_runtime()?
            .exec_stream(
                &id,
                ExecRequest {
                    command: "/bin/sh".into(),
                    args: vec!["-c".into(), provisioning_script(&build)],
                    cwd: Some("/".into()),
                    user: Some("root".into()),
                    env: vec![],
                    timeout: Some(effective.ttl),
                    tty: false,
                },
            )
            .await
        {
            Ok(stream) => stream,
            Err(error) => {
                let _ = self.cleanup(&id).await;
                return Err(error.into());
            }
        };
        Ok(PreparedEnvironment::Building(Box::new(
            EnvironmentBuilder {
                id,
                build,
                stream: Some(stream),
                memory_tail_bytes: effective.memory_tail_bytes,
                previous,
                force: options.force,
            },
        )))
    }

    /// Snapshot a successfully provisioned builder and register it for reuse.
    pub async fn finalize_environment(
        &self,
        builder: EnvironmentBuilder,
    ) -> Result<EnvironmentRecord> {
        let toolchains = toolchain_expressions(&builder.build);
        let labels = BTreeMap::from([
            ("asbx.managed".into(), "environment".into()),
            ("asbx.environment".into(), builder.build.name.clone()),
            ("asbx.cache_key".into(), builder.build.cache_key.clone()),
            ("asbx.base".into(), builder.build.base.clone()),
            (
                "asbx.base_digest".into(),
                builder
                    .build
                    .base_digest
                    .clone()
                    .expect("environment builders always pin their base digest"),
            ),
            ("asbx.arch".into(), builder.build.arch.clone()),
            (
                "asbx.toolchains".into(),
                serde_json::to_string(&toolchains)
                    .expect("toolchain expressions always serialize to JSON"),
            ),
        ]);
        if let Err(error) = self.runtime.stop(&builder.id).await {
            return Err(self.builder_failure(&builder.id, error).await);
        }
        if builder.force {
            match self
                .runtime
                .require_snapshot_runtime()?
                .inspect_snapshot(&builder.build.snapshot)
                .await
            {
                Ok(_) => {
                    if let Err(error) = self
                        .runtime
                        .require_snapshot_runtime()?
                        .remove_snapshot(&builder.build.snapshot)
                        .await
                    {
                        return Err(self.builder_failure(&builder.id, error).await);
                    }
                }
                Err(agent_sandbox_runtime::RuntimeError::NotFound(_)) => {}
                Err(error) => return Err(self.builder_failure(&builder.id, error).await),
            }
        }
        let snapshot = match self
            .runtime
            .require_snapshot_runtime()?
            .create_snapshot(&builder.build.snapshot, &builder.id, &labels)
            .await
        {
            Ok(snapshot) => snapshot,
            Err(error) => {
                return Err(self.builder_failure(&builder.id, error).await);
            }
        };
        self.cleanup(&builder.id).await?;
        let now = Utc::now();
        let record = EnvironmentRecord {
            name: builder.build.name,
            snapshot: snapshot.name,
            cache_key: builder.build.cache_key,
            base: builder.build.base,
            base_digest: builder
                .build
                .base_digest
                .expect("environment builders always pin their base digest"),
            arch: builder.build.arch,
            toolchains,
            created_at: snapshot.created_at.unwrap_or(now),
            last_used_at: now,
            size_bytes: snapshot.size_bytes,
        };
        self.state.upsert_environment(&record)?;
        if let Some(previous) = builder.previous
            && previous.snapshot != record.snapshot
        {
            match self
                .runtime
                .require_snapshot_runtime()?
                .remove_snapshot(&previous.snapshot)
                .await
            {
                Ok(()) | Err(agent_sandbox_runtime::RuntimeError::NotFound(_)) => {}
                Err(error) => {
                    tracing::warn!(
                        snapshot = %previous.snapshot,
                        error = %error,
                        "new environment is ready but the replaced snapshot could not be removed"
                    );
                }
            }
        }
        Ok(record)
    }

    /// Remove a failed or cancelled environment builder.
    pub async fn abort_environment(&self, id: &str) -> Result<()> {
        self.cleanup(id).await
    }

    /// List reusable managed environments by LRU order.
    pub fn list_environments(&self) -> Result<Vec<EnvironmentRecord>> {
        Ok(self.state.list_environments()?)
    }

    /// Inspect one reusable managed environment.
    pub async fn inspect_environment(&self, name: &str) -> Result<EnvironmentRecord> {
        let record = self.state.get_environment(name)?;
        self.runtime
            .require_snapshot_runtime()?
            .inspect_snapshot(&record.snapshot)
            .await?;
        Ok(record)
    }

    /// Remove one managed environment snapshot and its registry entry.
    pub async fn remove_environment(&self, name: &str) -> Result<()> {
        let record = self.state.get_environment(name)?;
        match self
            .runtime
            .require_snapshot_runtime()?
            .remove_snapshot(&record.snapshot)
            .await
        {
            Ok(()) | Err(agent_sandbox_runtime::RuntimeError::NotFound(_)) => {}
            Err(error) => return Err(error.into()),
        }
        self.state.remove_environment(name)?;
        Ok(())
    }

    /// Collect logical runtime cache metadata without walking backend internals.
    pub async fn cache_inventory(&self) -> Result<CacheInventory> {
        let images = self.runtime.require_image_runtime()?.list_images().await?;
        let environments = self.state.list_environments()?;
        let logical_bytes = images
            .iter()
            .map(|image| image.size_bytes)
            .chain(
                environments
                    .iter()
                    .map(|environment| environment.size_bytes),
            )
            .fold(0_u64, u64::saturating_add);
        Ok(CacheInventory {
            images,
            environments,
            logical_bytes,
        })
    }

    /// Apply deterministic age and LRU cache pruning through runtime APIs.
    pub async fn prune_cache(&self, options: CachePruneOptions) -> Result<CachePruneReport> {
        let inventory = self.cache_inventory().await?;
        let mut protected_bases = inventory
            .environments
            .iter()
            .map(|environment| environment.base.clone())
            .collect::<BTreeSet<_>>();
        let mut protected_base_digests = inventory
            .environments
            .iter()
            .map(|environment| environment.base_digest.clone())
            .filter(|digest| !digest.is_empty())
            .collect::<BTreeSet<_>>();
        for snapshot in self
            .runtime
            .require_snapshot_runtime()?
            .list_snapshots()
            .await?
        {
            protected_bases.insert(snapshot.image);
            protected_base_digests.insert(snapshot.image_manifest_digest);
        }
        let epoch = chrono::DateTime::<Utc>::UNIX_EPOCH;
        let mut entries = inventory
            .images
            .iter()
            .map(|image| CacheEntry {
                kind: CacheKind::Image,
                key: image.reference.clone(),
                size_bytes: image.size_bytes,
                last_used_at: image.last_used_at.or(image.created_at).unwrap_or(epoch),
                protected: protected_bases.contains(&image.reference)
                    || image
                        .manifest_digest
                        .as_ref()
                        .is_some_and(|digest| protected_base_digests.contains(digest)),
            })
            .collect::<Vec<_>>();
        entries.extend(inventory.environments.iter().map(|environment| CacheEntry {
            kind: CacheKind::Environment,
            key: environment.name.clone(),
            size_bytes: environment.size_bytes,
            last_used_at: environment.last_used_at,
            protected: !options.include_environments,
        }));
        let cutoff = options.older_than.map(|age| {
            Utc::now() - chrono::Duration::from_std(age).unwrap_or(chrono::Duration::MAX)
        });
        let plan = plan_prune(&entries, options.maximum_bytes, cutoff);
        if options.dry_run {
            return Ok(CachePruneReport {
                after_bytes: plan.projected_bytes,
                target_met: plan.target_met,
                plan,
                removed: vec![],
                failures: vec![],
                dry_run: true,
            });
        }

        let mut removed = Vec::new();
        let mut failures = Vec::new();
        for entry in &plan.selected {
            let result = match entry.kind {
                CacheKind::Environment => self.remove_environment(&entry.key).await,
                CacheKind::Image => self
                    .runtime
                    .require_image_runtime()?
                    .remove_image(&entry.key)
                    .await
                    .map_err(CoreError::from),
            };
            match result {
                Ok(()) => removed.push(entry.clone()),
                Err(error) => failures.push(CachePruneFailure {
                    entry: entry.clone(),
                    message: error.to_string(),
                }),
            }
        }
        let removed_bytes = removed
            .iter()
            .map(|entry| entry.size_bytes)
            .fold(0_u64, u64::saturating_add);
        let after_bytes = plan.before_bytes.saturating_sub(removed_bytes);
        Ok(CachePruneReport {
            target_met: after_bytes <= options.maximum_bytes,
            plan,
            removed,
            failures,
            after_bytes,
            dry_run: false,
        })
    }

    /// Create a one-shot sandbox. The caller must invoke [`cleanup`](Self::cleanup).
    pub async fn create_one_shot(&self, options: SandboxOptions) -> Result<OpenedSandbox> {
        self.create(options, false, false).await
    }

    /// Create and persist a detached session.
    pub async fn open(&self, options: SandboxOptions) -> Result<OpenedSandbox> {
        let opened = self.create(options, true, true).await?;
        Ok(opened)
    }

    /// Start a streaming guest command.
    pub async fn exec(&self, id: &str, request: ExecRequest) -> Result<ExecStream> {
        Ok(self
            .runtime
            .require_command_runtime()?
            .exec_stream(id, request)
            .await?)
    }

    /// Attach the current terminal to a guest command.
    pub async fn attach(&self, id: &str, request: ExecRequest) -> Result<i32> {
        Ok(self
            .runtime
            .require_terminal_runtime()?
            .attach(id, request)
            .await?)
    }

    /// Resolve a typed remote-debugging context for an open session.
    pub async fn debug_context(&self, id: &str) -> Result<DebugContext> {
        self.require_session(id)?;
        Ok(self
            .runtime
            .require_debug_runtime()?
            .debug_context(id)
            .await?)
    }

    /// Ensure a durable session exists before operating on it.
    pub fn require_session(&self, id: &str) -> Result<SessionRecord> {
        Ok(self.state.get(id)?)
    }

    /// Close a persistent session and remove its lease.
    pub async fn close(&self, id: &str) -> Result<()> {
        self.require_session(id)?;
        self.cleanup(id).await?;
        self.state.remove(id)?;
        Ok(())
    }

    /// Stop and remove runtime state using graceful then forceful cleanup.
    pub async fn cleanup(&self, id: &str) -> Result<()> {
        let runtime_result = async {
            let status = match self.runtime.inspect(id).await {
                Ok(info) => info.status,
                Err(agent_sandbox_runtime::RuntimeError::NotFound(_)) => return Ok(()),
                Err(error) => return Err(error.into()),
            };
            let terminal = matches!(status.as_str(), "created" | "stopped" | "crashed");
            if !terminal
                && let Err(stop_error) = self.runtime.stop(id).await
                && !matches!(
                    stop_error,
                    agent_sandbox_runtime::RuntimeError::NotFound(_)
                )
            {
                match self.runtime.kill(id).await {
                    Ok(()) | Err(agent_sandbox_runtime::RuntimeError::NotFound(_)) => {}
                    Err(kill_error) => {
                        return Err(CoreError::Cleanup {
                            id: id.into(),
                            message: format!(
                                "graceful stop failed ({stop_error}); force kill failed ({kill_error})"
                            ),
                        });
                    }
                }
            }
            if let Err(remove_error) = self.runtime.remove(id).await {
                match self.runtime.inspect(id).await {
                    Err(agent_sandbox_runtime::RuntimeError::NotFound(_)) => {}
                    Ok(_) => {
                        return Err(CoreError::Cleanup {
                            id: id.into(),
                            message: remove_error.to_string(),
                        });
                    }
                    Err(inspect_error) => {
                        return Err(CoreError::Cleanup {
                            id: id.into(),
                            message: format!(
                                "remove failed ({remove_error}); cannot verify cleanup ({inspect_error})"
                            ),
                        });
                    }
                }
            }
            Ok(())
        }
        .await;
        runtime_result?;
        self.state.release(id)?;
        Ok(())
    }

    /// Reconcile expired leases left by earlier wrapper processes.
    pub async fn reconcile(&self) -> Result<Vec<String>> {
        let now = Utc::now();
        let mut expired = BTreeSet::new();
        expired.extend(
            self.state
                .expired(now)?
                .into_iter()
                .map(|session| session.id),
        );
        expired.extend(
            self.state
                .expired_reservations(now)?
                .into_iter()
                .map(|reservation| reservation.id),
        );
        expired.extend(
            self.state
                .orphaned_reservations()?
                .into_iter()
                .map(|reservation| reservation.id),
        );
        let active = self.state.active_reservations()?;
        for reservation in active {
            match self.runtime.inspect(&reservation.id).await {
                Ok(sandbox) if sandbox.is_active() => {}
                Ok(_) | Err(agent_sandbox_runtime::RuntimeError::NotFound(_)) => {
                    expired.insert(reservation.id);
                }
                Err(error) => return Err(error.into()),
            }
        }
        let mut removed = Vec::new();
        for id in expired {
            self.cleanup(&id).await?;
            self.state.remove(&id)?;
            removed.push(id);
        }
        Ok(removed)
    }

    /// Extend a wrapper lease within its original host maximum.
    pub fn touch(&self, id: &str, ttl: Duration) -> Result<SessionRecord> {
        Ok(self.state.touch(id, ttl, Utc::now())?)
    }

    /// List wrapper sessions and correlate them with runtime state.
    pub async fn list(&self) -> Result<Vec<SessionView>> {
        let mut views = Vec::new();
        for session in self.state.list()? {
            let runtime = self.runtime.inspect(&session.id).await.ok();
            views.push(SessionView { session, runtime });
        }
        Ok(views)
    }

    /// Inspect one wrapper session.
    pub async fn inspect(&self, id: &str) -> Result<SessionView> {
        let session = self.require_session(id)?;
        let runtime = self.runtime.inspect(id).await.ok();
        Ok(SessionView { session, runtime })
    }

    /// Return published port mappings for a session.
    pub fn ports(&self, id: &str) -> Result<Vec<PortMapping>> {
        Ok(self
            .require_session(id)?
            .ports
            .into_iter()
            .map(|(guest_port, host_port)| PortMapping {
                guest_port,
                host_port,
            })
            .collect())
    }

    /// Recursively list regular artifacts without following symlinks.
    pub async fn artifacts(&self, id: &str) -> Result<Vec<Artifact>> {
        self.require_session(id)?;
        let mut pending = VecDeque::from(["/out".to_owned()]);
        let mut artifacts = Vec::new();
        let mut total = 0_u64;
        let transfer = self.runtime.require_file_transfer_runtime()?;
        while let Some(directory) = pending.pop_front() {
            for entry in transfer.list_dir(id, &directory).await? {
                let path = guest_child_path(&directory, &entry.path)?;
                if entry.symlink {
                    return Err(CoreError::UnsafePath(format!(
                        "artifact symlink is not downloadable: {path}"
                    )));
                }
                if entry.directory {
                    pending.push_back(path);
                } else {
                    total = total.saturating_add(entry.size);
                    if total > self.artifact_limit()? {
                        return Err(CoreError::UnsafePath(format!(
                            "artifact total exceeds configured limit of {} bytes",
                            self.artifact_limit()?
                        )));
                    }
                    artifacts.push(Artifact {
                        path,
                        size: entry.size,
                        mode: entry.mode,
                    });
                }
            }
        }
        artifacts.sort_by(|left, right| left.path.cmp(&right.path));
        Ok(artifacts)
    }

    /// Download one regular artifact to an authorized workspace path.
    pub async fn get_artifact(
        &self,
        id: &str,
        guest_path: &str,
        destination: impl AsRef<Path>,
    ) -> Result<()> {
        self.require_session(id)?;
        validate_artifact_path(guest_path)?;
        let artifact = self
            .artifacts(id)
            .await?
            .into_iter()
            .find(|artifact| artifact.path == guest_path)
            .ok_or_else(|| {
                CoreError::UnsafePath(format!("artifact does not exist: {guest_path}"))
            })?;
        if artifact.size > self.artifact_limit()? {
            return Err(CoreError::UnsafePath(format!(
                "artifact exceeds configured limit: {} bytes",
                artifact.size
            )));
        }

        let destination = destination.as_ref();
        let parent = destination.parent().unwrap_or_else(|| Path::new("."));
        let canonical_parent = parent.canonicalize().map_err(|source| CoreError::Io {
            operation: "resolve artifact destination",
            path: parent.to_path_buf(),
            source,
        })?;
        if !self.path_is_authorized(&canonical_parent) {
            return Err(CoreError::UnsafePath(format!(
                "artifact destination {} is outside authorized workspace roots",
                destination.display()
            )));
        }
        self.runtime
            .require_file_transfer_runtime()?
            .get_file(id, guest_path, destination)
            .await?;
        Ok(())
    }

    /// Run backend host-readiness checks.
    pub async fn doctor(&self) -> Result<Vec<(String, bool, String)>> {
        Ok(self.runtime.doctor().await?)
    }

    /// Access the host configuration.
    pub fn config(&self) -> &HostConfig {
        &self.config
    }

    async fn create(
        &self,
        options: SandboxOptions,
        detached: bool,
        persist_session: bool,
    ) -> Result<OpenedSandbox> {
        let backend = match options.backend.clone() {
            Some(backend) => backend,
            None => BackendId::new(self.config.runtime.backend.clone())?,
        };
        let requested_network = options.network;
        let mut network_rules = options.network_rules;
        if requested_network == Some(NetworkMode::Dependencies) {
            network_rules.extend(dependency_network_rules(&options.project)?);
        }
        if options.machine.is_some()
            && (options.image.is_some()
                || options.snapshot.is_some()
                || options
                    .environment
                    .as_deref()
                    .is_some_and(|value| value != "auto"))
        {
            return Err(CoreError::InvalidOperation(
                "machine boot inputs cannot be combined with --image, --snapshot, or --env".into(),
            ));
        }
        let named_environment =
            if options.machine.is_none() && options.image.is_none() && options.snapshot.is_none() {
                options
                    .environment
                    .as_deref()
                    .filter(|expression| *expression != "auto" && !expression.contains('@'))
                    .map(str::to_owned)
            } else {
                None
            };
        let (resolved, named_record) = if let Some(machine) = options.machine {
            (
                ResolvedEnvironment {
                    root: RootSource::Machine(Box::new(machine)),
                    detection: None,
                    source: "machine boot specification".into(),
                },
                None,
            )
        } else if let Some(name) = named_environment {
            let record = self.state.get_environment(&name)?;
            self.runtime
                .require_snapshot_runtime()?
                .inspect_snapshot(&record.snapshot)
                .await?;
            (
                ResolvedEnvironment {
                    root: RootSource::Snapshot(record.snapshot.clone()),
                    detection: None,
                    source: format!("managed environment {name:?}"),
                },
                Some(record),
            )
        } else {
            (
                resolve(
                    &EnvironmentRequest {
                        image: options.image,
                        snapshot: options.snapshot,
                        environment: options.environment,
                    },
                    &options.project,
                )?,
                None,
            )
        };
        let ports = resolve_ports(options.ports)?;
        let effective = self.config.enforce(
            RequestedSpec {
                backend: backend.clone(),
                root: resolved.root.clone(),
                project: options.project,
                cpus: options.cpus,
                memory: options.memory,
                disk: options.disk,
                user: options.user,
                security: options.security,
                network: requested_network,
                network_rules,
                project_mode: options.project_mode,
                timeout: options.timeout,
                ttl: options.ttl,
                env: options.env,
                ports: ports.clone(),
            },
            &self.invocation_root,
        )?;
        let transfer = build_transfer_plan(&effective)?;
        let id = format!(
            "sbx_{}_{}",
            backend.as_str(),
            Ulid::new().to_string().to_ascii_lowercase()
        );
        let create_spec = runtime_spec(&id, &effective, detached);
        let now = Utc::now();
        let reservation = ReservationRecord {
            id: id.clone(),
            memory_mib: effective.memory_mib,
            expires_at: now
                + chrono::Duration::from_std(effective.ttl).unwrap_or(chrono::Duration::MAX),
            active: false,
        };
        self.state.reserve(
            &reservation,
            self.config.runtime.max_concurrent_sandboxes,
            effective.max_reserved_memory_mib,
        )?;
        if let Err(error) = self.runtime.create(&create_spec).await {
            let _ = self.state.release(&id);
            return Err(error.into());
        }
        if let Err(error) = self.state.activate(&id) {
            let _ = self.cleanup(&id).await;
            return Err(error.into());
        }

        if effective.project_mode != ProjectMode::None
            && let Err(error) = self.prepare_workspace(&id, transfer.as_ref()).await
        {
            let _ = self.cleanup(&id).await;
            return Err(error);
        }
        if let Some(record) = named_record
            && let Err(error) = self.state.touch_environment(&record.name, Utc::now())
        {
            let _ = self.cleanup(&id).await;
            return Err(error.into());
        }

        if persist_session {
            let record = SessionRecord {
                id: id.clone(),
                backend: backend.clone(),
                project: effective.project.clone(),
                root: root_description(&resolved),
                created_at: now,
                expires_at: now
                    + chrono::Duration::from_std(effective.ttl).unwrap_or(chrono::Duration::MAX),
                maximum_expires_at: now
                    + chrono::Duration::from_std(effective.max_ttl)
                        .unwrap_or(chrono::Duration::MAX),
                ports: ports
                    .iter()
                    .map(|port| (port.guest_port, port.host_port))
                    .collect(),
            };
            if let Err(error) = self.state.insert(&record) {
                let _ = self.cleanup(&id).await;
                return Err(error.into());
            }
        }

        Ok(OpenedSandbox {
            id,
            backend,
            root: resolved.root,
            project_mode: effective.project_mode,
            network: effective.network,
            ports,
            ttl: effective.ttl,
            memory_tail_bytes: effective.memory_tail_bytes,
        })
    }

    async fn prepare_workspace(&self, id: &str, plan: Option<&TransferPlan>) -> Result<()> {
        let transfer = self.runtime.require_file_transfer_runtime()?;
        if plan.is_some() {
            transfer.mkdir(id, "/workspace").await?;
        }
        transfer.mkdir(id, "/out").await?;
        let Some(plan) = plan else {
            return Ok(());
        };
        for entry in &plan.entries {
            match entry {
                Entry::Directory { path, mode } => {
                    let guest = guest_project_path(path)?;
                    transfer.mkdir(id, &guest).await?;
                    transfer.set_mode(id, &guest, *mode).await?;
                }
                Entry::File {
                    path, source, mode, ..
                } => {
                    transfer
                        .put_file(id, source, &guest_project_path(path)?, *mode)
                        .await?;
                }
                Entry::Symlink { path, target } => {
                    let target = guest_symlink_target(path, target)?;
                    transfer
                        .symlink(id, &target, &guest_project_path(path)?)
                        .await?;
                }
            }
        }
        Ok(())
    }

    fn artifact_limit(&self) -> Result<u64> {
        Ok(agent_sandbox_policy::parse_bytes(
            &self.config.output.max_artifact_total,
            "max_artifact_total",
        )?)
    }

    fn path_is_authorized(&self, path: &Path) -> bool {
        let roots = if self.config.workspace.roots.is_empty() {
            vec![self.invocation_root.clone()]
        } else {
            self.config
                .workspace
                .roots
                .iter()
                .filter_map(|root| root.canonicalize().ok())
                .collect()
        };
        roots.iter().any(|root| path.starts_with(root))
    }

    async fn builder_failure(&self, id: &str, primary: impl std::fmt::Display) -> CoreError {
        let primary = primary.to_string();
        match self.cleanup(id).await {
            Ok(()) => CoreError::InvalidOperation(primary),
            Err(cleanup) => CoreError::InvalidOperation(format!(
                "{primary}; additionally failed to clean up builder {id}: {cleanup}"
            )),
        }
    }

    async fn cached_image_digest(&self, reference: &str) -> Result<Option<String>> {
        Ok(self
            .runtime
            .require_image_runtime()?
            .list_images()
            .await?
            .into_iter()
            .find(|image| image.reference == reference)
            .and_then(|image| image.manifest_digest))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn build_transfer_plan(effective: &EffectiveSpec) -> Result<Option<TransferPlan>> {
    if effective.project_mode != ProjectMode::Copy {
        return Ok(None);
    }
    Ok(Some(agent_sandbox_transfer::plan(
        &effective.project,
        TransferLimits {
            max_entries: effective.transfer_limits.max_files,
            max_file_size: effective.transfer_limits.max_file_size,
            max_total_size: effective.transfer_limits.max_total_size,
        },
    )?))
}

fn runtime_spec(id: &str, effective: &EffectiveSpec, detached: bool) -> CreateSpec {
    let workspace = match effective.project_mode {
        ProjectMode::None => WorkspaceSpec::None,
        ProjectMode::Copy => WorkspaceSpec::Copy,
        ProjectMode::MountReadOnly => WorkspaceSpec::Mount {
            host: effective.project.clone(),
            read_only: true,
            write_quota_mib: None,
        },
        ProjectMode::MountReadWrite => WorkspaceSpec::Mount {
            host: effective.project.clone(),
            read_only: false,
            write_quota_mib: effective.rw_mount_quota_mib,
        },
    };
    CreateSpec {
        id: id.into(),
        backend: effective.backend.clone(),
        root: effective.root.clone(),
        cpus: effective.cpus,
        memory_mib: effective.memory_mib,
        disk_mib: effective.disk_mib,
        user: effective.user.clone(),
        security: effective.security,
        network: effective.network,
        network_rules: effective.network_rules.clone(),
        workspace,
        env: effective.env.clone(),
        ports: effective.ports.clone(),
        max_duration: if detached {
            effective.max_ttl
        } else {
            effective.ttl
        },
        ephemeral: true,
        detached,
    }
}

fn dependency_network_rules(project: &Path) -> Result<Vec<NetworkRule>> {
    let detection = agent_sandbox_detector::detect(project)?;
    let mut domains = BTreeSet::new();
    for language in detection.languages {
        match language.name.as_str() {
            "go" => {
                domains.extend([
                    "proxy.golang.org",
                    "sum.golang.org",
                    "storage.googleapis.com",
                ]);
            }
            "rust" => {
                domains.extend([
                    "crates.io",
                    "index.crates.io",
                    "static.crates.io",
                    "github.com",
                    "objects.githubusercontent.com",
                ]);
            }
            "node" | "typescript" => {
                domains.insert("registry.npmjs.org");
            }
            _ => {}
        }
    }
    Ok(domains
        .into_iter()
        .map(|domain| NetworkRule {
            action: NetworkRuleAction::Allow,
            target: NetworkRuleTarget::DomainSuffix(domain.into()),
        })
        .collect())
}

fn resolve_ports(requested: Vec<RequestedPort>) -> Result<Vec<PortMapping>> {
    requested
        .into_iter()
        .map(|port| {
            if port.guest_port == 0 {
                return Err(CoreError::UnsafePath(
                    "guest publish port must be between 1 and 65535".into(),
                ));
            }
            let host_port = match port.host_port {
                Some(0) | None => allocate_loopback_port()?,
                Some(port) => port,
            };
            Ok(PortMapping {
                guest_port: port.guest_port,
                host_port,
            })
        })
        .collect()
}

fn allocate_loopback_port() -> Result<u16> {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).map_err(|source| CoreError::Io {
        operation: "allocate loopback port",
        path: PathBuf::from("127.0.0.1:0"),
        source,
    })?;
    listener
        .local_addr()
        .map(|address| address.port())
        .map_err(|source| CoreError::Io {
            operation: "read allocated loopback port",
            path: PathBuf::from("127.0.0.1:0"),
            source,
        })
}

fn guest_project_path(relative: &Path) -> Result<String> {
    let mut components = Vec::new();
    for component in relative.components() {
        match component {
            Component::Normal(value) => components.push(value.to_str().ok_or_else(|| {
                CoreError::UnsafePath(format!("non-UTF-8 project path {}", relative.display()))
            })?),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err(CoreError::UnsafePath(format!(
                    "invalid relative project path {}",
                    relative.display()
                )));
            }
        }
    }
    Ok(format!("/workspace/{}", components.join("/")))
}

fn guest_symlink_target(link: &Path, target: &Path) -> Result<String> {
    let mut components = Vec::new();
    for component in target.components() {
        match component {
            Component::Normal(value) => components.push(
                value
                    .to_str()
                    .ok_or_else(|| {
                        CoreError::UnsafePath(format!(
                            "non-UTF-8 symlink target in {}",
                            link.display()
                        ))
                    })?
                    .to_owned(),
            ),
            Component::ParentDir => components.push("..".into()),
            Component::CurDir => {}
            Component::RootDir | Component::Prefix(_) => {
                return Err(CoreError::UnsafePath(format!(
                    "non-portable symlink target in {}",
                    link.display()
                )));
            }
        }
    }
    Ok(if components.is_empty() {
        ".".into()
    } else {
        components.join("/")
    })
}

fn guest_child_path(parent: &str, entry_path: &str) -> Result<String> {
    let path = if entry_path.starts_with('/') {
        entry_path.to_owned()
    } else {
        format!("{}/{}", parent.trim_end_matches('/'), entry_path)
    };
    validate_artifact_path(&path)?;
    Ok(path)
}

fn validate_artifact_path(path: &str) -> Result<()> {
    let relative = path.strip_prefix("/out/").unwrap_or_default();
    if relative.is_empty()
        || relative
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(CoreError::UnsafePath(format!(
            "artifact path must be an absolute regular file below /out: {path}"
        )));
    }
    Ok(())
}

fn root_description(resolved: &ResolvedEnvironment) -> String {
    match &resolved.root {
        RootSource::Image(image) => format!("image:{image}"),
        RootSource::Snapshot(snapshot) => format!("snapshot:{snapshot}"),
        RootSource::Machine(machine) => format!(
            "machine:{}:{}",
            machine.architecture,
            machine
                .disk
                .as_ref()
                .map(|disk| disk.path.display().to_string())
                .or_else(|| {
                    machine
                        .kernel
                        .as_ref()
                        .map(|kernel| kernel.display().to_string())
                })
                .unwrap_or_else(|| "unconfigured".into())
        ),
        _ => "backend-defined".into(),
    }
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use std::{
        path::Path,
        sync::{Arc, Mutex},
    };

    use agent_sandbox_runtime::{
        BackendCapabilities, BootSourceKind, CommandRuntime, ExecEvent, FileTransferRuntime,
        GuestEntry, ImageInfo, ImageRuntime, Result as RuntimeResult, RuntimeError, RuntimeFeature,
        SandboxRuntime, SnapshotInfo, SnapshotRuntime, TerminalRuntime,
    };
    use async_trait::async_trait;
    use tempfile::tempdir;
    use tokio::sync::mpsc;

    use super::*;

    #[derive(Debug, Default)]
    struct MockState {
        existing: bool,
        inspect_error: bool,
        created: Option<CreateSpec>,
        snapshots: BTreeMap<String, SnapshotInfo>,
        images: Vec<ImageInfo>,
        removed_images: Vec<String>,
        uploaded: Vec<String>,
        operations: Vec<String>,
    }

    #[derive(Debug, Default)]
    struct MockRuntime {
        state: Mutex<MockState>,
    }

    #[async_trait]
    impl SandboxRuntime for MockRuntime {
        fn backend_id(&self) -> BackendId {
            BackendId::microsandbox()
        }

        fn capabilities(&self) -> BackendCapabilities {
            BackendCapabilities {
                backend: self.backend_id(),
                boot_sources: vec![BootSourceKind::OciImage],
                features: vec![
                    RuntimeFeature::Exec,
                    RuntimeFeature::Attach,
                    RuntimeFeature::FileTransfer,
                    RuntimeFeature::Snapshots,
                    RuntimeFeature::ImageCache,
                ],
                architectures: vec![],
                accelerators: vec![],
            }
        }

        fn command_runtime(&self) -> Option<&dyn CommandRuntime> {
            Some(self)
        }

        fn terminal_runtime(&self) -> Option<&dyn TerminalRuntime> {
            Some(self)
        }

        fn file_transfer_runtime(&self) -> Option<&dyn FileTransferRuntime> {
            Some(self)
        }

        fn snapshot_runtime(&self) -> Option<&dyn SnapshotRuntime> {
            Some(self)
        }

        fn image_runtime(&self) -> Option<&dyn ImageRuntime> {
            Some(self)
        }

        async fn create(&self, spec: &CreateSpec) -> RuntimeResult<SandboxInfo> {
            let mut state = self.state.lock().unwrap();
            state.existing = true;
            state.created = Some(spec.clone());
            state.operations.push("create".into());
            Ok(info(&spec.id))
        }

        async fn stop(&self, sandbox: &str) -> RuntimeResult<()> {
            self.stop_impl(sandbox).await
        }

        async fn kill(&self, sandbox: &str) -> RuntimeResult<()> {
            self.kill_impl(sandbox).await
        }

        async fn remove(&self, sandbox: &str) -> RuntimeResult<()> {
            self.remove_impl(sandbox).await
        }

        async fn list(&self) -> RuntimeResult<Vec<SandboxInfo>> {
            self.list_impl().await
        }

        async fn inspect(&self, sandbox: &str) -> RuntimeResult<SandboxInfo> {
            self.inspect_impl(sandbox).await
        }

        async fn doctor(&self) -> RuntimeResult<Vec<(String, bool, String)>> {
            self.doctor_impl().await
        }
    }

    #[async_trait]
    impl CommandRuntime for MockRuntime {
        async fn exec_stream(
            &self,
            _sandbox: &str,
            _request: ExecRequest,
        ) -> RuntimeResult<ExecStream> {
            let (sender, receiver) = mpsc::channel(2);
            sender
                .send(Ok(ExecEvent::Exited { code: 0 }))
                .await
                .unwrap();
            Ok(receiver)
        }
    }

    #[async_trait]
    impl TerminalRuntime for MockRuntime {
        async fn attach(&self, _sandbox: &str, _request: ExecRequest) -> RuntimeResult<i32> {
            Ok(0)
        }
    }

    #[async_trait]
    impl FileTransferRuntime for MockRuntime {
        async fn mkdir(&self, _sandbox: &str, guest_path: &str) -> RuntimeResult<()> {
            self.state
                .lock()
                .unwrap()
                .operations
                .push(format!("mkdir:{guest_path}"));
            Ok(())
        }

        async fn put_file(
            &self,
            _sandbox: &str,
            _host_path: &Path,
            guest_path: &str,
            _mode: u32,
        ) -> RuntimeResult<()> {
            self.state.lock().unwrap().uploaded.push(guest_path.into());
            Ok(())
        }

        async fn symlink(
            &self,
            _sandbox: &str,
            _target: &str,
            _guest_path: &str,
        ) -> RuntimeResult<()> {
            Ok(())
        }

        async fn set_mode(
            &self,
            _sandbox: &str,
            _guest_path: &str,
            _mode: u32,
        ) -> RuntimeResult<()> {
            Ok(())
        }

        async fn list_dir(
            &self,
            _sandbox: &str,
            _guest_path: &str,
        ) -> RuntimeResult<Vec<GuestEntry>> {
            Ok(vec![])
        }

        async fn get_file(
            &self,
            _sandbox: &str,
            _guest_path: &str,
            _host_path: &Path,
        ) -> RuntimeResult<()> {
            Ok(())
        }
    }

    impl MockRuntime {
        async fn stop_impl(&self, _sandbox: &str) -> RuntimeResult<()> {
            self.state.lock().unwrap().operations.push("stop".into());
            Ok(())
        }

        async fn kill_impl(&self, _sandbox: &str) -> RuntimeResult<()> {
            self.state.lock().unwrap().operations.push("kill".into());
            Ok(())
        }

        async fn remove_impl(&self, _sandbox: &str) -> RuntimeResult<()> {
            let mut state = self.state.lock().unwrap();
            state.operations.push("remove".into());
            state.existing = false;
            Ok(())
        }

        async fn list_impl(&self) -> RuntimeResult<Vec<SandboxInfo>> {
            Ok(vec![])
        }

        async fn inspect_impl(&self, sandbox: &str) -> RuntimeResult<SandboxInfo> {
            let state = self.state.lock().unwrap();
            if state.inspect_error {
                Err(RuntimeError::Backend {
                    operation: "inspect",
                    message: "backend unavailable".into(),
                })
            } else if state.existing {
                Ok(info(sandbox))
            } else {
                Err(RuntimeError::NotFound(sandbox.into()))
            }
        }

        async fn doctor_impl(&self) -> RuntimeResult<Vec<(String, bool, String)>> {
            Ok(vec![("mock".into(), true, "ready".into())])
        }
    }

    #[async_trait]
    impl SnapshotRuntime for MockRuntime {
        async fn create_snapshot(
            &self,
            name: &str,
            _sandbox: &str,
            labels: &std::collections::BTreeMap<String, String>,
        ) -> RuntimeResult<SnapshotInfo> {
            let snapshot = SnapshotInfo {
                name: name.into(),
                digest: format!("sha256:{name}"),
                image: "mock:latest".into(),
                image_manifest_digest: format!("sha256:{}", "a".repeat(64)),
                size_bytes: 4096,
                created_at: Some(Utc::now()),
                labels: labels.clone(),
            };
            self.state
                .lock()
                .unwrap()
                .snapshots
                .insert(name.into(), snapshot.clone());
            Ok(snapshot)
        }

        async fn list_snapshots(&self) -> RuntimeResult<Vec<SnapshotInfo>> {
            Ok(self
                .state
                .lock()
                .unwrap()
                .snapshots
                .values()
                .cloned()
                .collect())
        }

        async fn inspect_snapshot(&self, name: &str) -> RuntimeResult<SnapshotInfo> {
            self.state
                .lock()
                .unwrap()
                .snapshots
                .get(name)
                .cloned()
                .ok_or_else(|| RuntimeError::NotFound(name.into()))
        }

        async fn remove_snapshot(&self, name: &str) -> RuntimeResult<()> {
            self.state.lock().unwrap().snapshots.remove(name);
            Ok(())
        }
    }

    #[async_trait]
    impl ImageRuntime for MockRuntime {
        async fn list_images(&self) -> RuntimeResult<Vec<ImageInfo>> {
            let state = self.state.lock().unwrap();
            if !state.images.is_empty() {
                return Ok(state.images.clone());
            }
            let Some(CreateSpec {
                root: RootSource::Image(reference),
                ..
            }) = state.created.as_ref()
            else {
                return Ok(vec![]);
            };
            Ok(vec![ImageInfo {
                reference: reference.clone(),
                manifest_digest: Some(format!("sha256:{}", "a".repeat(64))),
                size_bytes: 1024,
                last_used_at: Some(Utc::now()),
                created_at: Some(Utc::now()),
            }])
        }

        async fn remove_image(&self, reference: &str) -> RuntimeResult<()> {
            self.state
                .lock()
                .unwrap()
                .removed_images
                .push(reference.into());
            Ok(())
        }
    }

    #[tokio::test]
    async fn open_transfers_project_and_close_removes_runtime_and_lease() {
        let root = tempdir().unwrap();
        let project = root.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("Cargo.toml"), "[package]\nname='demo'\n").unwrap();
        std::fs::create_dir(project.join(".git")).unwrap();
        std::fs::write(project.join(".git/config"), "must not transfer").unwrap();

        let store = StateStore::open(root.path().join("state.db")).unwrap();
        let runtime = Arc::new(MockRuntime::default());
        let service = AgentSandbox::new(
            runtime.clone(),
            store.clone(),
            HostConfig::default(),
            root.path(),
        )
        .unwrap();

        let opened = service
            .open(SandboxOptions {
                backend: Some(BackendId::microsandbox()),
                machine: None,
                project,
                image: Some("alpine:3.22".into()),
                snapshot: None,
                environment: Some("auto".into()),
                cpus: None,
                memory: None,
                disk: None,
                user: None,
                security: SecurityMode::Restricted,
                network: Some(NetworkMode::Off),
                network_rules: vec![],
                project_mode: ProjectMode::Copy,
                timeout: None,
                ttl: Some(Duration::from_secs(60)),
                env: vec![("CI".into(), "1".into())],
                ports: vec![],
            })
            .await
            .unwrap();

        assert_eq!(
            store.get(&opened.id).unwrap().project.file_name().unwrap(),
            "project"
        );
        {
            let state = runtime.state.lock().unwrap();
            let created = state.created.as_ref().unwrap();
            assert!(created.detached);
            assert!(created.ephemeral);
            assert_eq!(created.network, NetworkMode::Off);
            assert_eq!(created.security, SecurityMode::Restricted);
            assert_eq!(state.uploaded, vec!["/workspace/Cargo.toml"]);
        }

        service.close(&opened.id).await.unwrap();
        assert!(store.get(&opened.id).is_err());
        let operations = &runtime.state.lock().unwrap().operations;
        assert!(operations.ends_with(&["stop".into(), "remove".into()]));
    }

    #[test]
    fn guest_artifact_paths_use_posix_rules_on_every_host() {
        for accepted in ["/out/report.txt", "/out/nested/report.txt"] {
            validate_artifact_path(accepted).unwrap();
        }
        for rejected in [
            "/out",
            "/outside/report.txt",
            "out/report.txt",
            "/out/../secret",
            "/out/./report.txt",
            "/out//report.txt",
        ] {
            assert!(validate_artifact_path(rejected).is_err(), "{rejected}");
        }
    }

    #[tokio::test]
    async fn cleanup_releases_only_after_absence_is_proven() {
        let root = tempdir().unwrap();
        let store = StateStore::open(root.path().join("state.db")).unwrap();
        let runtime = Arc::new(MockRuntime::default());
        let service = AgentSandbox::new(
            runtime.clone(),
            store.clone(),
            HostConfig::default(),
            root.path(),
        )
        .unwrap();
        let expires_at = Utc::now() + chrono::Duration::minutes(30);
        store
            .reserve(
                &ReservationRecord {
                    id: "missing".into(),
                    memory_mib: 512,
                    expires_at,
                    active: false,
                },
                1,
                1024,
            )
            .unwrap();
        service.cleanup("missing").await.unwrap();
        store
            .reserve(
                &ReservationRecord {
                    id: "replacement".into(),
                    memory_mib: 512,
                    expires_at,
                    active: false,
                },
                1,
                1024,
            )
            .unwrap();

        runtime.state.lock().unwrap().inspect_error = true;
        assert!(service.cleanup("replacement").await.is_err());
        assert!(matches!(
            store.reserve(
                &ReservationRecord {
                    id: "must_be_blocked".into(),
                    memory_mib: 1,
                    expires_at,
                    active: false,
                },
                1,
                1024,
            ),
            Err(agent_sandbox_state::StateError::ConcurrencyLimit(1))
        ));
    }

    #[tokio::test]
    async fn read_only_mount_skips_host_traversal_and_uses_canonical_path() {
        let root = tempdir().unwrap();
        let project = root.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(project.join("large.bin"), b"not copied").unwrap();
        let runtime = Arc::new(MockRuntime::default());
        let service = AgentSandbox::new(
            runtime.clone(),
            StateStore::open(root.path().join("state.db")).unwrap(),
            HostConfig::default(),
            root.path(),
        )
        .unwrap();
        let opened = service
            .create_one_shot(options(&project, ProjectMode::MountReadOnly))
            .await
            .unwrap();
        {
            let state = runtime.state.lock().unwrap();
            assert!(state.uploaded.is_empty());
            assert!(!state.operations.contains(&"mkdir:/workspace".into()));
            assert!(state.operations.contains(&"mkdir:/out".into()));
            assert_eq!(
                state.created.as_ref().unwrap().workspace,
                WorkspaceSpec::Mount {
                    host: project.canonicalize().unwrap(),
                    read_only: true,
                    write_quota_mib: None,
                }
            );
        }
        service.cleanup(&opened.id).await.unwrap();
    }

    #[tokio::test]
    async fn machine_boot_is_namespaced_and_skips_guest_workspace_setup() {
        let root = tempdir().unwrap();
        let project = root.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let kernel = root.path().join("Image");
        std::fs::write(&kernel, []).unwrap();
        let runtime = Arc::new(MockRuntime::default());
        let service = AgentSandbox::new(
            runtime.clone(),
            StateStore::open(root.path().join("state.db")).unwrap(),
            HostConfig::default(),
            root.path(),
        )
        .unwrap();
        let mut requested = options(&project, ProjectMode::None);
        requested.backend = Some(BackendId::qemu());
        requested.machine = Some(MachineBootSpec {
            architecture: "aarch64".into(),
            machine: None,
            cpu: None,
            accelerator: Some("tcg".into()),
            disk: None,
            kernel: Some(kernel),
            initrd: None,
            dtb: None,
            firmware: None,
            kernel_append: vec![],
            debug: None,
        });
        requested.image = None;
        requested.environment = None;

        let opened = service.create_one_shot(requested).await.unwrap();
        assert!(opened.id.starts_with("sbx_qemu_"));
        assert_eq!(opened.backend, BackendId::qemu());
        assert_eq!(
            runtime.state.lock().unwrap().operations,
            vec!["create".to_owned()]
        );
        service.cleanup(&opened.id).await.unwrap();
    }

    #[tokio::test]
    async fn dependency_network_is_inferred_without_running_project_code() {
        let root = tempdir().unwrap();
        let project = root.path().join("project");
        std::fs::create_dir(&project).unwrap();
        std::fs::write(
            project.join("Cargo.toml"),
            "[package]\nname='demo'\nversion='0.1.0'\n",
        )
        .unwrap();
        let runtime = Arc::new(MockRuntime::default());
        let service = AgentSandbox::new(
            runtime.clone(),
            StateStore::open(root.path().join("state.db")).unwrap(),
            HostConfig::default(),
            root.path(),
        )
        .unwrap();
        let mut requested = options(&project, ProjectMode::Copy);
        requested.network = Some(NetworkMode::Dependencies);
        let opened = service.create_one_shot(requested).await.unwrap();
        {
            let state = runtime.state.lock().unwrap();
            let created = state.created.as_ref().unwrap();
            assert_eq!(created.network, NetworkMode::Dependencies);
            assert!(created.network_rules.iter().any(|rule| {
                rule.target == NetworkRuleTarget::DomainSuffix("static.crates.io".into())
            }));
        }
        service.cleanup(&opened.id).await.unwrap();
    }

    #[tokio::test]
    async fn managed_environment_snapshots_and_then_hits_cache() {
        let root = tempdir().unwrap();
        let runtime = Arc::new(MockRuntime::default());
        let service = AgentSandbox::new(
            runtime.clone(),
            StateStore::open(root.path().join("state.db")).unwrap(),
            HostConfig::default(),
            root.path(),
        )
        .unwrap();
        let request = EnvironmentBuildOptions {
            name: "audit".into(),
            base: "ubuntu:24.04".into(),
            toolchains: vec!["go@1.24".into(), "rust@1.88".into()],
            cpus: None,
            memory: None,
            disk: None,
            force: false,
        };
        let PreparedEnvironment::Building(builder) =
            service.prepare_environment(request.clone()).await.unwrap()
        else {
            panic!("first build must provision a VM");
        };
        assert_eq!(
            runtime
                .state
                .lock()
                .unwrap()
                .created
                .as_ref()
                .unwrap()
                .workspace,
            WorkspaceSpec::None
        );
        let record = service.finalize_environment(*builder).await.unwrap();
        assert_eq!(record.toolchains, vec!["go@1.24.0", "rust@1.88.0"]);

        let PreparedEnvironment::Cached(cached) =
            service.prepare_environment(request).await.unwrap()
        else {
            panic!("second build must reuse the healthy snapshot");
        };
        assert_eq!(cached.snapshot, record.snapshot);
    }

    #[tokio::test]
    async fn cache_pruning_protects_snapshot_bases_by_manifest_digest() {
        let root = tempdir().unwrap();
        let runtime = Arc::new(MockRuntime::default());
        let service = AgentSandbox::new(
            runtime.clone(),
            StateStore::open(root.path().join("state.db")).unwrap(),
            HostConfig::default(),
            root.path(),
        )
        .unwrap();
        let digest = format!("sha256:{}", "b".repeat(64));
        {
            let mut state = runtime.state.lock().unwrap();
            state.images.push(ImageInfo {
                reference: "ubuntu:24.04".into(),
                manifest_digest: Some(digest.clone()),
                size_bytes: 1024,
                last_used_at: Some(Utc::now() - chrono::Duration::days(30)),
                created_at: Some(Utc::now() - chrono::Duration::days(30)),
            });
            state.snapshots.insert(
                "external".into(),
                SnapshotInfo {
                    name: "external".into(),
                    digest: format!("sha256:{}", "c".repeat(64)),
                    image: "docker.io/library/ubuntu:24.04".into(),
                    image_manifest_digest: digest,
                    size_bytes: 4096,
                    created_at: Some(Utc::now()),
                    labels: BTreeMap::new(),
                },
            );
        }

        let report = service
            .prune_cache(CachePruneOptions {
                maximum_bytes: 0,
                older_than: None,
                include_environments: false,
                dry_run: false,
            })
            .await
            .unwrap();
        assert!(report.plan.selected.is_empty());
        assert!(!report.target_met);
        assert!(runtime.state.lock().unwrap().removed_images.is_empty());
    }

    fn options(project: &Path, project_mode: ProjectMode) -> SandboxOptions {
        SandboxOptions {
            backend: Some(BackendId::microsandbox()),
            machine: None,
            project: project.into(),
            image: Some("alpine:3.22".into()),
            snapshot: None,
            environment: Some("auto".into()),
            cpus: None,
            memory: None,
            disk: None,
            user: None,
            security: SecurityMode::Restricted,
            network: Some(NetworkMode::Off),
            network_rules: vec![],
            project_mode,
            timeout: None,
            ttl: Some(Duration::from_secs(60)),
            env: vec![],
            ports: vec![],
        }
    }

    fn info(id: &str) -> SandboxInfo {
        SandboxInfo {
            id: id.into(),
            backend: BackendId::microsandbox(),
            status: "running".into(),
            created_at: None,
            metadata: BTreeMap::new(),
        }
    }
}
