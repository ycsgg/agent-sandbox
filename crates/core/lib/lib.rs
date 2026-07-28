//! Agent Sandbox orchestration and lifecycle management.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeSet, VecDeque},
    net::{Ipv4Addr, TcpListener},
    path::{Component, Path, PathBuf},
    sync::Arc,
    time::Duration,
};

use agent_sandbox_environment::{EnvironmentRequest, ResolvedEnvironment, resolve};
use agent_sandbox_policy::{EffectiveSpec, HostConfig, RequestedSpec};
use agent_sandbox_runtime::{
    CreateSpec, ExecRequest, ExecStream, NetworkMode, PortMapping, RootSource, SandboxInfo,
    SandboxRuntime, SecurityMode,
};
use agent_sandbox_state::{ReservationRecord, SessionRecord, StateStore};
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
}

/// CLI-level sandbox options before environment and host policy resolution.
#[derive(Debug, Clone)]
pub struct SandboxOptions {
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
    /// Resolved root source.
    pub root: RootSource,
    /// Published loopback ports.
    pub ports: Vec<PortMapping>,
    /// Effective wrapper lease TTL.
    #[serde(skip)]
    pub ttl: Duration,
    /// Bounded output-tail capacity.
    #[serde(skip)]
    pub memory_tail_bytes: usize,
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
        Ok(self.runtime.exec_stream(id, request).await?)
    }

    /// Attach the current terminal to a guest command.
    pub async fn attach(&self, id: &str, request: ExecRequest) -> Result<i32> {
        Ok(self.runtime.attach(id, request).await?)
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
        let active = self.state.active_reservations()?;
        if !active.is_empty() {
            let runtime_ids = self
                .runtime
                .list()
                .await?
                .into_iter()
                .filter(|sandbox| sandbox.status == "running")
                .map(|sandbox| sandbox.id)
                .collect::<BTreeSet<_>>();
            expired.extend(
                active
                    .into_iter()
                    .filter(|reservation| !runtime_ids.contains(&reservation.id))
                    .map(|reservation| reservation.id),
            );
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
        let runtime = self.runtime.list().await.unwrap_or_default();
        Ok(self
            .state
            .list()?
            .into_iter()
            .map(|session| SessionView {
                runtime: runtime
                    .iter()
                    .find(|sandbox| sandbox.id == session.id)
                    .cloned(),
                session,
            })
            .collect())
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
        while let Some(directory) = pending.pop_front() {
            for entry in self.runtime.list_dir(id, &directory).await? {
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
        self.runtime.get_file(id, guest_path, destination).await?;
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
        let resolved = resolve(
            &EnvironmentRequest {
                image: options.image,
                snapshot: options.snapshot,
                environment: options.environment,
            },
            &options.project,
        )?;
        let ports = resolve_ports(options.ports)?;
        let effective = self.config.enforce(
            RequestedSpec {
                root: resolved.root.clone(),
                project: options.project,
                cpus: options.cpus,
                memory: options.memory,
                disk: options.disk,
                user: options.user,
                security: options.security,
                network: options.network,
                timeout: options.timeout,
                ttl: options.ttl,
                env: options.env,
                ports: ports.clone(),
            },
            &self.invocation_root,
        )?;
        let transfer = build_transfer_plan(&effective)?;
        let id = format!("sbx_{}", Ulid::new().to_string().to_ascii_lowercase());
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

        if let Err(error) = self.transfer_project(&id, &transfer).await {
            let _ = self.cleanup(&id).await;
            return Err(error);
        }

        if persist_session {
            let record = SessionRecord {
                id: id.clone(),
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
            root: resolved.root,
            ports,
            ttl: effective.ttl,
            memory_tail_bytes: effective.memory_tail_bytes,
        })
    }

    async fn transfer_project(&self, id: &str, plan: &TransferPlan) -> Result<()> {
        self.runtime.mkdir(id, "/workspace").await?;
        self.runtime.mkdir(id, "/out").await?;
        for entry in &plan.entries {
            match entry {
                Entry::Directory { path, mode } => {
                    let guest = guest_project_path(path)?;
                    self.runtime.mkdir(id, &guest).await?;
                    self.runtime.set_mode(id, &guest, *mode).await?;
                }
                Entry::File {
                    path, source, mode, ..
                } => {
                    self.runtime
                        .put_file(id, source, &guest_project_path(path)?, *mode)
                        .await?;
                }
                Entry::Symlink { path, target } => {
                    let target = guest_symlink_target(path, target)?;
                    self.runtime
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
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn build_transfer_plan(effective: &EffectiveSpec) -> Result<TransferPlan> {
    Ok(agent_sandbox_transfer::plan(
        &effective.project,
        TransferLimits {
            max_entries: effective.transfer_limits.max_files,
            max_file_size: effective.transfer_limits.max_file_size,
            max_total_size: effective.transfer_limits.max_total_size,
        },
    )?)
}

fn runtime_spec(id: &str, effective: &EffectiveSpec, detached: bool) -> CreateSpec {
    CreateSpec {
        id: id.into(),
        root: effective.root.clone(),
        cpus: effective.cpus,
        memory_mib: effective.memory_mib,
        disk_mib: effective.disk_mib,
        user: effective.user.clone(),
        security: effective.security,
        network: effective.network,
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
        ExecEvent, GuestEntry, Result as RuntimeResult, RuntimeError, SandboxRuntime,
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
        uploaded: Vec<String>,
        operations: Vec<String>,
    }

    #[derive(Debug, Default)]
    struct MockRuntime {
        state: Mutex<MockState>,
    }

    #[async_trait]
    impl SandboxRuntime for MockRuntime {
        async fn create(&self, spec: &CreateSpec) -> RuntimeResult<SandboxInfo> {
            let mut state = self.state.lock().unwrap();
            state.existing = true;
            state.created = Some(spec.clone());
            state.operations.push("create".into());
            Ok(info(&spec.id))
        }

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

        async fn attach(&self, _sandbox: &str, _request: ExecRequest) -> RuntimeResult<i32> {
            Ok(0)
        }

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

        async fn stop(&self, _sandbox: &str) -> RuntimeResult<()> {
            self.state.lock().unwrap().operations.push("stop".into());
            Ok(())
        }

        async fn kill(&self, _sandbox: &str) -> RuntimeResult<()> {
            self.state.lock().unwrap().operations.push("kill".into());
            Ok(())
        }

        async fn remove(&self, _sandbox: &str) -> RuntimeResult<()> {
            let mut state = self.state.lock().unwrap();
            state.operations.push("remove".into());
            state.existing = false;
            Ok(())
        }

        async fn list(&self) -> RuntimeResult<Vec<SandboxInfo>> {
            Ok(vec![])
        }

        async fn inspect(&self, sandbox: &str) -> RuntimeResult<SandboxInfo> {
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

        async fn doctor(&self) -> RuntimeResult<Vec<(String, bool, String)>> {
            Ok(vec![("mock".into(), true, "ready".into())])
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

    fn info(id: &str) -> SandboxInfo {
        SandboxInfo {
            id: id.into(),
            status: "running".into(),
            created_at: None,
        }
    }
}
