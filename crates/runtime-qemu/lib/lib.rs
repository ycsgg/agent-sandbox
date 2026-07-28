//! Cross-platform QEMU full-system runtime adapter.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    fs,
    net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use agent_sandbox_runtime::{
    BackendCapabilities, BackendId, BootSourceKind, CreateSpec, ExecEvent, ExecRequest, ExecStream,
    GuestEntry, ImageInfo, OutputStream, Result, RuntimeError, RuntimeFeature, SandboxInfo,
    SandboxRuntime, SnapshotInfo, WorkspaceSpec,
};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use sysinfo::{Pid, ProcessesToUpdate, Signal, System};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::mpsc,
    time::Instant,
};

mod command;
mod qmp;
mod ssh;
mod state;

use ssh::SshTools;
use state::{MachineState, STATE_VERSION};

/// Host-side QEMU process and SSH transport configuration.
#[derive(Debug, Clone)]
pub struct QemuRuntimeConfig {
    /// Durable QEMU backend state directory.
    pub home: PathBuf,
    /// Explicit `qemu-system-*` binary, or architecture-derived lookup.
    pub binary: Option<PathBuf>,
    /// Explicit OpenSSH client.
    pub ssh_binary: Option<PathBuf>,
    /// Default SSH login; `None` disables command and file transport.
    pub ssh_user: Option<String>,
    /// Optional SSH private key.
    pub ssh_key: Option<PathBuf>,
    /// QMP and SSH readiness deadline.
    pub boot_timeout: Duration,
    /// Graceful ACPI shutdown deadline.
    pub shutdown_timeout: Duration,
}

/// Runtime adapter backed by a locally installed QEMU system emulator.
pub struct QemuRuntime {
    config: QemuRuntimeConfig,
}

struct PendingDirectory {
    path: PathBuf,
    committed: bool,
}

impl PendingDirectory {
    fn new(path: PathBuf) -> Self {
        Self {
            path,
            committed: false,
        }
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PendingDirectory {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_dir_all(&self.path);
        }
    }
}

impl QemuRuntime {
    /// Construct a QEMU backend without touching the filesystem.
    pub fn new(config: QemuRuntimeConfig) -> Result<Self> {
        if config.boot_timeout.is_zero() {
            return Err(RuntimeError::Configuration(
                "qemu.boot_timeout must be greater than zero".into(),
            ));
        }
        if config.shutdown_timeout.is_zero() {
            return Err(RuntimeError::Configuration(
                "qemu.shutdown_timeout must be greater than zero".into(),
            ));
        }
        Ok(Self { config })
    }

    fn machine_dir(&self, sandbox: &str) -> Result<PathBuf> {
        validate_sandbox_id(sandbox)?;
        Ok(self.config.home.join(sandbox))
    }

    fn state_path(&self, sandbox: &str) -> Result<PathBuf> {
        Ok(self.machine_dir(sandbox)?.join("state.json"))
    }

    fn load_state(&self, sandbox: &str) -> Result<MachineState> {
        state::load(&self.state_path(sandbox)?)
    }

    fn ssh_tools(&self) -> Result<SshTools> {
        SshTools::resolve(self.config.ssh_binary.as_deref(), Duration::from_secs(5))
    }

    async fn qmp(&self, state: &MachineState, command: &str) -> Result<serde_json::Value> {
        tokio::time::timeout(
            Duration::from_secs(5),
            qmp::execute(qmp_address(state.qmp_port), command, Duration::from_secs(2)),
        )
        .await
        .map_err(|_| RuntimeError::Backend {
            operation: "execute QMP command",
            message: format!("{command} timed out"),
        })?
    }

    async fn wait_for_qmp(&self, state: &MachineState) -> Result<()> {
        let deadline = Instant::now() + self.config.boot_timeout;
        loop {
            if !process_alive(state) {
                return Err(RuntimeError::Backend {
                    operation: "start QEMU",
                    message: format!(
                        "QEMU process {} exited before QMP became ready{}",
                        state.pid,
                        log_suffix(&state.process_log)
                    ),
                });
            }
            let last_error = match self.qmp(state, "query-status").await {
                Ok(_) => return Ok(()),
                Err(error) => error.to_string(),
            };
            if Instant::now() >= deadline {
                return Err(RuntimeError::Backend {
                    operation: "start QEMU",
                    message: format!(
                        "QMP readiness timed out: {last_error}{}",
                        log_suffix(&state.process_log)
                    ),
                });
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn remote_output(
        &self,
        sandbox: &str,
        operation: &'static str,
        remote: &str,
    ) -> Result<Vec<u8>> {
        let state = self.load_state(sandbox)?;
        let output = self.ssh_tools()?.run(&state, None, remote).await?;
        if !output.status.success() {
            return Err(RuntimeError::Backend {
                operation,
                message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
            });
        }
        Ok(output.stdout)
    }

    async fn wait_stopped(&self, state: &MachineState, timeout: Duration) -> bool {
        let deadline = Instant::now() + timeout;
        while process_alive(state) {
            if Instant::now() >= deadline {
                return false;
            }
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
        true
    }
}

#[async_trait]
impl SandboxRuntime for QemuRuntime {
    fn backend_id(&self) -> BackendId {
        BackendId::qemu()
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: self.backend_id(),
            boot_sources: vec![BootSourceKind::DiskImage, BootSourceKind::DirectKernel],
            features: vec![
                RuntimeFeature::Exec,
                RuntimeFeature::Attach,
                RuntimeFeature::FileTransfer,
                RuntimeFeature::PortForward,
                RuntimeFeature::SerialLog,
                RuntimeFeature::MachineControl,
                RuntimeFeature::GdbStub,
            ],
            architectures: vec!["x86_64".into(), "aarch64".into(), "riscv64".into()],
            accelerators: vec![
                "auto".into(),
                "kvm".into(),
                "hvf".into(),
                "whpx".into(),
                "tcg".into(),
            ],
        }
    }

    async fn create(&self, spec: &CreateSpec) -> Result<SandboxInfo> {
        if spec.backend != self.backend_id() {
            return Err(RuntimeError::Configuration(format!(
                "QEMU received a create request for backend {:?}",
                spec.backend
            )));
        }
        let directory = self.machine_dir(&spec.id)?;
        if directory.exists() {
            return Err(RuntimeError::Backend {
                operation: "create QEMU sandbox",
                message: format!("state directory {} already exists", directory.display()),
            });
        }
        fs::create_dir_all(&directory)
            .map_err(|error| state::io_error("create QEMU sandbox directory", &directory, error))?;
        secure_directory(&directory)?;
        let pending = PendingDirectory::new(directory.clone());
        let serial_log = directory.join("serial.log");
        let process_log = directory.join("qemu.log");
        let qmp_port = allocate_loopback_port()?;
        let ssh_user = spec.user.clone().or_else(|| self.config.ssh_user.clone());
        if ssh_user.is_some()
            && let Some(key) = &self.config.ssh_key
            && !key.is_file()
        {
            return Err(RuntimeError::Configuration(format!(
                "QEMU SSH key {} is not a regular file",
                key.display()
            )));
        }
        let ssh_port = if ssh_user.is_some() {
            Some(allocate_loopback_port()?)
        } else {
            None
        };
        let gdb_port = match &spec.root {
            agent_sandbox_runtime::RootSource::Machine(machine) => machine.debug.map(|debug| {
                if debug.gdb_port == 0 {
                    allocate_loopback_port()
                } else {
                    Ok(debug.gdb_port)
                }
            }),
            _ => None,
        }
        .transpose()?;
        if let Some(port) = gdb_port
            && (port == qmp_port
                || ssh_port == Some(port)
                || spec.ports.iter().any(|mapping| mapping.host_port == port))
        {
            return Err(RuntimeError::Configuration(format!(
                "QEMU GDB port {port} conflicts with another host port"
            )));
        }
        let plan = command::build(
            &self.config,
            spec,
            qmp_port,
            ssh_port,
            gdb_port,
            &serial_log,
        )?;

        let process_file = fs::File::create(&process_log)
            .map_err(|error| state::io_error("create QEMU process log", &process_log, error))?;
        let process_stderr = process_file
            .try_clone()
            .map_err(|error| state::io_error("clone QEMU process log", &process_log, error))?;
        let mut process = Command::new(&plan.binary);
        process
            .args(&plan.arguments)
            .stdin(Stdio::null())
            .stdout(Stdio::from(process_file))
            .stderr(Stdio::from(process_stderr))
            .kill_on_drop(false);
        let mut child = process.spawn().map_err(|error| RuntimeError::Backend {
            operation: "spawn QEMU",
            message: format!("{}: {error}", plan.binary.display()),
        })?;
        let Some(pid) = child.id() else {
            let _ = child.kill().await;
            return Err(RuntimeError::Backend {
                operation: "spawn QEMU",
                message: "spawned process has no PID".into(),
            });
        };
        let process_started_at = match wait_for_process_start(pid, Duration::from_secs(1)).await {
            Some(started_at) => started_at,
            None => {
                let _ = child.kill().await;
                return Err(RuntimeError::Backend {
                    operation: "spawn QEMU",
                    message: format!(
                        "cannot capture process identity for PID {pid}{}",
                        log_suffix(&process_log)
                    ),
                });
            }
        };
        // Dropping a Tokio child does not terminate it when kill_on_drop is
        // false. QMP and durable state own lifecycle from this point onward.
        let state = MachineState {
            version: STATE_VERSION,
            id: spec.id.clone(),
            pid,
            process_started_at,
            created_at: Utc::now(),
            architecture: plan.architecture,
            accelerator: plan.accelerator,
            qmp_port,
            ssh_port: plan.ssh_port,
            gdb_port: plan.gdb_port,
            ssh_user,
            ssh_key: self.config.ssh_key.clone(),
            serial_log,
            process_log,
        };
        if let Err(error) = state::save(&directory.join("state.json"), &state) {
            let _ = child.kill().await;
            return Err(error);
        }
        tokio::spawn(async move {
            let _ = child.wait().await;
        });

        if let Err(error) = self.wait_for_qmp(&state).await {
            kill_process(&state);
            return Err(error);
        }
        if matches!(spec.workspace, WorkspaceSpec::Copy) {
            let readiness = match self.ssh_tools() {
                Ok(tools) => tools.wait_ready(&state, self.config.boot_timeout).await,
                Err(error) => Err(error),
            };
            if let Err(error) = readiness {
                let _ = self.qmp(&state, "quit").await;
                kill_process(&state);
                return Err(error);
            }
        }
        let info = match self.inspect(&spec.id).await {
            Ok(info) => info,
            Err(error) => {
                let _ = self.qmp(&state, "quit").await;
                kill_process(&state);
                return Err(error);
            }
        };
        pending.commit();
        Ok(info)
    }

    async fn exec_stream(&self, sandbox: &str, request: ExecRequest) -> Result<ExecStream> {
        let state = self.load_state(sandbox)?;
        if !process_alive(&state) {
            return Err(RuntimeError::Backend {
                operation: "execute QEMU guest command",
                message: "virtual machine is not running".into(),
            });
        }
        let remote = ssh::remote_command(
            &request.command,
            &request.args,
            request.cwd.as_deref(),
            &request.env,
        );
        let mut command =
            self.ssh_tools()?
                .command(&state, request.user.as_deref(), &remote, false)?;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|error| RuntimeError::Backend {
            operation: "start QEMU guest command",
            message: error.to_string(),
        })?;
        let pid = child.id().unwrap_or(0);
        let stdout = child.stdout.take().expect("piped stdout is available");
        let stderr = child.stderr.take().expect("piped stderr is available");
        let timeout = request.timeout;
        let (sender, receiver) = mpsc::channel(64);
        tokio::spawn(async move {
            if sender.send(Ok(ExecEvent::Started { pid })).await.is_err() {
                let _ = child.kill().await;
                return;
            }
            let stdout_task =
                tokio::spawn(forward_pipe(stdout, sender.clone(), OutputStream::Stdout));
            let stderr_task =
                tokio::spawn(forward_pipe(stderr, sender.clone(), OutputStream::Stderr));
            let status = match timeout {
                Some(duration) => match tokio::time::timeout(duration, child.wait()).await {
                    Ok(status) => status,
                    Err(_) => {
                        let _ = child.kill().await;
                        let _ = child.wait().await;
                        let _ = stdout_task.await;
                        let _ = stderr_task.await;
                        let _ = sender
                            .send(Ok(ExecEvent::TimedOut {
                                after: duration,
                                sandbox_terminated: false,
                            }))
                            .await;
                        return;
                    }
                },
                None => child.wait().await,
            };
            let _ = stdout_task.await;
            let _ = stderr_task.await;
            match status {
                Ok(status) => {
                    let _ = sender
                        .send(Ok(ExecEvent::Exited {
                            code: status.code().unwrap_or(-1),
                        }))
                        .await;
                }
                Err(error) => {
                    let _ = sender.send(Ok(ExecEvent::Failed(error.to_string()))).await;
                }
            }
        });
        Ok(receiver)
    }

    async fn attach(&self, sandbox: &str, request: ExecRequest) -> Result<i32> {
        let state = self.load_state(sandbox)?;
        let remote = ssh::remote_command(
            &request.command,
            &request.args,
            request.cwd.as_deref(),
            &request.env,
        );
        let mut command =
            self.ssh_tools()?
                .command(&state, request.user.as_deref(), &remote, true)?;
        command
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let status = command
            .status()
            .await
            .map_err(|error| RuntimeError::Backend {
                operation: "attach QEMU guest terminal",
                message: error.to_string(),
            })?;
        Ok(status.code().unwrap_or(-1))
    }

    async fn mkdir(&self, sandbox: &str, guest_path: &str) -> Result<()> {
        self.remote_output(
            sandbox,
            "create QEMU guest directory",
            &format!("mkdir -p -- {}", ssh::shell_quote(guest_path)),
        )
        .await?;
        Ok(())
    }

    async fn put_file(
        &self,
        sandbox: &str,
        host_path: &Path,
        guest_path: &str,
        mode: u32,
    ) -> Result<()> {
        let state = self.load_state(sandbox)?;
        self.ssh_tools()?
            .upload(&state, host_path, guest_path)
            .await?;
        self.set_mode(sandbox, guest_path, mode).await
    }

    async fn symlink(&self, sandbox: &str, target: &str, guest_path: &str) -> Result<()> {
        self.remote_output(
            sandbox,
            "create QEMU guest symlink",
            &format!(
                "ln -s -- {} {}",
                ssh::shell_quote(target),
                ssh::shell_quote(guest_path)
            ),
        )
        .await?;
        Ok(())
    }

    async fn set_mode(&self, sandbox: &str, guest_path: &str, mode: u32) -> Result<()> {
        self.remote_output(
            sandbox,
            "set QEMU guest path mode",
            &format!("chmod {mode:o} -- {}", ssh::shell_quote(guest_path)),
        )
        .await?;
        Ok(())
    }

    async fn list_dir(&self, sandbox: &str, guest_path: &str) -> Result<Vec<GuestEntry>> {
        let output = self
            .remote_output(
                sandbox,
                "list QEMU guest directory",
                &format!(
                    "find {} -mindepth 1 -maxdepth 1 -printf '%y\\0%p\\0%s\\0%m\\0'",
                    ssh::shell_quote(guest_path)
                ),
            )
            .await?;
        parse_find_output(&output)
    }

    async fn get_file(&self, sandbox: &str, guest_path: &str, host_path: &Path) -> Result<()> {
        let state = self.load_state(sandbox)?;
        self.ssh_tools()?
            .download(&state, guest_path, host_path)
            .await
    }

    async fn stop(&self, sandbox: &str) -> Result<()> {
        let state = self.load_state(sandbox)?;
        if !process_alive(&state) {
            return Ok(());
        }
        let status = self.qmp(&state, "query-status").await?;
        let status = status
            .get("status")
            .and_then(serde_json::Value::as_str)
            .unwrap_or("unknown");
        if status != "running" {
            return Err(RuntimeError::Backend {
                operation: "stop QEMU sandbox",
                message: format!(
                    "guest status {status:?} cannot process a graceful power button; force termination is required"
                ),
            });
        }
        self.qmp(&state, "system_powerdown").await?;
        if self
            .wait_stopped(&state, self.config.shutdown_timeout)
            .await
        {
            Ok(())
        } else {
            Err(RuntimeError::Backend {
                operation: "stop QEMU sandbox",
                message: format!(
                    "guest did not power down within {:?}",
                    self.config.shutdown_timeout
                ),
            })
        }
    }

    async fn kill(&self, sandbox: &str) -> Result<()> {
        let state = self.load_state(sandbox)?;
        if !process_alive(&state) {
            return Ok(());
        }
        let _ = self.qmp(&state, "quit").await;
        if self.wait_stopped(&state, Duration::from_secs(2)).await {
            return Ok(());
        }
        if kill_process(&state) && self.wait_stopped(&state, Duration::from_secs(2)).await {
            Ok(())
        } else {
            Err(RuntimeError::Backend {
                operation: "kill QEMU sandbox",
                message: format!("could not terminate process {}", state.pid),
            })
        }
    }

    async fn remove(&self, sandbox: &str) -> Result<()> {
        let state = self.load_state(sandbox)?;
        if process_alive(&state) {
            return Err(RuntimeError::Backend {
                operation: "remove QEMU sandbox",
                message: "virtual machine is still running".into(),
            });
        }
        let directory = self.machine_dir(sandbox)?;
        fs::remove_dir_all(&directory)
            .map_err(|error| state::io_error("remove QEMU sandbox state", &directory, error))
    }

    async fn list(&self) -> Result<Vec<SandboxInfo>> {
        let entries = match fs::read_dir(&self.config.home) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(error) => {
                return Err(state::io_error(
                    "list QEMU sandbox state",
                    &self.config.home,
                    error,
                ));
            }
        };
        let mut sandboxes = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| {
                state::io_error("list QEMU sandbox state", &self.config.home, error)
            })?;
            if !entry
                .file_type()
                .map_err(|error| state::io_error("inspect QEMU state entry", &entry.path(), error))?
                .is_dir()
            {
                continue;
            }
            let id = entry.file_name().to_string_lossy().into_owned();
            match self.inspect(&id).await {
                Ok(info) => sandboxes.push(info),
                Err(RuntimeError::NotFound(_)) => {}
                Err(error) => return Err(error),
            }
        }
        sandboxes.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(sandboxes)
    }

    async fn inspect(&self, sandbox: &str) -> Result<SandboxInfo> {
        let state = self.load_state(sandbox)?;
        let status = if !process_alive(&state) {
            "stopped".into()
        } else {
            self.qmp(&state, "query-status")
                .await
                .ok()
                .and_then(|value| {
                    value
                        .get("status")
                        .and_then(serde_json::Value::as_str)
                        .map(str::to_owned)
                })
                .unwrap_or_else(|| "unknown".into())
        };
        let mut metadata = BTreeMap::from([
            ("architecture".into(), state.architecture.clone()),
            ("accelerator".into(), state.accelerator.clone()),
            ("pid".into(), state.pid.to_string()),
            ("serial_log".into(), state.serial_log.display().to_string()),
            ("qmp".into(), format!("tcp://127.0.0.1:{}", state.qmp_port)),
        ]);
        if let Some(port) = state.ssh_port {
            metadata.insert("ssh".into(), format!("127.0.0.1:{port}"));
        }
        if let Some(port) = state.gdb_port {
            metadata.insert("gdb".into(), format!("tcp://127.0.0.1:{port}"));
        }
        Ok(SandboxInfo {
            id: state.id,
            backend: self.backend_id(),
            status,
            created_at: Some(state.created_at),
            metadata,
        })
    }

    async fn doctor(&self) -> Result<Vec<(String, bool, String)>> {
        let architecture = command::normalize_architecture(std::env::consts::ARCH)
            .unwrap_or_else(|_| std::env::consts::ARCH.into());
        let candidate = self
            .config
            .binary
            .clone()
            .unwrap_or_else(|| PathBuf::from(format!("qemu-system-{architecture}")));
        let resolved = which::which(&candidate);
        let mut checks = vec![match &resolved {
            Ok(path) => (
                "QEMU / system emulator".into(),
                true,
                path.display().to_string(),
            ),
            Err(error) => (
                "QEMU / system emulator".into(),
                false,
                format!("{}: {error}", candidate.display()),
            ),
        }];
        if let Ok(binary) = &resolved {
            let output = Command::new(binary).arg("--version").output().await;
            checks.push(match output {
                Ok(output) if output.status.success() => (
                    "QEMU / version".into(),
                    true,
                    String::from_utf8_lossy(&output.stdout)
                        .lines()
                        .next()
                        .unwrap_or("version reported")
                        .into(),
                ),
                Ok(output) => (
                    "QEMU / version".into(),
                    false,
                    String::from_utf8_lossy(&output.stderr).trim().into(),
                ),
                Err(error) => ("QEMU / version".into(), false, error.to_string()),
            });
            let selected = command::resolve_accelerator("auto", &architecture);
            let output = Command::new(binary).args(["-accel", "help"]).output().await;
            checks.push(match (selected, output) {
                (Ok(selected), Ok(output)) if output.status.success() => {
                    let available = String::from_utf8_lossy(&output.stdout);
                    let available = available
                        .lines()
                        .map(str::trim)
                        .filter(|line| matches!(*line, "kvm" | "hvf" | "whpx" | "tcg"))
                        .collect::<Vec<_>>();
                    let supported = available.contains(&selected.as_str());
                    (
                        "QEMU / accelerator".into(),
                        supported,
                        format!("selected {selected}; available {}", available.join(", ")),
                    )
                }
                (Err(error), _) => ("QEMU / accelerator".into(), false, error.to_string()),
                (_, Ok(output)) => (
                    "QEMU / accelerator".into(),
                    false,
                    String::from_utf8_lossy(&output.stderr).trim().into(),
                ),
                (_, Err(error)) => ("QEMU / accelerator".into(), false, error.to_string()),
            });
        }
        if self.config.ssh_user.is_some() {
            checks.push(
                match (
                    self.config.ssh_key.as_ref().is_none_or(|key| key.is_file()),
                    self.ssh_tools(),
                ) {
                    (true, Ok(tools)) => (
                        "QEMU / SSH transport".into(),
                        true,
                        format!("ssh={}", tools.ssh.display()),
                    ),
                    (false, _) => {
                        let detail = self
                            .config
                            .ssh_key
                            .as_ref()
                            .map(|key| format!("SSH key {} is not a regular file", key.display()))
                            .unwrap_or_else(|| "SSH key configuration is invalid".into());
                        ("QEMU / SSH transport".into(), false, detail)
                    }
                    (_, Err(error)) => ("QEMU / SSH transport".into(), false, error.to_string()),
                },
            );
        } else {
            checks.push((
                "QEMU / SSH transport".into(),
                true,
                "disabled; lifecycle and serial/QMP access remain available".into(),
            ));
        }
        Ok(checks)
    }

    async fn create_snapshot(
        &self,
        _name: &str,
        _sandbox: &str,
        _labels: &BTreeMap<String, String>,
    ) -> Result<SnapshotInfo> {
        Err(RuntimeError::Unsupported(
            "QEMU managed snapshots are not implemented".into(),
        ))
    }

    async fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>> {
        Err(RuntimeError::Unsupported(
            "QEMU managed snapshots are not implemented".into(),
        ))
    }

    async fn inspect_snapshot(&self, _name: &str) -> Result<SnapshotInfo> {
        Err(RuntimeError::Unsupported(
            "QEMU managed snapshots are not implemented".into(),
        ))
    }

    async fn remove_snapshot(&self, _name: &str) -> Result<()> {
        Err(RuntimeError::Unsupported(
            "QEMU managed snapshots are not implemented".into(),
        ))
    }

    async fn list_images(&self) -> Result<Vec<ImageInfo>> {
        Ok(Vec::new())
    }

    async fn remove_image(&self, _reference: &str) -> Result<()> {
        Err(RuntimeError::Unsupported(
            "QEMU does not manage OCI images".into(),
        ))
    }
}

async fn forward_pipe<R>(mut pipe: R, sender: mpsc::Sender<Result<ExecEvent>>, stream: OutputStream)
where
    R: AsyncRead + Unpin,
{
    let mut buffer = vec![0_u8; 16 * 1024];
    let mut dropped = 0_u64;
    loop {
        let read = match pipe.read(&mut buffer).await {
            Ok(0) => break,
            Ok(read) => read,
            Err(error) => {
                let _ = sender
                    .send(Err(RuntimeError::Backend {
                        operation: "read QEMU guest command output",
                        message: error.to_string(),
                    }))
                    .await;
                return;
            }
        };
        if dropped > 0 {
            match sender.try_send(Ok(ExecEvent::OutputTruncated {
                stream,
                dropped_bytes: dropped,
            })) {
                Ok(()) => dropped = 0,
                Err(mpsc::error::TrySendError::Closed(_)) => return,
                Err(mpsc::error::TrySendError::Full(_)) => {}
            }
        }
        let event = match stream {
            OutputStream::Stdout => ExecEvent::Stdout(Bytes::copy_from_slice(&buffer[..read])),
            OutputStream::Stderr => ExecEvent::Stderr(Bytes::copy_from_slice(&buffer[..read])),
        };
        match sender.try_send(Ok(event)) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                dropped = dropped.saturating_add(read as u64);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => return,
        }
    }
    if dropped > 0 {
        let _ = sender
            .send(Ok(ExecEvent::OutputTruncated {
                stream,
                dropped_bytes: dropped,
            }))
            .await;
    }
}

fn parse_find_output(output: &[u8]) -> Result<Vec<GuestEntry>> {
    let fields = output
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    if fields.len() % 4 != 0 {
        return Err(RuntimeError::Backend {
            operation: "decode QEMU guest directory",
            message: "find output contained an incomplete record".into(),
        });
    }
    fields
        .chunks_exact(4)
        .map(|fields| {
            let kind = text_field(fields[0], "entry type")?;
            let path = text_field(fields[1], "entry path")?.to_owned();
            let size = text_field(fields[2], "entry size")?
                .parse::<u64>()
                .map_err(|error| decode_error("entry size", error))?;
            let mode = u32::from_str_radix(text_field(fields[3], "entry mode")?, 8)
                .map_err(|error| decode_error("entry mode", error))?;
            Ok(GuestEntry {
                path,
                directory: kind == "d",
                symlink: kind == "l",
                size,
                mode,
            })
        })
        .collect()
}

fn text_field<'a>(value: &'a [u8], label: &str) -> Result<&'a str> {
    std::str::from_utf8(value).map_err(|error| decode_error(label, error))
}

fn decode_error(label: &str, error: impl std::fmt::Display) -> RuntimeError {
    RuntimeError::Backend {
        operation: "decode QEMU guest directory",
        message: format!("{label}: {error}"),
    }
}

fn allocate_loopback_port() -> Result<u16> {
    TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 0))
        .and_then(|listener| listener.local_addr())
        .map(|address| address.port())
        .map_err(|error| RuntimeError::Backend {
            operation: "allocate QEMU control port",
            message: error.to_string(),
        })
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .map_err(|error| state::io_error("inspect QEMU state directory", path, error))?
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)
        .map_err(|error| state::io_error("secure QEMU state directory", path, error))
}

#[cfg(not(unix))]
fn secure_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn qmp_address(port: u16) -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), port)
}

fn process_alive(state: &MachineState) -> bool {
    process_start_time(state.pid).is_some_and(|started_at| {
        state.process_started_at == 0 || state.process_started_at == started_at
    })
}

fn process_start_time(pid: u32) -> Option<u64> {
    let pid = Pid::from_u32(pid);
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).map(|process| process.start_time())
}

async fn wait_for_process_start(pid: u32, timeout: Duration) -> Option<u64> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(started_at) = process_start_time(pid) {
            return Some(started_at);
        }
        if Instant::now() >= deadline {
            return None;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

fn kill_process(state: &MachineState) -> bool {
    let pid = Pid::from_u32(state.pid);
    let mut system = System::new();
    system.refresh_processes(ProcessesToUpdate::Some(&[pid]), true);
    system.process(pid).is_none_or(|process| {
        if state.process_started_at != 0 && process.start_time() != state.process_started_at {
            return true;
        }
        process
            .kill_with(Signal::Kill)
            .unwrap_or_else(|| process.kill())
    })
}

fn validate_sandbox_id(sandbox: &str) -> Result<()> {
    if sandbox.is_empty()
        || sandbox.len() > 96
        || sandbox
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || "_-".contains(character)))
    {
        return Err(RuntimeError::Configuration(format!(
            "invalid sandbox identifier {sandbox:?}"
        )));
    }
    Ok(())
}

fn log_suffix(path: &Path) -> String {
    let Ok(bytes) = fs::read(path) else {
        return String::new();
    };
    let start = bytes.len().saturating_sub(8 * 1024);
    let tail = String::from_utf8_lossy(&bytes[start..]).trim().to_owned();
    if tail.is_empty() {
        String::new()
    } else {
        format!("; QEMU log: {tail}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_nul_delimited_directory_records() {
        let entries =
            parse_find_output(b"d\x00/out/sub\x004096\x00755\x00f\x00/out/a b\x0012\x00644\x00")
                .unwrap();
        assert_eq!(entries.len(), 2);
        assert!(entries[0].directory);
        assert_eq!(entries[1].path, "/out/a b");
        assert_eq!(entries[1].size, 12);
        assert_eq!(entries[1].mode, 0o644);
    }

    #[test]
    fn rejects_state_path_traversal() {
        assert!(validate_sandbox_id("../other").is_err());
        assert!(validate_sandbox_id("sbx_qemu_good-1").is_ok());
    }
}
