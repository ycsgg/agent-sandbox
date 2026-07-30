//! Linux Android Cuttlefish runtime adapter.

#![forbid(unsafe_code)]

use std::{
    collections::BTreeMap,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    net::{Ipv4Addr, TcpListener},
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use agent_sandbox_runtime::{
    BackendCapabilities, BackendId, BootSourceKind, CommandRuntime, CreateSpec, ExecEvent,
    ExecRequest, ExecStream, FileTransferRuntime, GuestEntry, GuestLayout, NetworkMode,
    OutputStream, Result, RootSource, RuntimeError, RuntimeFeature, SandboxInfo, SandboxRuntime,
    SecurityMode, TerminalRuntime, WorkspaceSpec,
};
use async_trait::async_trait;
use bytes::Bytes;
use chrono::Utc;
use serde::{Deserialize, Serialize};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::mpsc,
};

mod state;

use state::{DeviceState, STATE_VERSION};

const FIRST_INSTANCE: u16 = 1;
// The standard cuttlefish-base host package preallocates resources for 1..=10.
const LAST_INSTANCE: u16 = 10;
const ADB_BASE_PORT: u16 = 6520;
const ADB_SERVER_BASE_PORT: u16 = 7500;
const MAX_DIRECTORY_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const GUEST_WORKSPACE: &str = "/data/local/tmp/asbx/workspace";
const GUEST_ARTIFACTS: &str = "/data/local/tmp/asbx/out";
static TRANSFER_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Host-side Android Cuttlefish process configuration.
#[derive(Debug, Clone)]
pub struct CuttlefishRuntimeConfig {
    /// Durable wrapper-owned Cuttlefish state directory.
    pub home: PathBuf,
    /// Default combined host-tools/device-images directory.
    pub artifacts: Option<PathBuf>,
    /// Device launch and ADB readiness deadline.
    pub boot_timeout: Duration,
    /// Cuttlefish shutdown deadline.
    pub shutdown_timeout: Duration,
}

/// Runtime adapter backed by Android Cuttlefish and ADB.
pub struct CuttlefishRuntime {
    config: CuttlefishRuntimeConfig,
}

#[derive(Debug, Clone)]
struct CuttlefishTools {
    launch: PathBuf,
    stop: PathBuf,
    adb: PathBuf,
}

struct PendingDevice {
    directory: PathBuf,
    claim: PathBuf,
    committed: bool,
}

struct PendingClaim {
    path: Option<PathBuf>,
}

#[derive(Debug, Serialize, Deserialize)]
struct InstanceClaim {
    sandbox: String,
    pid: u32,
}

impl PendingClaim {
    fn new(path: PathBuf) -> Self {
        Self { path: Some(path) }
    }

    fn take(&mut self) -> PathBuf {
        self.path.take().expect("pending claim is available")
    }
}

impl Drop for PendingClaim {
    fn drop(&mut self) {
        if let Some(path) = &self.path {
            let _ = fs::remove_file(path);
        }
    }
}

impl PendingDevice {
    fn new(directory: PathBuf, claim: PathBuf) -> Self {
        Self {
            directory,
            claim,
            committed: false,
        }
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for PendingDevice {
    fn drop(&mut self) {
        if !self.committed {
            let _ = fs::remove_dir_all(&self.directory);
            let _ = fs::remove_file(&self.claim);
        }
    }
}

impl CuttlefishRuntime {
    /// Construct the Cuttlefish backend without starting host tools.
    pub fn new(config: CuttlefishRuntimeConfig) -> Result<Self> {
        if config.home.to_str().is_none() {
            return Err(RuntimeError::Configuration(
                "the Cuttlefish state directory must be valid UTF-8".into(),
            ));
        }
        if config.boot_timeout.is_zero() {
            return Err(RuntimeError::Configuration(
                "cuttlefish.boot_timeout must be greater than zero".into(),
            ));
        }
        if config.shutdown_timeout.is_zero() {
            return Err(RuntimeError::Configuration(
                "cuttlefish.shutdown_timeout must be greater than zero".into(),
            ));
        }
        Ok(Self { config })
    }

    fn device_dir(&self, sandbox: &str) -> Result<PathBuf> {
        validate_sandbox_id(sandbox)?;
        Ok(self.config.home.join("devices").join(sandbox))
    }

    fn state_path(&self, sandbox: &str) -> Result<PathBuf> {
        Ok(self.device_dir(sandbox)?.join("state.json"))
    }

    fn load_state(&self, sandbox: &str) -> Result<DeviceState> {
        state::load(&self.state_path(sandbox)?)
    }

    fn save_state(&self, state: &DeviceState) -> Result<()> {
        state::save(&self.state_path(&state.id)?, state)
    }

    fn claim_dir(&self) -> PathBuf {
        self.config.home.join("claims")
    }

    fn claim_path(&self, instance_num: u16) -> PathBuf {
        self.claim_dir().join(format!("{instance_num}.claim"))
    }

    fn claim_instance(&self, sandbox: &str) -> Result<(u16, PathBuf)> {
        fs::create_dir_all(self.claim_dir()).map_err(|error| {
            state::io_error(
                "create Cuttlefish instance-claim directory",
                &self.claim_dir(),
                error,
            )
        })?;
        let claim = serde_json::to_vec(&InstanceClaim {
            sandbox: sandbox.into(),
            pid: std::process::id(),
        })
        .map_err(|error| RuntimeError::Backend {
            operation: "encode Cuttlefish instance claim",
            message: error.to_string(),
        })?;
        for instance_num in FIRST_INSTANCE..=LAST_INSTANCE {
            let device_port = adb_port(instance_num)?;
            let Ok(_device_listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, device_port)) else {
                continue;
            };
            let server_port = adb_server_port(instance_num)?;
            let Ok(_server_listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, server_port)) else {
                continue;
            };
            let path = self.claim_path(instance_num);
            for attempt in 0..=1 {
                match OpenOptions::new().write(true).create_new(true).open(&path) {
                    Ok(mut file) => {
                        if let Err(error) = file.write_all(&claim) {
                            drop(file);
                            let _ = fs::remove_file(&path);
                            return Err(state::io_error(
                                "write Cuttlefish instance claim",
                                &path,
                                error,
                            ));
                        }
                        return Ok((instance_num, path));
                    }
                    Err(error)
                        if error.kind() == std::io::ErrorKind::AlreadyExists
                            && attempt == 0
                            && self.reclaim_abandoned_claim(&path)? =>
                    {
                        continue;
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => break,
                    Err(error) => {
                        return Err(state::io_error(
                            "reserve Cuttlefish instance number",
                            &path,
                            error,
                        ));
                    }
                }
            }
        }
        Err(RuntimeError::Backend {
            operation: "reserve Cuttlefish instance number",
            message: format!("no free instance number in {FIRST_INSTANCE}..={LAST_INSTANCE}"),
        })
    }

    fn reclaim_abandoned_claim(&self, path: &Path) -> Result<bool> {
        let claim = match read_claim(path) {
            Ok(claim) => claim,
            Err(RuntimeError::NotFound(_)) => return Ok(true),
            Err(error) => return Err(error),
        };
        if process_is_alive(claim.pid) {
            return Ok(false);
        }
        let directory = match self.device_dir(&claim.sandbox) {
            Ok(directory) => directory,
            Err(_) => return Ok(false),
        };
        if directory.join("state.json").exists() {
            return Ok(false);
        }
        match fs::remove_dir_all(&directory) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(state::io_error(
                    "remove abandoned Cuttlefish device directory",
                    &directory,
                    error,
                ));
            }
        }
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(state::io_error(
                "remove abandoned Cuttlefish instance claim",
                path,
                error,
            )),
        }
    }

    fn command_for(&self, state: &DeviceState, executable: &Path) -> Result<Command> {
        let home = self.device_dir(&state.id)?;
        let mut command = Command::new(executable);
        command
            .current_dir(&state.artifacts)
            .env("HOME", &home)
            .env("ANDROID_HOST_OUT", &state.artifacts)
            .env("ANDROID_SOONG_HOST_OUT", &state.artifacts)
            .env("ANDROID_PRODUCT_OUT", &state.artifacts)
            .env("CUTTLEFISH_INSTANCE", state.instance_num.to_string());
        Ok(command)
    }

    fn adb_command(&self, state: &DeviceState) -> Result<Command> {
        let tools = resolve_tools(&state.artifacts)?;
        let mut command = self.command_for(state, &tools.adb)?;
        command
            .arg("-P")
            .arg(state.adb_server_port.to_string())
            .args(["-s", &state.serial]);
        Ok(command)
    }

    async fn connect_adb(&self, state: &DeviceState) -> Result<()> {
        let tools = resolve_tools(&state.artifacts)?;
        let mut connect = self.command_for(state, &tools.adb)?;
        connect
            .arg("-P")
            .arg(state.adb_server_port.to_string())
            .args(["connect", &state.serial])
            .kill_on_drop(true);
        let _ = tokio::time::timeout(Duration::from_secs(10), connect.output()).await;

        let mut wait = self.adb_command(state)?;
        wait.arg("wait-for-device").kill_on_drop(true);
        let output = tokio::time::timeout(self.config.boot_timeout, wait.output())
            .await
            .map_err(|_| RuntimeError::Backend {
                operation: "wait for Cuttlefish ADB",
                message: format!(
                    "device {} was not ready within {:?}",
                    state.serial, self.config.boot_timeout
                ),
            })?
            .map_err(|error| RuntimeError::Backend {
                operation: "wait for Cuttlefish ADB",
                message: error.to_string(),
            })?;
        ensure_success("wait for Cuttlefish ADB", output).map(|_| ())
    }

    async fn stop_impl(&self, sandbox: &str, clear: bool) -> Result<()> {
        let mut state = self.load_state(sandbox)?;
        if !state.active {
            return self.kill_adb_server(&state).await;
        }
        let tools = resolve_tools(&state.artifacts)?;
        let mut command = self.command_for(&state, &tools.stop)?;
        if clear {
            command.arg("--clear_instance_dirs=true");
        }
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true);
        let status = tokio::time::timeout(self.config.shutdown_timeout, command.status())
            .await
            .map_err(|_| RuntimeError::Backend {
                operation: "stop Cuttlefish device",
                message: format!(
                    "{sandbox} did not stop within {:?}",
                    self.config.shutdown_timeout
                ),
            })?
            .map_err(|error| RuntimeError::Backend {
                operation: "stop Cuttlefish device",
                message: error.to_string(),
            })?;
        if !status.success() && clear {
            let mut fallback = self.command_for(&state, &tools.stop)?;
            fallback
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            let fallback_status =
                tokio::time::timeout(self.config.shutdown_timeout, fallback.status())
                    .await
                    .map_err(|_| RuntimeError::Backend {
                        operation: "stop Cuttlefish device",
                        message: format!(
                            "{sandbox} fallback stop did not finish within {:?}",
                            self.config.shutdown_timeout
                        ),
                    })?
                    .map_err(|error| RuntimeError::Backend {
                        operation: "stop Cuttlefish device",
                        message: error.to_string(),
                    })?;
            if !fallback_status.success() {
                return Err(RuntimeError::Backend {
                    operation: "stop Cuttlefish device",
                    message: format!("stop_cvd exited with {fallback_status}"),
                });
            }
        } else if !status.success() {
            return Err(RuntimeError::Backend {
                operation: "stop Cuttlefish device",
                message: format!("stop_cvd exited with {status}"),
            });
        }
        state.active = false;
        self.save_state(&state)?;
        self.kill_adb_server(&state).await
    }

    async fn remote_output(
        &self,
        sandbox: &str,
        operation: &'static str,
        script: &str,
    ) -> Result<Vec<u8>> {
        let state = self.load_state(sandbox)?;
        if !state.active {
            return Err(RuntimeError::Backend {
                operation,
                message: "Android device is stopped".into(),
            });
        }
        let mut command = self.adb_command(&state)?;
        add_adb_shell_command(&mut command, script, false);
        let output = command
            .output()
            .await
            .map_err(|error| RuntimeError::Backend {
                operation,
                message: error.to_string(),
            })?;
        ensure_success(operation, output).map(|output| output.stdout)
    }

    async fn adb_transfer(
        &self,
        state: &DeviceState,
        operation: &'static str,
        arguments: &[OsString],
    ) -> Result<()> {
        if !state.active {
            return Err(RuntimeError::Backend {
                operation,
                message: "Android device is stopped".into(),
            });
        }
        let mut command = self.adb_command(state)?;
        command.args(arguments);
        let output = command
            .output()
            .await
            .map_err(|error| RuntimeError::Backend {
                operation,
                message: error.to_string(),
            })?;
        ensure_success(operation, output).map(|_| ())
    }

    fn info(&self, state: &DeviceState, status: String) -> SandboxInfo {
        SandboxInfo {
            id: state.id.clone(),
            backend: BackendId::cuttlefish(),
            status,
            created_at: Some(state.created_at),
            metadata: BTreeMap::from([
                ("adb_serial".into(), state.serial.clone()),
                ("adb_server_port".into(), state.adb_server_port.to_string()),
                ("instance_num".into(), state.instance_num.to_string()),
                (
                    "android_artifacts".into(),
                    state.artifacts.display().to_string(),
                ),
                ("workspace".into(), GUEST_WORKSPACE.into()),
                ("artifacts".into(), GUEST_ARTIFACTS.into()),
            ]),
        }
    }

    async fn supports_launch_flag(&self, artifacts: &Path, flag: &str) -> Result<bool> {
        let tools = resolve_tools(artifacts)?;
        let mut command = Command::new(&tools.launch);
        command
            .current_dir(artifacts)
            .env("HOME", artifacts)
            .arg("--help")
            .stdin(Stdio::null())
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(10), command.output())
            .await
            .map_err(|_| RuntimeError::Backend {
                operation: "inspect Cuttlefish launch flags",
                message: "launch_cvd --help did not finish within 10s".into(),
            })?
            .map_err(|error| RuntimeError::Backend {
                operation: "inspect Cuttlefish launch flags",
                message: error.to_string(),
            })?;
        let mut help = output.stdout;
        help.extend_from_slice(&output.stderr);
        Ok(String::from_utf8_lossy(&help).contains(flag))
    }

    async fn kill_adb_server(&self, state: &DeviceState) -> Result<()> {
        let tools = resolve_tools(&state.artifacts)?;
        let mut command = self.command_for(state, &tools.adb)?;
        command
            .arg("-P")
            .arg(state.adb_server_port.to_string())
            .arg("kill-server")
            .stdin(Stdio::null())
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(5), command.output())
            .await
            .map_err(|_| RuntimeError::Backend {
                operation: "stop Cuttlefish ADB server",
                message: format!(
                    "ADB server on port {} did not stop within 5s",
                    state.adb_server_port
                ),
            })?
            .map_err(|error| RuntimeError::Backend {
                operation: "stop Cuttlefish ADB server",
                message: error.to_string(),
            })?;
        ensure_success("stop Cuttlefish ADB server", output).map(|_| ())
    }
}

#[async_trait]
impl SandboxRuntime for CuttlefishRuntime {
    fn backend_id(&self) -> BackendId {
        BackendId::cuttlefish()
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: self.backend_id(),
            boot_sources: vec![BootSourceKind::AndroidArtifacts],
            features: vec![
                RuntimeFeature::Exec,
                RuntimeFeature::Attach,
                RuntimeFeature::FileTransfer,
            ],
            architectures: vec!["x86_64".into(), "aarch64".into()],
            accelerators: if cfg!(target_os = "linux") {
                vec!["kvm".into()]
            } else {
                vec![]
            },
        }
    }

    fn guest_layout(&self) -> GuestLayout {
        GuestLayout {
            root: "/".into(),
            workspace: GUEST_WORKSPACE.into(),
            artifacts: GUEST_ARTIFACTS.into(),
            shell: "/system/bin/sh".into(),
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

    async fn create(&self, spec: &CreateSpec) -> Result<SandboxInfo> {
        validate_create_spec(spec)?;
        if !cfg!(target_os = "linux") {
            return Err(RuntimeError::Unsupported(
                "Cuttlefish is supported only on Linux hosts with KVM".into(),
            ));
        }
        require_host_device(Path::new("/dev/kvm"), "KVM")?;
        require_host_device(Path::new("/dev/vhost-vsock"), "vhost-vsock")?;
        let RootSource::Android(android) = &spec.root else {
            unreachable!("validated Cuttlefish create source");
        };
        let artifacts = canonical_artifacts(&android.artifacts)?;
        let tools = resolve_tools(&artifacts)?;
        if spec.network == NetworkMode::Off
            && !self
                .supports_launch_flag(&artifacts, "enable_tap_devices")
                .await?
        {
            return Err(RuntimeError::Unsupported(
                "offline Android devices require Cuttlefish host tools with \
                 --enable_tap_devices support; use matching 2025-03 or newer artifacts, \
                 or explicitly request host-gated network mode 'all'"
                    .into(),
            ));
        }
        let (instance_num, claim) = self.claim_instance(&spec.id)?;
        let mut claim = PendingClaim::new(claim);
        let directory = self.device_dir(&spec.id)?;
        fs::create_dir_all(directory.parent().expect("device directory has a parent")).map_err(
            |error| {
                state::io_error(
                    "create Cuttlefish device-state root",
                    directory.parent().expect("device directory has a parent"),
                    error,
                )
            },
        )?;
        fs::create_dir(&directory).map_err(|error| {
            state::io_error("create Cuttlefish device directory", &directory, error)
        })?;
        let pending = PendingDevice::new(directory.clone(), claim.take());
        secure_directory(&directory)?;
        for child in ["assembly", "runtime", "tmp"] {
            let path = directory.join(child);
            fs::create_dir_all(&path).map_err(|error| {
                state::io_error("create Cuttlefish runtime directory", &path, error)
            })?;
        }
        let state = DeviceState {
            version: STATE_VERSION,
            id: spec.id.clone(),
            artifacts,
            instance_num,
            serial: format!("127.0.0.1:{}", adb_port(instance_num)?),
            adb_server_port: adb_server_port(instance_num)?,
            default_user: spec.user.clone(),
            default_env: spec.env.clone(),
            created_at: Utc::now(),
            active: true,
        };
        self.save_state(&state)?;

        let log_path = directory.join("launch.log");
        let stdout = fs::File::create(&log_path)
            .map_err(|error| state::io_error("create Cuttlefish launch log", &log_path, error))?;
        let stderr = stdout.try_clone().map_err(|error| {
            state::io_error("duplicate Cuttlefish launch log", &log_path, error)
        })?;
        let mut command = self.command_for(&state, &tools.launch)?;
        command
            .args(launch_arguments(spec, &state, &directory)?)
            .env("TMPDIR", directory.join("tmp"))
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|error| RuntimeError::Backend {
            operation: "start Cuttlefish device",
            message: error.to_string(),
        })?;
        let status = match tokio::time::timeout(self.config.boot_timeout, child.wait()).await {
            Ok(Ok(status)) => status,
            Ok(Err(source)) => {
                let error = RuntimeError::Backend {
                    operation: "start Cuttlefish device",
                    message: source.to_string(),
                };
                let cleanup = self.stop_impl(&spec.id, true).await;
                return failed_creation(pending, error, cleanup);
            }
            Err(_) => {
                let _ = child.kill().await;
                let error = RuntimeError::Backend {
                    operation: "start Cuttlefish device",
                    message: format!(
                        "launch_cvd did not finish within {:?}; see {}",
                        self.config.boot_timeout,
                        log_path.display()
                    ),
                };
                let cleanup = self.stop_impl(&spec.id, true).await;
                return failed_creation(pending, error, cleanup);
            }
        };
        if !status.success() {
            let error = RuntimeError::Backend {
                operation: "start Cuttlefish device",
                message: format!(
                    "launch_cvd exited with {status}; see {}",
                    log_path.display()
                ),
            };
            let cleanup = self.stop_impl(&spec.id, true).await;
            return failed_creation(pending, error, cleanup);
        }
        if let Err(error) = self.connect_adb(&state).await {
            let cleanup = self.stop_impl(&spec.id, true).await;
            return failed_creation(pending, error, cleanup);
        }
        if let Err(error) = self
            .remote_output(
                &spec.id,
                "initialize Android guest directories",
                &format!(
                    "mkdir -p {} {} && chmod 0777 {} {}",
                    shell_quote(GUEST_WORKSPACE),
                    shell_quote(GUEST_ARTIFACTS),
                    shell_quote(GUEST_WORKSPACE),
                    shell_quote(GUEST_ARTIFACTS)
                ),
            )
            .await
        {
            let cleanup = self.stop_impl(&spec.id, true).await;
            return failed_creation(pending, error, cleanup);
        }
        pending.commit();
        Ok(self.info(&state, "running".into()))
    }

    async fn stop(&self, sandbox: &str) -> Result<()> {
        self.stop_impl(sandbox, false).await
    }

    async fn kill(&self, sandbox: &str) -> Result<()> {
        self.stop_impl(sandbox, true).await
    }

    async fn remove(&self, sandbox: &str) -> Result<()> {
        let state = self.load_state(sandbox)?;
        if state.active {
            return Err(RuntimeError::Backend {
                operation: "remove Cuttlefish device",
                message: "device is still active; stop or kill it first".into(),
            });
        }
        self.kill_adb_server(&state).await?;
        let claim = self.claim_path(state.instance_num);
        match read_claim(&claim) {
            Ok(owner) if owner.sandbox == sandbox => {
                fs::remove_file(&claim).map_err(|error| {
                    state::io_error("release Cuttlefish instance claim", &claim, error)
                })?;
            }
            Ok(_) | Err(RuntimeError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }
        let directory = self.device_dir(sandbox)?;
        fs::remove_dir_all(&directory).map_err(|error| {
            state::io_error("remove Cuttlefish device state", &directory, error)
        })?;
        Ok(())
    }

    async fn list(&self) -> Result<Vec<SandboxInfo>> {
        let root = self.config.home.join("devices");
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(error) => {
                return Err(state::io_error(
                    "list Cuttlefish device states",
                    &root,
                    error,
                ));
            }
        };
        let mut devices = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| {
                state::io_error("read Cuttlefish device state entry", &root, error)
            })?;
            if !entry.file_type().map(|kind| kind.is_dir()).unwrap_or(false) {
                continue;
            }
            if let Ok(info) = self.inspect(&entry.file_name().to_string_lossy()).await {
                devices.push(info);
            }
        }
        devices.sort_by(|left, right| left.id.cmp(&right.id));
        Ok(devices)
    }

    async fn inspect(&self, sandbox: &str) -> Result<SandboxInfo> {
        let state = self.load_state(sandbox)?;
        if !state.active {
            return Ok(self.info(&state, "stopped".into()));
        }
        let mut command = self.adb_command(&state)?;
        command.arg("get-state").kill_on_drop(true);
        let status = match tokio::time::timeout(Duration::from_secs(3), command.output()).await {
            Ok(Ok(output))
                if output.status.success()
                    && String::from_utf8_lossy(&output.stdout).trim() == "device" =>
            {
                "running"
            }
            _ => "unknown",
        };
        Ok(self.info(&state, status.into()))
    }

    async fn doctor(&self) -> Result<Vec<(String, bool, String)>> {
        let linux = cfg!(target_os = "linux");
        let kvm = linux
            && OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/kvm")
                .is_ok();
        let vsock = linux
            && OpenOptions::new()
                .read(true)
                .write(true)
                .open("/dev/vhost-vsock")
                .is_ok();
        let mut checks = vec![
            (
                "Cuttlefish / Linux host".into(),
                linux,
                if linux {
                    "Linux host detected".into()
                } else {
                    "Cuttlefish requires Linux".into()
                },
            ),
            (
                "Cuttlefish / KVM".into(),
                kvm,
                if kvm {
                    "/dev/kvm is readable and writable".into()
                } else {
                    "/dev/kvm is unavailable or not accessible".into()
                },
            ),
            (
                "Cuttlefish / vhost-vsock".into(),
                vsock,
                if vsock {
                    "/dev/vhost-vsock is readable and writable".into()
                } else {
                    "/dev/vhost-vsock is unavailable or not accessible".into()
                },
            ),
        ];
        match self.config.artifacts.as_deref() {
            Some(path) => match canonical_artifacts(path).and_then(|path| {
                resolve_tools(&path)?;
                Ok(path)
            }) {
                Ok(path) => {
                    checks.push((
                        "Cuttlefish / Android artifacts".into(),
                        true,
                        path.display().to_string(),
                    ));
                    match self.supports_launch_flag(&path, "enable_tap_devices").await {
                        Ok(true) => checks.push((
                            "Cuttlefish / offline networking".into(),
                            true,
                            "--enable_tap_devices is supported".into(),
                        )),
                        Ok(false) => checks.push((
                            "Cuttlefish / offline networking".into(),
                            false,
                            "host tools are too old for --enable_tap_devices".into(),
                        )),
                        Err(error) => checks.push((
                            "Cuttlefish / launch tools".into(),
                            false,
                            error.to_string(),
                        )),
                    }
                }
                Err(error) => checks.push((
                    "Cuttlefish / Android artifacts".into(),
                    false,
                    error.to_string(),
                )),
            },
            None => checks.push((
                "Cuttlefish / Android artifacts".into(),
                false,
                "configure cuttlefish.artifacts or pass --android-artifacts".into(),
            )),
        }
        Ok(checks)
    }
}

#[async_trait]
impl CommandRuntime for CuttlefishRuntime {
    async fn exec_stream(&self, sandbox: &str, request: ExecRequest) -> Result<ExecStream> {
        let state = self.load_state(sandbox)?;
        if !state.active {
            return Err(RuntimeError::Backend {
                operation: "execute Android guest command",
                message: "Android device is stopped".into(),
            });
        }
        let request = request_with_defaults(request, &state);
        let remote = remote_command(&request);
        let mut command = self.adb_command(&state)?;
        add_adb_shell_command(&mut command, &remote, false);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|error| RuntimeError::Backend {
            operation: "start Android guest command",
            message: error.to_string(),
        })?;
        let pid = child.id().unwrap_or(0);
        let stdout = child.stdout.take().expect("piped ADB stdout is available");
        let stderr = child.stderr.take().expect("piped ADB stderr is available");
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
}

#[async_trait]
impl TerminalRuntime for CuttlefishRuntime {
    async fn attach(&self, sandbox: &str, request: ExecRequest) -> Result<i32> {
        let state = self.load_state(sandbox)?;
        if !state.active {
            return Err(RuntimeError::Backend {
                operation: "attach Android guest terminal",
                message: "Android device is stopped".into(),
            });
        }
        let request = request_with_defaults(request, &state);
        let remote = remote_command(&request);
        let mut command = self.adb_command(&state)?;
        add_adb_shell_command(&mut command, &remote, true);
        command
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let status = command
            .status()
            .await
            .map_err(|error| RuntimeError::Backend {
                operation: "attach Android guest terminal",
                message: error.to_string(),
            })?;
        Ok(status.code().unwrap_or(-1))
    }
}

#[async_trait]
impl FileTransferRuntime for CuttlefishRuntime {
    async fn mkdir(&self, sandbox: &str, guest_path: &str) -> Result<()> {
        validate_guest_path(guest_path)?;
        self.remote_output(
            sandbox,
            "create Android guest directory",
            &format!("mkdir -p {}", shell_quote(guest_path)),
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
        validate_guest_path(guest_path)?;
        let state = self.load_state(sandbox)?;
        let temporary = format!(
            "{guest_path}.asbx-{}-{}.part",
            std::process::id(),
            TRANSFER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        );
        self.adb_transfer(
            &state,
            "upload Android guest file",
            &[
                OsString::from("push"),
                host_path.as_os_str().to_owned(),
                OsString::from(&temporary),
            ],
        )
        .await?;
        let result = self
            .remote_output(
                sandbox,
                "commit Android guest file",
                &format!(
                    "chmod {mode:o} {} && mv -f {} {}",
                    shell_quote(&temporary),
                    shell_quote(&temporary),
                    shell_quote(guest_path)
                ),
            )
            .await;
        if result.is_err() {
            let _ = self
                .remote_output(
                    sandbox,
                    "remove partial Android guest file",
                    &format!("rm -f {}", shell_quote(&temporary)),
                )
                .await;
        }
        result.map(|_| ())
    }

    async fn symlink(&self, sandbox: &str, target: &str, guest_path: &str) -> Result<()> {
        validate_guest_path(guest_path)?;
        self.remote_output(
            sandbox,
            "create Android guest symlink",
            &format!("ln -s {} {}", shell_quote(target), shell_quote(guest_path)),
        )
        .await?;
        Ok(())
    }

    async fn set_mode(&self, sandbox: &str, guest_path: &str, mode: u32) -> Result<()> {
        validate_guest_path(guest_path)?;
        self.remote_output(
            sandbox,
            "set Android guest path mode",
            &format!("chmod {mode:o} {}", shell_quote(guest_path)),
        )
        .await?;
        Ok(())
    }

    async fn list_dir(&self, sandbox: &str, guest_path: &str) -> Result<Vec<GuestEntry>> {
        validate_guest_path(guest_path)?;
        let directory = shell_quote(guest_path);
        let output = self
            .remote_output(
                sandbox,
                "list Android guest directory",
                &format!(
                    "( for p in {directory}/* {directory}/.[!.]* {directory}/..?*; do \
                     if [ -e \"$p\" ] || [ -L \"$p\" ]; then \
                     if [ -L \"$p\" ]; then t=l; elif [ -d \"$p\" ]; then t=d; else t=f; fi; \
                     printf '%s\\0%s\\0%s\\0%s\\0' \"$t\" \"$p\" \
                     \"$(stat -c %s \"$p\")\" \"$(stat -c %a \"$p\")\"; fi; done ) \
                     | head -c {}",
                    MAX_DIRECTORY_OUTPUT_BYTES + 1
                ),
            )
            .await?;
        if output.len() > MAX_DIRECTORY_OUTPUT_BYTES {
            return Err(RuntimeError::Backend {
                operation: "list Android guest directory",
                message: format!(
                    "directory metadata exceeds the {} byte safety limit",
                    MAX_DIRECTORY_OUTPUT_BYTES
                ),
            });
        }
        parse_directory_output(&output)
    }

    async fn get_file(&self, sandbox: &str, guest_path: &str, host_path: &Path) -> Result<()> {
        validate_guest_path(guest_path)?;
        let state = self.load_state(sandbox)?;
        let temporary = download_temporary_path(host_path);
        let result = self
            .adb_transfer(
                &state,
                "download Android guest file",
                &[
                    OsString::from("pull"),
                    OsString::from(guest_path),
                    temporary.as_os_str().to_owned(),
                ],
            )
            .await;
        if let Err(error) = result {
            let _ = fs::remove_file(&temporary);
            return Err(error);
        }
        if let Err(error) = fs::rename(&temporary, host_path) {
            let _ = fs::remove_file(&temporary);
            return Err(state::io_error(
                "commit downloaded Android guest file",
                host_path,
                error,
            ));
        }
        Ok(())
    }
}

fn validate_create_spec(spec: &CreateSpec) -> Result<()> {
    if spec.backend.as_str() != BackendId::CUTTLEFISH {
        return Err(RuntimeError::Configuration(format!(
            "Cuttlefish received a create request for backend {}",
            spec.backend
        )));
    }
    if !matches!(spec.root, RootSource::Android(_)) {
        return Err(RuntimeError::Unsupported(
            "Cuttlefish requires an Android artifact directory".into(),
        ));
    }
    if !matches!(spec.workspace, WorkspaceSpec::None | WorkspaceSpec::Copy) {
        return Err(RuntimeError::Unsupported(
            "Cuttlefish does not support host workspace mounts; use copy or none".into(),
        ));
    }
    if !matches!(spec.network, NetworkMode::Off | NetworkMode::All) {
        return Err(RuntimeError::Unsupported(
            "Cuttlefish supports offline or host-gated unrestricted networking; filtered modes are not yet enforceable".into(),
        ));
    }
    if !spec.network_rules.is_empty() {
        return Err(RuntimeError::Unsupported(
            "Cuttlefish does not support wrapper network rules".into(),
        ));
    }
    if !spec.ports.is_empty() {
        return Err(RuntimeError::Unsupported(
            "Cuttlefish guest port publication is not implemented".into(),
        ));
    }
    if spec.security != SecurityMode::Default {
        return Err(RuntimeError::Unsupported(
            "Cuttlefish does not implement the wrapper restricted security profile".into(),
        ));
    }
    Ok(())
}

fn failed_creation(
    pending: PendingDevice,
    error: RuntimeError,
    cleanup: Result<()>,
) -> Result<SandboxInfo> {
    match cleanup {
        Ok(()) => {
            drop(pending);
            Err(error)
        }
        Err(cleanup_error) => {
            pending.commit();
            Err(RuntimeError::Backend {
                operation: "recover failed Cuttlefish creation",
                message: format!(
                    "{error}; cleanup also failed ({cleanup_error}); retained runtime state for retry"
                ),
            })
        }
    }
}

fn launch_arguments(
    spec: &CreateSpec,
    state: &DeviceState,
    directory: &Path,
) -> Result<Vec<String>> {
    let artifacts = utf8_path(&state.artifacts, "Android artifacts")?;
    let assembly_path = directory.join("assembly");
    let instance_path = directory.join("runtime");
    let data_path = directory.join("userdata.img");
    let assembly = utf8_path(&assembly_path, "Cuttlefish assembly directory")?;
    let instance = utf8_path(&instance_path, "Cuttlefish instance directory")?;
    let data = utf8_path(&data_path, "Cuttlefish data image")?;
    let mut arguments = vec![
        "--daemon=true".to_owned(),
        "--resume=false".to_owned(),
        "--num_instances=1".to_owned(),
        format!("--base_instance_num={}", state.instance_num),
        format!("--system_image_dir={artifacts}"),
        format!("--assembly_dir={assembly}"),
        format!("--instance_dir={instance}"),
        format!("--cpus={}", spec.cpus),
        format!("--memory_mb={}", spec.memory_mib),
        format!("--data_image={data}"),
        "--data_policy=always_create".to_owned(),
        format!("--blank_data_image_mb={}", spec.disk_mib),
        "--start_webrtc=false".to_owned(),
        "--report_anonymous_usage_stats=n".to_owned(),
        "--gpu_mode=guest_swiftshader".to_owned(),
    ];
    if spec.network == NetworkMode::Off {
        // Force the VMM whose upstream implementation omits every network
        // device when TAP devices are disabled; ADB remains available over
        // the independent vsock/TCP bridge.
        arguments.push("--vm_manager=crosvm".into());
        arguments.push("--enable_tap_devices=false".into());
    }
    Ok(arguments)
}

fn canonical_artifacts(path: &Path) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .map_err(|error| state::io_error("resolve Android artifact directory", path, error))?;
    if !canonical.is_dir() {
        return Err(RuntimeError::Configuration(format!(
            "Android artifacts {} is not a directory",
            canonical.display()
        )));
    }
    utf8_path(&canonical, "Android artifact directory")?;
    let has_image = fs::read_dir(&canonical)
        .map_err(|error| state::io_error("inspect Android artifact directory", &canonical, error))?
        .filter_map(std::result::Result::ok)
        .any(|entry| {
            entry.path().is_file()
                && entry
                    .path()
                    .extension()
                    .is_some_and(|extension| extension.eq_ignore_ascii_case("img"))
        });
    if !has_image {
        return Err(RuntimeError::Configuration(format!(
            "Android artifacts {} contains no device .img files",
            canonical.display()
        )));
    }
    Ok(canonical)
}

fn require_host_device(path: &Path, label: &str) -> Result<()> {
    OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .map(|_| ())
        .map_err(|error| {
            RuntimeError::Configuration(format!(
                "Cuttlefish requires read/write {label} access at {}: {error}",
                path.display()
            ))
        })
}

fn utf8_path<'a>(path: &'a Path, label: &str) -> Result<&'a str> {
    path.to_str().ok_or_else(|| {
        RuntimeError::Configuration(format!("{label} {} is not valid UTF-8", path.display()))
    })
}

fn resolve_tools(artifacts: &Path) -> Result<CuttlefishTools> {
    Ok(CuttlefishTools {
        launch: resolve_artifact_tool(artifacts, &["launch_cvd", "cvd_internal_start"])?,
        stop: resolve_artifact_tool(artifacts, &["stop_cvd", "cvd_internal_stop"])?,
        adb: resolve_artifact_tool(artifacts, &["adb"])?,
    })
}

fn resolve_artifact_tool(artifacts: &Path, names: &[&str]) -> Result<PathBuf> {
    for name in names {
        let candidate = artifacts.join("bin").join(name);
        if candidate.is_file() {
            return candidate.canonicalize().map_err(|error| {
                state::io_error("resolve Cuttlefish host tool", &candidate, error)
            });
        }
    }
    Err(RuntimeError::Configuration(format!(
        "Android artifacts {} does not contain bin/{}",
        artifacts.display(),
        names.join(" or bin/")
    )))
}

fn remote_command(request: &ExecRequest) -> String {
    let mut invocation = String::new();
    if !request.env.is_empty() {
        invocation.push_str("env");
        for (key, value) in &request.env {
            invocation.push(' ');
            invocation.push_str(&shell_quote(&format!("{key}={value}")));
        }
        invocation.push(' ');
    }
    invocation.push_str(&shell_quote(&request.command));
    for argument in &request.args {
        invocation.push(' ');
        invocation.push_str(&shell_quote(argument));
    }
    if let Some(user) = request.user.as_deref()
        && user != "shell"
    {
        let user = if user == "root" { "0" } else { user };
        invocation = format!(
            "exec su {} sh -c {}",
            shell_quote(user),
            shell_quote(&invocation)
        );
    } else {
        invocation.insert_str(0, "exec ");
    }
    match request.cwd.as_deref() {
        Some(cwd) => format!("cd {} && {invocation}", shell_quote(cwd)),
        None => invocation,
    }
}

fn request_with_defaults(mut request: ExecRequest, state: &DeviceState) -> ExecRequest {
    if request.user.is_none() {
        request.user.clone_from(&state.default_user);
    }
    let mut environment = state.default_env.clone();
    environment.retain(|(key, _)| {
        !request
            .env
            .iter()
            .any(|(override_key, _)| override_key == key)
    });
    environment.extend(request.env);
    request.env = environment;
    request
}

fn add_adb_shell_command(command: &mut Command, script: &str, tty: bool) {
    command.arg("shell");
    if tty {
        command.arg("-t");
    }
    command.arg(format!("sh -c {}", shell_quote(script)));
}

fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn ensure_success(
    operation: &'static str,
    output: std::process::Output,
) -> Result<std::process::Output> {
    if output.status.success() {
        return Ok(output);
    }
    let detail = String::from_utf8_lossy(&output.stderr).trim().to_owned();
    Err(RuntimeError::Backend {
        operation,
        message: if detail.is_empty() {
            format!("command exited with {}", output.status)
        } else {
            detail
        },
    })
}

fn read_claim(path: &Path) -> Result<InstanceClaim> {
    let bytes = fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            RuntimeError::NotFound(path.display().to_string())
        } else {
            state::io_error("read Cuttlefish instance claim", path, error)
        }
    })?;
    serde_json::from_slice(&bytes).map_err(|error| RuntimeError::Backend {
        operation: "decode Cuttlefish instance claim",
        message: format!("{}: {error}", path.display()),
    })
}

fn process_is_alive(pid: u32) -> bool {
    pid != 0 && Path::new("/proc").join(pid.to_string()).exists()
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
                        operation: "read Android guest command output",
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

fn parse_directory_output(output: &[u8]) -> Result<Vec<GuestEntry>> {
    let fields = output
        .split(|byte| *byte == 0)
        .filter(|field| !field.is_empty())
        .collect::<Vec<_>>();
    if fields.len() % 4 != 0 {
        return Err(RuntimeError::Backend {
            operation: "decode Android guest directory",
            message: "directory output contained an incomplete record".into(),
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
        operation: "decode Android guest directory",
        message: format!("{label}: {error}"),
    }
}

fn validate_guest_path(path: &str) -> Result<()> {
    let mut components = path.split('/');
    if components.next() != Some("")
        || components.any(|component| {
            component.is_empty()
                || matches!(component, "." | "..")
                || component.chars().any(char::is_control)
        })
    {
        return Err(RuntimeError::Configuration(format!(
            "invalid absolute Android guest path {path:?}"
        )));
    }
    Ok(())
}

fn validate_sandbox_id(sandbox: &str) -> Result<()> {
    if sandbox.is_empty()
        || sandbox.len() > 96
        || sandbox
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || matches!(character, '_' | '-')))
    {
        return Err(RuntimeError::Configuration(format!(
            "invalid Cuttlefish sandbox identifier {sandbox:?}"
        )));
    }
    Ok(())
}

fn adb_port(instance_num: u16) -> Result<u16> {
    ADB_BASE_PORT
        .checked_add(instance_num.saturating_sub(1))
        .ok_or_else(|| {
            RuntimeError::Configuration(format!(
                "Cuttlefish instance number {instance_num} has no valid ADB port"
            ))
        })
}

fn adb_server_port(instance_num: u16) -> Result<u16> {
    ADB_SERVER_BASE_PORT
        .checked_add(instance_num.saturating_sub(1))
        .ok_or_else(|| {
            RuntimeError::Configuration(format!(
                "Cuttlefish instance number {instance_num} has no valid ADB server port"
            ))
        })
}

fn download_temporary_path(destination: &Path) -> PathBuf {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let name = destination
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    parent.join(format!(
        ".{name}.asbx-{}-{}.part",
        std::process::id(),
        TRANSFER_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}

#[cfg(unix)]
fn secure_directory(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    let mut permissions = fs::metadata(path)
        .map_err(|error| state::io_error("inspect Cuttlefish state directory", path, error))?
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)
        .map_err(|error| state::io_error("secure Cuttlefish state directory", path, error))
}

#[cfg(not(unix))]
fn secure_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn request() -> ExecRequest {
        ExecRequest {
            command: "printf".into(),
            args: vec!["%s".into(), "a b';$(touch nope)".into()],
            cwd: Some(GUEST_WORKSPACE.into()),
            user: None,
            env: vec![("TOKEN".into(), "x y'z".into())],
            timeout: None,
            tty: false,
        }
    }

    fn create_spec(network: NetworkMode) -> CreateSpec {
        CreateSpec {
            id: "sbx_cuttlefish_test".into(),
            backend: BackendId::cuttlefish(),
            root: RootSource::Android(Box::new(agent_sandbox_runtime::AndroidBootSpec {
                artifacts: PathBuf::from("/android"),
            })),
            cpus: 2,
            memory_mib: 2048,
            disk_mib: 4096,
            user: None,
            security: SecurityMode::Default,
            network,
            network_rules: vec![],
            workspace: WorkspaceSpec::Copy,
            env: vec![],
            ports: vec![],
            max_duration: Duration::from_secs(60),
            ephemeral: true,
            detached: false,
        }
    }

    #[test]
    fn android_remote_commands_preserve_argument_boundaries() {
        let command = remote_command(&request());
        assert!(command.starts_with("cd '/data/local/tmp/asbx/workspace' && exec env "));
        assert!(command.contains("'a b'\"'\"';$(touch nope)'"));
        assert!(command.contains("'TOKEN=x y'\"'\"'z'"));
    }

    #[test]
    fn root_user_is_explicitly_wrapped_with_su() {
        let mut request = request();
        request.user = Some("root".into());
        let command = remote_command(&request);
        assert!(command.contains("exec su '0' sh -c"));
    }

    #[test]
    fn sandbox_defaults_are_merged_without_overriding_command_values() {
        let state = DeviceState {
            version: STATE_VERSION,
            id: "sbx_cuttlefish_test".into(),
            artifacts: PathBuf::from("/android"),
            instance_num: 1,
            serial: "127.0.0.1:6520".into(),
            adb_server_port: 7500,
            default_user: Some("root".into()),
            default_env: vec![
                ("CI".into(), "1".into()),
                ("TOKEN".into(), "sandbox".into()),
            ],
            created_at: Utc::now(),
            active: true,
        };
        let mut request = request();
        request.env.push(("TOKEN".into(), "command".into()));
        let request = request_with_defaults(request, &state);

        assert_eq!(request.user.as_deref(), Some("root"));
        assert!(request.env.contains(&("CI".into(), "1".into())));
        assert!(request.env.contains(&("TOKEN".into(), "command".into())));
        assert!(!request.env.contains(&("TOKEN".into(), "sandbox".into())));
    }

    #[test]
    fn offline_launch_disables_tap_devices_without_changing_adb_transport() {
        let state = DeviceState {
            version: STATE_VERSION,
            id: "sbx_cuttlefish_test".into(),
            artifacts: PathBuf::from("/android"),
            instance_num: 7,
            serial: "127.0.0.1:6526".into(),
            adb_server_port: 7506,
            default_user: None,
            default_env: vec![],
            created_at: Utc::now(),
            active: true,
        };
        let directory = Path::new("/state/device");
        let offline = launch_arguments(&create_spec(NetworkMode::Off), &state, directory).unwrap();
        let online = launch_arguments(&create_spec(NetworkMode::All), &state, directory).unwrap();

        assert!(offline.contains(&"--base_instance_num=7".into()));
        assert!(offline.contains(&"--vm_manager=crosvm".into()));
        assert!(offline.contains(&"--enable_tap_devices=false".into()));
        assert!(
            !online
                .iter()
                .any(|argument| argument.contains("tap_devices"))
        );
    }

    #[test]
    fn parses_nul_delimited_android_directory_records() {
        let output = [
            b"f\0/data/local/tmp/asbx/out/a b\0".as_slice(),
            b"12\0",
            b"644\0",
        ]
        .concat();
        let entries = parse_directory_output(&output).unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].path, "/data/local/tmp/asbx/out/a b");
        assert_eq!(entries[0].size, 12);
        assert_eq!(entries[0].mode, 0o644);
    }

    #[test]
    fn cuttlefish_declares_android_guest_layout() {
        let runtime = CuttlefishRuntime::new(CuttlefishRuntimeConfig {
            home: PathBuf::from("/tmp/asbx-cuttlefish"),
            artifacts: None,
            boot_timeout: Duration::from_secs(1),
            shutdown_timeout: Duration::from_secs(1),
        })
        .unwrap();
        assert_eq!(runtime.backend_id(), BackendId::cuttlefish());
        assert_eq!(runtime.guest_layout().workspace, GUEST_WORKSPACE);
        assert_eq!(runtime.guest_layout().artifacts, GUEST_ARTIFACTS);
    }

    #[test]
    fn rejects_filtered_network_modes_until_they_are_enforceable() {
        let spec = create_spec(NetworkMode::Public);
        let error = validate_create_spec(&spec).unwrap_err();
        assert!(error.to_string().contains("filtered modes"));
    }

    #[test]
    fn instance_claim_round_trips_owner_and_process() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("1.claim");
        fs::write(
            &path,
            serde_json::to_vec(&InstanceClaim {
                sandbox: "sbx_cuttlefish_test".into(),
                pid: 1234,
            })
            .unwrap(),
        )
        .unwrap();

        let claim = read_claim(&path).unwrap();
        assert_eq!(claim.sandbox, "sbx_cuttlefish_test");
        assert_eq!(claim.pid, 1234);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn dead_prelaunch_claim_is_reclaimed_but_live_claim_is_retained() {
        let directory = tempdir().unwrap();
        let runtime = CuttlefishRuntime::new(CuttlefishRuntimeConfig {
            home: directory.path().into(),
            artifacts: None,
            boot_timeout: Duration::from_secs(1),
            shutdown_timeout: Duration::from_secs(1),
        })
        .unwrap();
        fs::create_dir_all(runtime.claim_dir()).unwrap();
        let path = runtime.claim_path(1);

        fs::write(
            &path,
            serde_json::to_vec(&InstanceClaim {
                sandbox: "sbx_cuttlefish_dead".into(),
                pid: u32::MAX,
            })
            .unwrap(),
        )
        .unwrap();
        assert!(runtime.reclaim_abandoned_claim(&path).unwrap());
        assert!(!path.exists());

        fs::write(
            &path,
            serde_json::to_vec(&InstanceClaim {
                sandbox: "sbx_cuttlefish_live".into(),
                pid: std::process::id(),
            })
            .unwrap(),
        )
        .unwrap();
        assert!(!runtime.reclaim_abandoned_claim(&path).unwrap());
        assert!(path.exists());
    }
}
