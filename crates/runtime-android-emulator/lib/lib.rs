//! Cross-platform Android SDK Emulator runtime adapter.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, BTreeSet},
    env,
    ffi::OsString,
    fs::{self, OpenOptions},
    io::Write,
    net::{Ipv4Addr, TcpListener},
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
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
use sysinfo::{Pid, ProcessesToUpdate, Signal, System};
use tokio::{
    io::{AsyncRead, AsyncReadExt},
    process::Command,
    sync::mpsc,
};

mod state;

use state::{EmulatorState, STATE_VERSION};

const FIRST_CONSOLE_PORT: u16 = 5554;
const LAST_CONSOLE_PORT: u16 = 5682;
const ADB_SERVER_BASE_PORT: u16 = 7600;
const ADB_COMMAND_TIMEOUT: Duration = Duration::from_secs(30);
const MAX_DIRECTORY_OUTPUT_BYTES: usize = 16 * 1024 * 1024;
const GUEST_WORKSPACE: &str = "/data/local/tmp/asbx/workspace";
const GUEST_ARTIFACTS: &str = "/data/local/tmp/asbx/out";
static TRANSFER_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Host-side Android SDK Emulator configuration.
#[derive(Debug, Clone)]
pub struct AndroidEmulatorRuntimeConfig {
    /// Durable wrapper-owned emulator state directory.
    pub home: PathBuf,
    /// Android SDK root override.
    pub sdk_root: Option<PathBuf>,
    /// Android Emulator executable override.
    pub emulator: Option<PathBuf>,
    /// ADB executable override.
    pub adb: Option<PathBuf>,
    /// Default source AVD name.
    pub avd: Option<String>,
    /// Device boot and ADB readiness deadline.
    pub boot_timeout: Duration,
    /// Graceful emulator shutdown deadline.
    pub shutdown_timeout: Duration,
    /// Emulator graphics backend.
    pub gpu: String,
}

/// Runtime adapter backed by the Android SDK Emulator and ADB.
pub struct AndroidEmulatorRuntime {
    config: AndroidEmulatorRuntimeConfig,
}

#[derive(Debug, Clone)]
struct EmulatorTools {
    sdk_root: PathBuf,
    emulator: PathBuf,
    adb: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
struct PortClaim {
    sandbox: String,
    pid: u32,
}

struct PendingClaim {
    path: Option<PathBuf>,
}

struct PendingDevice {
    directory: PathBuf,
    claim: PathBuf,
    committed: bool,
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

impl AndroidEmulatorRuntime {
    /// Construct the Android Emulator backend without starting host tools.
    pub fn new(config: AndroidEmulatorRuntimeConfig) -> Result<Self> {
        if config.home.to_str().is_none() {
            return Err(RuntimeError::Configuration(
                "the Android Emulator state directory must be valid UTF-8".into(),
            ));
        }
        if config.boot_timeout.is_zero() {
            return Err(RuntimeError::Configuration(
                "android_emulator.boot_timeout must be greater than zero".into(),
            ));
        }
        if config.shutdown_timeout.is_zero() {
            return Err(RuntimeError::Configuration(
                "android_emulator.shutdown_timeout must be greater than zero".into(),
            ));
        }
        if !matches!(
            config.gpu.as_str(),
            "auto" | "host" | "software" | "swiftshader" | "swangle" | "lavapipe"
        ) {
            return Err(RuntimeError::Configuration(format!(
                "android_emulator.gpu {:?} is unsupported",
                config.gpu
            )));
        }
        if let Some(avd) = config.avd.as_deref() {
            validate_avd_name(avd)?;
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

    fn load_state(&self, sandbox: &str) -> Result<EmulatorState> {
        state::load(&self.state_path(sandbox)?)
    }

    fn save_state(&self, state: &EmulatorState) -> Result<()> {
        state::save(&self.state_path(&state.id)?, state)
    }

    fn claim_dir(&self) -> PathBuf {
        self.config.home.join("claims")
    }

    fn claim_path(&self, console_port: u16) -> PathBuf {
        self.claim_dir().join(format!("{console_port}.claim"))
    }

    fn claim_ports(&self, sandbox: &str) -> Result<(u16, u16, u16, PathBuf)> {
        fs::create_dir_all(self.claim_dir()).map_err(|error| {
            state::io_error(
                "create Android Emulator port-claim directory",
                &self.claim_dir(),
                error,
            )
        })?;
        let claim = serde_json::to_vec(&PortClaim {
            sandbox: sandbox.into(),
            pid: std::process::id(),
        })
        .map_err(|error| RuntimeError::Backend {
            operation: "encode Android Emulator port claim",
            message: error.to_string(),
        })?;
        for console_port in (FIRST_CONSOLE_PORT..=LAST_CONSOLE_PORT).step_by(2) {
            let adb_port = console_port.checked_add(1).ok_or_else(|| {
                RuntimeError::Configuration("Android Emulator ADB port overflow".into())
            })?;
            let slot = (console_port - FIRST_CONSOLE_PORT) / 2;
            let adb_server_port = ADB_SERVER_BASE_PORT.checked_add(slot).ok_or_else(|| {
                RuntimeError::Configuration("Android Emulator ADB server port overflow".into())
            })?;
            let Ok(_console_listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, console_port))
            else {
                continue;
            };
            let Ok(_adb_listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, adb_port)) else {
                continue;
            };
            let Ok(_server_listener) = TcpListener::bind((Ipv4Addr::LOCALHOST, adb_server_port))
            else {
                continue;
            };
            let path = self.claim_path(console_port);
            for attempt in 0..=1 {
                match OpenOptions::new().write(true).create_new(true).open(&path) {
                    Ok(mut file) => {
                        if let Err(error) = file.write_all(&claim) {
                            drop(file);
                            let _ = fs::remove_file(&path);
                            return Err(state::io_error(
                                "write Android Emulator port claim",
                                &path,
                                error,
                            ));
                        }
                        return Ok((console_port, adb_port, adb_server_port, path));
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
                            "reserve Android Emulator ports",
                            &path,
                            error,
                        ));
                    }
                }
            }
        }
        Err(RuntimeError::Backend {
            operation: "reserve Android Emulator ports",
            message: format!(
                "no free console/ADB pair in {FIRST_CONSOLE_PORT}..={LAST_CONSOLE_PORT}"
            ),
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
                    "remove abandoned Android Emulator device directory",
                    &directory,
                    error,
                ));
            }
        }
        match fs::remove_file(path) {
            Ok(()) => Ok(true),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
            Err(error) => Err(state::io_error(
                "remove abandoned Android Emulator port claim",
                path,
                error,
            )),
        }
    }

    fn adb_command(&self, state: &EmulatorState) -> Command {
        let mut command = Command::new(&state.adb);
        command
            .arg("-P")
            .arg(state.adb_server_port.to_string())
            .args(["-s", &state.serial])
            .env("ANDROID_ADB_SERVER_PORT", state.adb_server_port.to_string())
            .env("ADB_SERVER_PORT", state.adb_server_port.to_string());
        command
    }

    async fn start_adb_server(tools: &EmulatorTools, server_port: u16) -> Result<()> {
        let mut command = Command::new(&tools.adb);
        command
            .arg("-P")
            .arg(server_port.to_string())
            .arg("start-server")
            .env("ANDROID_ADB_SERVER_PORT", server_port.to_string())
            .env("ADB_SERVER_PORT", server_port.to_string())
            .kill_on_drop(true);
        let result = tokio::time::timeout(Duration::from_secs(10), command.output())
            .await
            .map_err(|_| RuntimeError::Backend {
                operation: "start Android Emulator ADB server",
                message: format!("ADB server on port {server_port} did not start within 10s"),
            })?
            .map_err(|error| RuntimeError::Backend {
                operation: "start Android Emulator ADB server",
                message: error.to_string(),
            })
            .and_then(|output| ensure_success("start Android Emulator ADB server", output));
        if let Err(error) = result {
            let _ = Self::kill_adb_server_at(&tools.adb, server_port).await;
            return Err(error);
        }
        Ok(())
    }

    async fn kill_adb_server(&self, state: &EmulatorState) -> Result<()> {
        Self::kill_adb_server_at(&state.adb, state.adb_server_port).await
    }

    async fn kill_adb_server_at(adb: &Path, server_port: u16) -> Result<()> {
        let mut command = Command::new(adb);
        command
            .arg("-P")
            .arg(server_port.to_string())
            .arg("kill-server")
            .env("ANDROID_ADB_SERVER_PORT", server_port.to_string())
            .env("ADB_SERVER_PORT", server_port.to_string())
            .stdin(Stdio::null())
            .kill_on_drop(true);
        let output = tokio::time::timeout(Duration::from_secs(5), command.output())
            .await
            .map_err(|_| RuntimeError::Backend {
                operation: "stop Android Emulator ADB server",
                message: format!("ADB server on port {server_port} did not stop within 5s"),
            })?
            .map_err(|error| RuntimeError::Backend {
                operation: "stop Android Emulator ADB server",
                message: error.to_string(),
            })?;
        ensure_success("stop Android Emulator ADB server", output).map(|_| ())
    }

    async fn wait_ready(&self, state: &EmulatorState) -> Result<()> {
        let deadline = Instant::now() + self.config.boot_timeout;
        let mut wait = self.adb_command(state);
        wait.arg("wait-for-device").kill_on_drop(true);
        tokio::time::timeout(self.config.boot_timeout, wait.output())
            .await
            .map_err(|_| RuntimeError::Backend {
                operation: "wait for Android Emulator ADB",
                message: format!(
                    "{} was not visible within {:?}",
                    state.serial, self.config.boot_timeout
                ),
            })?
            .map_err(|error| RuntimeError::Backend {
                operation: "wait for Android Emulator ADB",
                message: error.to_string(),
            })
            .and_then(|output| ensure_success("wait for Android Emulator ADB", output))?;

        let mut last_adb_error = None;
        loop {
            if !emulator_process_alive(state) {
                return Err(RuntimeError::Backend {
                    operation: "wait for Android Emulator boot",
                    message: format!(
                        "emulator process {} exited before Android completed booting",
                        state.pid
                    ),
                });
            }
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                let last_error = last_adb_error
                    .as_deref()
                    .map(|error| format!("; last transient ADB error: {error}"))
                    .unwrap_or_default();
                return Err(RuntimeError::Backend {
                    operation: "wait for Android Emulator boot",
                    message: format!(
                        "{} did not complete booting within {:?}{last_error}",
                        state.serial, self.config.boot_timeout,
                    ),
                });
            }
            match self
                .remote_output_state_timeout(
                    state,
                    "check Android Emulator boot",
                    "getprop sys.boot_completed",
                    remaining.min(Duration::from_secs(10)),
                )
                .await
            {
                Ok(output) if String::from_utf8_lossy(&output).trim() == "1" => return Ok(()),
                Ok(_) => {}
                Err(error) => last_adb_error = Some(error.to_string()),
            }
            if Instant::now() >= deadline {
                let last_error = last_adb_error
                    .as_deref()
                    .map(|error| format!("; last transient ADB error: {error}"))
                    .unwrap_or_default();
                return Err(RuntimeError::Backend {
                    operation: "wait for Android Emulator boot",
                    message: format!(
                        "{} did not complete booting within {:?}{last_error}",
                        state.serial, self.config.boot_timeout,
                    ),
                });
            }
            tokio::time::sleep(Duration::from_secs(1)).await;
        }
    }

    async fn stop_state(&self, state: &mut EmulatorState, force: bool) -> Result<()> {
        if !emulator_process_alive(state) {
            state.active = false;
            self.save_state(state)?;
            return self.kill_adb_server(state).await;
        }

        if !force {
            let mut command = self.adb_command(state);
            command.args(["emu", "kill"]).kill_on_drop(true);
            let output = tokio::time::timeout(Duration::from_secs(10), command.output())
                .await
                .map_err(|_| RuntimeError::Backend {
                    operation: "stop Android Emulator",
                    message: "ADB emulator shutdown command timed out".into(),
                })?
                .map_err(|error| RuntimeError::Backend {
                    operation: "stop Android Emulator",
                    message: error.to_string(),
                })?;
            ensure_success("stop Android Emulator", output)?;
            if !wait_process_stopped(state, self.config.shutdown_timeout).await {
                return Err(RuntimeError::Backend {
                    operation: "stop Android Emulator",
                    message: format!(
                        "process {} did not stop within {:?}",
                        state.pid, self.config.shutdown_timeout
                    ),
                });
            }
        } else {
            let mut command = self.adb_command(state);
            command.args(["emu", "kill"]).kill_on_drop(true);
            let _ = tokio::time::timeout(Duration::from_secs(2), command.output()).await;
            if !wait_process_stopped(state, Duration::from_secs(2)).await {
                kill_emulator_process(state);
            }
            if !wait_process_stopped(state, Duration::from_secs(3)).await {
                return Err(RuntimeError::Backend {
                    operation: "kill Android Emulator",
                    message: format!("could not terminate process {}", state.pid),
                });
            }
        }
        state.active = false;
        self.save_state(state)?;
        self.kill_adb_server(state).await
    }

    async fn remote_output(
        &self,
        sandbox: &str,
        operation: &'static str,
        script: &str,
    ) -> Result<Vec<u8>> {
        let state = self.load_state(sandbox)?;
        self.remote_output_state(&state, operation, script).await
    }

    async fn remote_output_state(
        &self,
        state: &EmulatorState,
        operation: &'static str,
        script: &str,
    ) -> Result<Vec<u8>> {
        self.remote_output_state_timeout(state, operation, script, ADB_COMMAND_TIMEOUT)
            .await
    }

    async fn remote_output_state_timeout(
        &self,
        state: &EmulatorState,
        operation: &'static str,
        script: &str,
        timeout: Duration,
    ) -> Result<Vec<u8>> {
        if !state.active || !emulator_process_alive(state) {
            return Err(RuntimeError::Backend {
                operation,
                message: "Android Emulator is stopped".into(),
            });
        }
        let mut command = self.adb_command(state);
        add_adb_shell_command(&mut command, script, false);
        command.kill_on_drop(true);
        let output = tokio::time::timeout(timeout, command.output())
            .await
            .map_err(|_| RuntimeError::Backend {
                operation,
                message: format!("ADB command timed out after {timeout:?}"),
            })?
            .map_err(|error| RuntimeError::Backend {
                operation,
                message: error.to_string(),
            })?;
        ensure_success(operation, output).map(|output| output.stdout)
    }

    async fn adb_transfer(
        &self,
        state: &EmulatorState,
        operation: &'static str,
        arguments: &[OsString],
    ) -> Result<()> {
        if !state.active || !emulator_process_alive(state) {
            return Err(RuntimeError::Backend {
                operation,
                message: "Android Emulator is stopped".into(),
            });
        }
        let mut command = self.adb_command(state);
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

    fn info(&self, state: &EmulatorState, status: String) -> SandboxInfo {
        SandboxInfo {
            id: state.id.clone(),
            backend: BackendId::android_emulator(),
            status,
            created_at: Some(state.created_at),
            metadata: BTreeMap::from([
                ("avd".into(), state.source_avd.clone()),
                ("private_avd".into(), state.private_avd.clone()),
                ("adb_serial".into(), state.serial.clone()),
                ("adb_server_port".into(), state.adb_server_port.to_string()),
                ("console_port".into(), state.console_port.to_string()),
                ("workspace".into(), GUEST_WORKSPACE.into()),
                ("artifacts".into(), GUEST_ARTIFACTS.into()),
            ]),
        }
    }
}

#[async_trait]
impl SandboxRuntime for AndroidEmulatorRuntime {
    fn backend_id(&self) -> BackendId {
        BackendId::android_emulator()
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: self.backend_id(),
            boot_sources: vec![BootSourceKind::AndroidAvd],
            features: vec![
                RuntimeFeature::Exec,
                RuntimeFeature::Attach,
                RuntimeFeature::FileTransfer,
            ],
            architectures: vec!["x86_64".into(), "arm64-v8a".into()],
            accelerators: match env::consts::OS {
                "macos" => vec!["auto".into(), "hvf".into()],
                "windows" => vec!["auto".into(), "whpx".into()],
                "linux" => vec!["auto".into(), "kvm".into()],
                _ => vec![],
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
        let RootSource::AndroidEmulator(android) = &spec.root else {
            unreachable!("validated Android Emulator create source");
        };
        let tools = resolve_tools(&self.config)?;
        validate_avd_name(&android.name)?;
        let source_avd = locate_avd(&android.name)?;
        let (console_port, adb_port, adb_server_port, claim) = self.claim_ports(&spec.id)?;
        let mut claim = PendingClaim::new(claim);
        let directory = self.device_dir(&spec.id)?;
        fs::create_dir_all(directory.parent().expect("device directory has a parent")).map_err(
            |error| {
                state::io_error(
                    "create Android Emulator device-state root",
                    directory.parent().expect("device directory has a parent"),
                    error,
                )
            },
        )?;
        fs::create_dir(&directory).map_err(|error| {
            state::io_error(
                "create Android Emulator device directory",
                &directory,
                error,
            )
        })?;
        let pending = PendingDevice::new(directory.clone(), claim.take());
        secure_directory(&directory)?;
        let private_avd = private_avd_name(&spec.id);
        let avd_home = prepare_private_avd(
            &source_avd,
            &directory,
            &private_avd,
            spec,
            &self.config.gpu,
        )?;
        let process_log = directory.join("emulator.log");
        let stdout = fs::File::create(&process_log).map_err(|error| {
            state::io_error("create Android Emulator process log", &process_log, error)
        })?;
        let stderr = stdout.try_clone().map_err(|error| {
            state::io_error(
                "duplicate Android Emulator process log",
                &process_log,
                error,
            )
        })?;
        Self::start_adb_server(&tools, adb_server_port).await?;
        let mut command = Command::new(&tools.emulator);
        command
            .args(launch_arguments(
                &private_avd,
                console_port,
                spec,
                &self.config.gpu,
            ))
            .env("ANDROID_SDK_ROOT", &tools.sdk_root)
            .env("ANDROID_HOME", &tools.sdk_root)
            .env("ANDROID_AVD_HOME", &avd_home)
            .env("ANDROID_ADB_SERVER_PORT", adb_server_port.to_string())
            .env("ADB_SERVER_PORT", adb_server_port.to_string())
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr))
            .kill_on_drop(false);
        let mut child = match command.spawn() {
            Ok(child) => child,
            Err(error) => {
                let _ = Self::kill_adb_server_at(&tools.adb, adb_server_port).await;
                return Err(RuntimeError::Backend {
                    operation: "start Android Emulator",
                    message: format!("{}: {error}", tools.emulator.display()),
                });
            }
        };
        let Some(pid) = child.id() else {
            let _ = child.kill().await;
            let _ = Self::kill_adb_server_at(&tools.adb, adb_server_port).await;
            return Err(RuntimeError::Backend {
                operation: "start Android Emulator",
                message: "spawned emulator process has no PID".into(),
            });
        };
        let process_started_at = match wait_for_process_start(pid, Duration::from_secs(5)).await {
            Some(started_at) => started_at,
            None => {
                let _ = child.kill().await;
                let _ = Self::kill_adb_server_at(&tools.adb, adb_server_port).await;
                return Err(RuntimeError::Backend {
                    operation: "start Android Emulator",
                    message: format!(
                        "cannot capture process identity for PID {pid}; see {}",
                        process_log.display()
                    ),
                });
            }
        };
        let state = EmulatorState {
            version: STATE_VERSION,
            id: spec.id.clone(),
            source_avd: android.name.clone(),
            private_avd,
            sdk_root: tools.sdk_root,
            emulator: tools.emulator,
            adb: tools.adb,
            pid,
            process_started_at,
            console_port,
            adb_port,
            adb_server_port,
            serial: format!("emulator-{console_port}"),
            created_at: Utc::now(),
            default_user: spec.user.clone(),
            default_env: spec.env.clone(),
            active: true,
        };
        if let Err(error) = self.save_state(&state) {
            let _ = child.kill().await;
            let _ = Self::kill_adb_server_at(&state.adb, state.adb_server_port).await;
            return Err(error);
        }
        tokio::spawn(async move {
            let _ = child.wait().await;
        });

        if let Err(error) = self.wait_ready(&state).await {
            let mut cleanup_state = state.clone();
            let cleanup = self.stop_state(&mut cleanup_state, true).await;
            return failed_creation(pending, error, cleanup);
        }
        if let Err(error) = self
            .remote_output_state(
                &state,
                "initialize Android Emulator guest directories",
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
            let mut cleanup_state = state.clone();
            let cleanup = self.stop_state(&mut cleanup_state, true).await;
            return failed_creation(pending, error, cleanup);
        }
        pending.commit();
        Ok(self.info(&state, "running".into()))
    }

    async fn stop(&self, sandbox: &str) -> Result<()> {
        let mut state = self.load_state(sandbox)?;
        self.stop_state(&mut state, false).await
    }

    async fn kill(&self, sandbox: &str) -> Result<()> {
        let mut state = self.load_state(sandbox)?;
        self.stop_state(&mut state, true).await
    }

    async fn remove(&self, sandbox: &str) -> Result<()> {
        let state = self.load_state(sandbox)?;
        if emulator_process_alive(&state) {
            return Err(RuntimeError::Backend {
                operation: "remove Android Emulator",
                message: "emulator process is still running".into(),
            });
        }
        self.kill_adb_server(&state).await?;
        let claim = self.claim_path(state.console_port);
        match read_claim(&claim) {
            Ok(owner) if owner.sandbox == sandbox => {
                fs::remove_file(&claim).map_err(|error| {
                    state::io_error("release Android Emulator port claim", &claim, error)
                })?;
            }
            Ok(_) | Err(RuntimeError::NotFound(_)) => {}
            Err(error) => return Err(error),
        }
        let directory = self.device_dir(sandbox)?;
        fs::remove_dir_all(&directory)
            .map_err(|error| state::io_error("remove Android Emulator state", &directory, error))
    }

    async fn list(&self) -> Result<Vec<SandboxInfo>> {
        let root = self.config.home.join("devices");
        let entries = match fs::read_dir(&root) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(vec![]),
            Err(error) => {
                return Err(state::io_error(
                    "list Android Emulator states",
                    &root,
                    error,
                ));
            }
        };
        let mut devices = Vec::new();
        for entry in entries {
            let entry = entry.map_err(|error| {
                state::io_error("read Android Emulator state entry", &root, error)
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
        let status = if emulator_process_alive(&state) {
            "running"
        } else if state.active {
            "crashed"
        } else {
            "stopped"
        };
        Ok(self.info(&state, status.into()))
    }

    async fn doctor(&self) -> Result<Vec<(String, bool, String)>> {
        let os_supported = matches!(env::consts::OS, "linux" | "macos" | "windows");
        let mut checks = vec![(
            "Android Emulator / host OS".into(),
            os_supported,
            if os_supported {
                format!("{} host is supported", env::consts::OS)
            } else {
                format!(
                    "{} is not a supported Android Emulator host",
                    env::consts::OS
                )
            },
        )];
        let tools = match resolve_tools(&self.config) {
            Ok(tools) => tools,
            Err(error) => {
                checks.push((
                    "Android Emulator / SDK tools".into(),
                    false,
                    error.to_string(),
                ));
                return Ok(checks);
            }
        };
        checks.push((
            "Android Emulator / SDK tools".into(),
            true,
            format!(
                "emulator={} adb={}",
                tools.emulator.display(),
                tools.adb.display()
            ),
        ));

        let mut acceleration = Command::new(&tools.emulator);
        acceleration.arg("-accel-check").kill_on_drop(true);
        let acceleration =
            tokio::time::timeout(Duration::from_secs(15), acceleration.output()).await;
        match acceleration {
            Ok(Ok(output)) if output.status.success() => checks.push((
                "Android Emulator / acceleration".into(),
                true,
                compact_output(&output),
            )),
            Ok(Ok(output)) => checks.push((
                "Android Emulator / acceleration".into(),
                false,
                compact_output(&output),
            )),
            Ok(Err(error)) => checks.push((
                "Android Emulator / acceleration".into(),
                false,
                error.to_string(),
            )),
            Err(_) => checks.push((
                "Android Emulator / acceleration".into(),
                false,
                "emulator -accel-check timed out".into(),
            )),
        }

        match self.config.avd.as_deref() {
            Some(avd) => match locate_avd(avd) {
                Ok(path) => checks.push((
                    "Android Emulator / AVD".into(),
                    true,
                    format!("{avd} ({})", path.display()),
                )),
                Err(error) => {
                    checks.push(("Android Emulator / AVD".into(), false, error.to_string()))
                }
            },
            None => match list_avds(&tools).await {
                Ok(avds) if avds.is_empty() => checks.push((
                    "Android Emulator / AVD".into(),
                    false,
                    "no AVDs were discovered; create one with avdmanager or Android Studio".into(),
                )),
                Ok(avds) => checks.push((
                    "Android Emulator / AVD".into(),
                    true,
                    format!(
                        "no default configured; pass --android-avd or choose from: {}",
                        avds.join(", ")
                    ),
                )),
                Err(error) => checks.push((
                    "Android Emulator / AVD".into(),
                    false,
                    format!("could not list AVDs: {error}"),
                )),
            },
        }
        Ok(checks)
    }
}

#[async_trait]
impl CommandRuntime for AndroidEmulatorRuntime {
    async fn exec_stream(&self, sandbox: &str, request: ExecRequest) -> Result<ExecStream> {
        let state = self.load_state(sandbox)?;
        if !state.active || !emulator_process_alive(&state) {
            return Err(RuntimeError::Backend {
                operation: "execute Android Emulator guest command",
                message: "Android Emulator is stopped".into(),
            });
        }
        let request = request_with_defaults(request, &state);
        let remote = remote_command(&request);
        let mut command = self.adb_command(&state);
        add_adb_shell_command(&mut command, &remote, false);
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command.spawn().map_err(|error| RuntimeError::Backend {
            operation: "start Android Emulator guest command",
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
impl TerminalRuntime for AndroidEmulatorRuntime {
    async fn attach(&self, sandbox: &str, request: ExecRequest) -> Result<i32> {
        let state = self.load_state(sandbox)?;
        if !state.active || !emulator_process_alive(&state) {
            return Err(RuntimeError::Backend {
                operation: "attach Android Emulator guest terminal",
                message: "Android Emulator is stopped".into(),
            });
        }
        let request = request_with_defaults(request, &state);
        let remote = remote_command(&request);
        let mut command = self.adb_command(&state);
        add_adb_shell_command(&mut command, &remote, true);
        command
            .stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());
        let status = command
            .status()
            .await
            .map_err(|error| RuntimeError::Backend {
                operation: "attach Android Emulator guest terminal",
                message: error.to_string(),
            })?;
        Ok(status.code().unwrap_or(-1))
    }
}

#[async_trait]
impl FileTransferRuntime for AndroidEmulatorRuntime {
    async fn mkdir(&self, sandbox: &str, guest_path: &str) -> Result<()> {
        validate_guest_path(guest_path)?;
        self.remote_output(
            sandbox,
            "create Android Emulator guest directory",
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
            "upload Android Emulator guest file",
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
                "commit Android Emulator guest file",
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
                    "remove partial Android Emulator guest file",
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
            "create Android Emulator guest symlink",
            &format!("ln -s {} {}", shell_quote(target), shell_quote(guest_path)),
        )
        .await?;
        Ok(())
    }

    async fn set_mode(&self, sandbox: &str, guest_path: &str, mode: u32) -> Result<()> {
        validate_guest_path(guest_path)?;
        self.remote_output(
            sandbox,
            "set Android Emulator guest path mode",
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
                "list Android Emulator guest directory",
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
                operation: "list Android Emulator guest directory",
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
                "download Android Emulator guest file",
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
        tempfile::TempPath::try_from_path(&temporary)
            .map_err(|error| {
                state::io_error(
                    "adopt downloaded Android Emulator guest file",
                    &temporary,
                    error,
                )
            })?
            .persist(host_path)
            .map_err(|error| {
                state::io_error(
                    "commit downloaded Android Emulator guest file",
                    host_path,
                    error.error,
                )
            })?;
        Ok(())
    }
}

fn validate_create_spec(spec: &CreateSpec) -> Result<()> {
    if !matches!(env::consts::OS, "linux" | "macos" | "windows") {
        return Err(RuntimeError::Unsupported(format!(
            "Android Emulator does not support {} hosts",
            env::consts::OS
        )));
    }
    if spec.backend.as_str() != BackendId::ANDROID_EMULATOR {
        return Err(RuntimeError::Configuration(format!(
            "Android Emulator received a create request for backend {}",
            spec.backend
        )));
    }
    if !matches!(spec.root, RootSource::AndroidEmulator(_)) {
        return Err(RuntimeError::Unsupported(
            "Android Emulator requires an AVD boot source".into(),
        ));
    }
    if !matches!(spec.workspace, WorkspaceSpec::None | WorkspaceSpec::Copy) {
        return Err(RuntimeError::Unsupported(
            "Android Emulator does not support host workspace mounts; use copy or none".into(),
        ));
    }
    if spec.network != NetworkMode::All {
        return Err(RuntimeError::Unsupported(
            "Android Emulator currently supports only explicitly host-gated unrestricted networking; portable egress isolation is not enforceable"
                .into(),
        ));
    }
    if !spec.network_rules.is_empty() {
        return Err(RuntimeError::Unsupported(
            "Android Emulator does not support wrapper network rules".into(),
        ));
    }
    if !spec.ports.is_empty() {
        return Err(RuntimeError::Unsupported(
            "Android Emulator guest port publication is not implemented".into(),
        ));
    }
    if spec.security != SecurityMode::Default {
        return Err(RuntimeError::Unsupported(
            "Android Emulator does not implement the wrapper restricted security profile".into(),
        ));
    }
    if spec.cpus == 0 {
        return Err(RuntimeError::Configuration(
            "Android Emulator requires at least one virtual CPU".into(),
        ));
    }
    if !(1536..=8192).contains(&spec.memory_mib) {
        return Err(RuntimeError::Configuration(format!(
            "Android Emulator memory must be between 1536 and 8192 MiB, received {} MiB",
            spec.memory_mib
        )));
    }
    if spec.disk_mib == 0 {
        return Err(RuntimeError::Configuration(
            "Android Emulator data partition must be greater than zero".into(),
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
                operation: "recover failed Android Emulator creation",
                message: format!(
                    "{error}; cleanup also failed ({cleanup_error}); retained runtime state for retry"
                ),
            })
        }
    }
}

fn launch_arguments(avd: &str, console_port: u16, spec: &CreateSpec, gpu: &str) -> Vec<String> {
    vec![
        "-avd".into(),
        avd.into(),
        "-port".into(),
        console_port.to_string(),
        "-no-window".into(),
        "-no-audio".into(),
        "-no-boot-anim".into(),
        "-no-snapshot".into(),
        "-wipe-data".into(),
        "-no-metrics".into(),
        "-camera-back".into(),
        "none".into(),
        "-camera-front".into(),
        "none".into(),
        "-gpu".into(),
        gpu.into(),
        "-accel".into(),
        "auto".into(),
        "-cores".into(),
        spec.cpus.to_string(),
        "-memory".into(),
        spec.memory_mib.to_string(),
    ]
}

fn prepare_private_avd(
    source: &Path,
    directory: &Path,
    private_name: &str,
    spec: &CreateSpec,
    gpu: &str,
) -> Result<PathBuf> {
    let source_config = source.join("config.ini");
    let config = fs::read_to_string(&source_config)
        .map_err(|error| state::io_error("read source AVD configuration", &source_config, error))?;
    let mut values = parse_ini(&config);
    values.insert("avd.ini.displayname".into(), private_name.into());
    values.insert(
        "disk.dataPartition.size".into(),
        format!("{}M", spec.disk_mib),
    );
    values.insert("fastboot.forceChosenSnapshotBoot".into(), "no".into());
    values.insert("fastboot.forceColdBoot".into(), "yes".into());
    values.insert("fastboot.forceFastBoot".into(), "no".into());
    values.insert("hw.audioInput".into(), "no".into());
    values.insert("hw.camera.back".into(), "none".into());
    values.insert("hw.camera.front".into(), "none".into());
    values.insert("hw.cpu.ncore".into(), spec.cpus.to_string());
    values.insert("hw.gpu.enabled".into(), "yes".into());
    values.insert("hw.gpu.mode".into(), gpu.into());
    values.insert("hw.ramSize".into(), spec.memory_mib.to_string());
    values.insert("hw.sdCard".into(), "no".into());
    values.insert("showDeviceFrame".into(), "no".into());

    let avd_home = directory.join("avd-home");
    let private_dir = avd_home.join(format!("{private_name}.avd"));
    fs::create_dir_all(&private_dir).map_err(|error| {
        state::io_error(
            "create private Android Emulator AVD directory",
            &private_dir,
            error,
        )
    })?;
    let rendered = values
        .iter()
        .map(|(key, value)| format!("{key}={value}\n"))
        .collect::<String>();
    fs::write(private_dir.join("config.ini"), rendered).map_err(|error| {
        state::io_error(
            "write private Android Emulator AVD configuration",
            &private_dir.join("config.ini"),
            error,
        )
    })?;
    let target = values.get("target").cloned().unwrap_or_default();
    let private_path = utf8_path(&private_dir, "private Android Emulator AVD directory")?;
    let ini = format!(
        "avd.ini.encoding=UTF-8\npath={private_path}\ntarget={target}\nAvdId={private_name}\n"
    );
    fs::write(avd_home.join(format!("{private_name}.ini")), ini).map_err(|error| {
        state::io_error(
            "write private Android Emulator AVD descriptor",
            &avd_home.join(format!("{private_name}.ini")),
            error,
        )
    })?;
    Ok(avd_home)
}

fn parse_ini(contents: &str) -> BTreeMap<String, String> {
    contents
        .lines()
        .filter_map(|line| {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                return None;
            }
            line.split_once('=')
                .map(|(key, value)| (key.trim().into(), value.trim().into()))
        })
        .collect()
}

fn resolve_tools(config: &AndroidEmulatorRuntimeConfig) -> Result<EmulatorTools> {
    let emulator = resolve_executable(
        config.emulator.as_deref(),
        config.sdk_root.as_deref(),
        "emulator",
        "emulator",
    )?;
    let sdk_root = resolve_sdk_root(config.sdk_root.as_deref(), &emulator)?;
    let adb = resolve_executable(
        config.adb.as_deref(),
        Some(&sdk_root),
        "platform-tools",
        "adb",
    )?;
    Ok(EmulatorTools {
        sdk_root,
        emulator,
        adb,
    })
}

fn resolve_sdk_root(explicit: Option<&Path>, emulator: &Path) -> Result<PathBuf> {
    if let Some(path) = explicit {
        if !path.is_dir() {
            return Err(RuntimeError::Configuration(format!(
                "configured android_emulator.sdk_root {} is not a directory",
                path.display()
            )));
        }
        return path
            .canonicalize()
            .map_err(|error| state::io_error("resolve configured Android SDK root", path, error));
    }
    let mut candidates = Vec::new();
    for key in ["ANDROID_SDK_ROOT", "ANDROID_HOME"] {
        if let Some(path) = env::var_os(key) {
            candidates.push(PathBuf::from(path));
        }
    }
    if let Some(parent) = emulator.parent().and_then(Path::parent) {
        candidates.push(parent.to_path_buf());
    }
    if let Some(home) = dirs::home_dir() {
        candidates.push(home.join("Library").join("Android").join("sdk"));
        candidates.push(home.join("Android").join("Sdk"));
        candidates.push(
            home.join("AppData")
                .join("Local")
                .join("Android")
                .join("Sdk"),
        );
    }
    for candidate in candidates {
        if candidate.is_dir() {
            return candidate
                .canonicalize()
                .map_err(|error| state::io_error("resolve Android SDK root", &candidate, error));
        }
    }
    Err(RuntimeError::Configuration(
        "cannot locate the Android SDK root; configure android_emulator.sdk_root or ANDROID_SDK_ROOT"
            .into(),
    ))
}

fn resolve_executable(
    explicit: Option<&Path>,
    sdk_root: Option<&Path>,
    component: &str,
    name: &str,
) -> Result<PathBuf> {
    let executable = executable_name(name);
    if let Some(path) = explicit {
        if !path.is_file() {
            return Err(RuntimeError::Configuration(format!(
                "configured android_emulator.{name} {} is not a file",
                path.display()
            )));
        }
        return path.canonicalize().map_err(|error| {
            state::io_error("resolve configured Android SDK executable", path, error)
        });
    }
    if let Some(root) = sdk_root {
        let candidate = root.join(component).join(&executable);
        if !candidate.is_file() {
            return Err(RuntimeError::Configuration(format!(
                "configured android_emulator.sdk_root {} has no {}",
                root.display(),
                candidate.strip_prefix(root).unwrap_or(&candidate).display()
            )));
        }
        return candidate
            .canonicalize()
            .map_err(|error| state::io_error("resolve Android SDK executable", &candidate, error));
    }
    let mut candidates = Vec::new();
    if let Ok(path) = which::which(name) {
        candidates.push(path);
    }
    if let Some(home) = dirs::home_dir() {
        for root in [
            home.join("Library").join("Android").join("sdk"),
            home.join("Android").join("Sdk"),
            home.join("AppData")
                .join("Local")
                .join("Android")
                .join("Sdk"),
        ] {
            candidates.push(root.join(component).join(&executable));
        }
    }
    for candidate in candidates {
        if candidate.is_file() {
            return candidate.canonicalize().map_err(|error| {
                state::io_error("resolve Android SDK executable", &candidate, error)
            });
        }
    }
    Err(RuntimeError::Configuration(format!(
        "cannot locate Android SDK {name}; configure android_emulator.{name} or android_emulator.sdk_root"
    )))
}

fn executable_name(name: &str) -> OsString {
    if cfg!(windows) {
        format!("{name}.exe").into()
    } else {
        name.into()
    }
}

fn avd_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();
    if let Some(path) = env::var_os("ANDROID_AVD_HOME") {
        roots.push(PathBuf::from(path));
    }
    if let Some(path) = env::var_os("ANDROID_USER_HOME") {
        roots.push(PathBuf::from(path).join("avd"));
    }
    if let Some(path) = env::var_os("ANDROID_SDK_HOME") {
        roots.push(PathBuf::from(path).join(".android").join("avd"));
    }
    if let Some(home) = dirs::home_dir() {
        roots.push(home.join(".android").join("avd"));
    }
    let mut unique = BTreeSet::new();
    roots
        .into_iter()
        .filter(|path| unique.insert(path.clone()))
        .collect()
}

fn locate_avd(name: &str) -> Result<PathBuf> {
    validate_avd_name(name)?;
    for root in avd_roots() {
        let descriptor = root.join(format!("{name}.ini"));
        let contents = match fs::read_to_string(&descriptor) {
            Ok(contents) => contents,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(state::io_error(
                    "read Android Emulator AVD descriptor",
                    &descriptor,
                    error,
                ));
            }
        };
        let values = parse_ini(&contents);
        let directory = values
            .get("path")
            .map(PathBuf::from)
            .unwrap_or_else(|| root.join(format!("{name}.avd")));
        let directory = directory.canonicalize().map_err(|error| {
            state::io_error("resolve Android Emulator AVD directory", &directory, error)
        })?;
        if !directory.join("config.ini").is_file() {
            return Err(RuntimeError::Configuration(format!(
                "AVD {name:?} has no config.ini in {}",
                directory.display()
            )));
        }
        return Ok(directory);
    }
    Err(RuntimeError::Configuration(format!(
        "Android Emulator AVD {name:?} was not found; create it with avdmanager or Android Studio"
    )))
}

async fn list_avds(tools: &EmulatorTools) -> Result<Vec<String>> {
    let mut command = Command::new(&tools.emulator);
    command.arg("-list-avds").kill_on_drop(true);
    let output = tokio::time::timeout(Duration::from_secs(15), command.output())
        .await
        .map_err(|_| RuntimeError::Backend {
            operation: "list Android Emulator AVDs",
            message: "emulator -list-avds timed out".into(),
        })?
        .map_err(|error| RuntimeError::Backend {
            operation: "list Android Emulator AVDs",
            message: error.to_string(),
        })?;
    let output = ensure_success("list Android Emulator AVDs", output)?;
    Ok(String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect())
}

fn private_avd_name(sandbox: &str) -> String {
    format!("asbx_{}", sandbox.replace('-', "_"))
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

fn request_with_defaults(mut request: ExecRequest, state: &EmulatorState) -> ExecRequest {
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

fn compact_output(output: &std::process::Output) -> String {
    let text = if output.stdout.is_empty() {
        &output.stderr
    } else {
        &output.stdout
    };
    String::from_utf8_lossy(text)
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
}

fn read_claim(path: &Path) -> Result<PortClaim> {
    let bytes = fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            RuntimeError::NotFound(path.display().to_string())
        } else {
            state::io_error("read Android Emulator port claim", path, error)
        }
    })?;
    serde_json::from_slice(&bytes).map_err(|error| RuntimeError::Backend {
        operation: "decode Android Emulator port claim",
        message: format!("{}: {error}", path.display()),
    })
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
                        operation: "read Android Emulator guest command output",
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
            operation: "decode Android Emulator guest directory",
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
        operation: "decode Android Emulator guest directory",
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
            "invalid absolute Android Emulator guest path {path:?}"
        )));
    }
    Ok(())
}

fn validate_sandbox_id(sandbox: &str) -> Result<()> {
    if sandbox.is_empty()
        || sandbox.len() > 96
        || sandbox
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || "_-".contains(character)))
    {
        return Err(RuntimeError::Configuration(format!(
            "invalid Android Emulator sandbox identifier {sandbox:?}"
        )));
    }
    Ok(())
}

fn validate_avd_name(avd: &str) -> Result<()> {
    if avd.is_empty()
        || avd.len() > 96
        || avd
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || "_.-".contains(character)))
    {
        return Err(RuntimeError::Configuration(format!(
            "invalid Android Emulator AVD name {avd:?}"
        )));
    }
    Ok(())
}

fn utf8_path<'a>(path: &'a Path, label: &str) -> Result<&'a str> {
    path.to_str().ok_or_else(|| {
        RuntimeError::Configuration(format!("{label} {} is not valid UTF-8", path.display()))
    })
}

fn process_is_alive(pid: u32) -> bool {
    process_start_time(pid).is_some()
}

fn emulator_process_alive(state: &EmulatorState) -> bool {
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

async fn wait_process_stopped(state: &EmulatorState, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if !emulator_process_alive(state) {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

fn kill_emulator_process(state: &EmulatorState) -> bool {
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
        .map_err(|error| state::io_error("inspect Android Emulator state directory", path, error))?
        .permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(path, permissions)
        .map_err(|error| state::io_error("secure Android Emulator state directory", path, error))
}

#[cfg(not(unix))]
fn secure_directory(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    fn create_spec(network: NetworkMode) -> CreateSpec {
        CreateSpec {
            id: "sbx_android-emulator_test".into(),
            backend: BackendId::android_emulator(),
            root: RootSource::AndroidEmulator(Box::new(agent_sandbox_runtime::AndroidAvdSpec {
                name: "Pixel_API_36".into(),
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

    #[test]
    fn emulator_declares_cross_platform_android_layout() {
        let runtime = AndroidEmulatorRuntime::new(AndroidEmulatorRuntimeConfig {
            home: PathBuf::from("/tmp/asbx-android-emulator"),
            sdk_root: None,
            emulator: None,
            adb: None,
            avd: None,
            boot_timeout: Duration::from_secs(1),
            shutdown_timeout: Duration::from_secs(1),
            gpu: "auto".into(),
        })
        .unwrap();
        assert_eq!(runtime.backend_id(), BackendId::android_emulator());
        assert_eq!(runtime.guest_layout().workspace, GUEST_WORKSPACE);
        assert_eq!(runtime.guest_layout().artifacts, GUEST_ARTIFACTS);
    }

    #[test]
    fn launch_is_headless_ephemeral_and_uses_explicit_resources() {
        let arguments = launch_arguments(
            "asbx_test",
            5558,
            &create_spec(NetworkMode::All),
            "software",
        );
        for expected in [
            "-no-window",
            "-no-audio",
            "-no-snapshot",
            "-wipe-data",
            "-no-metrics",
        ] {
            assert!(arguments.contains(&expected.into()));
        }
        assert!(arguments.windows(2).any(|pair| pair == ["-port", "5558"]));
        assert!(arguments.windows(2).any(|pair| pair == ["-cores", "2"]));
        assert!(arguments.windows(2).any(|pair| pair == ["-memory", "2048"]));
    }

    #[test]
    fn rejects_network_modes_that_cannot_be_enforced_portably() {
        let error = validate_create_spec(&create_spec(NetworkMode::Off)).unwrap_err();
        assert!(error.to_string().contains("portable egress isolation"));
        validate_create_spec(&create_spec(NetworkMode::All)).unwrap();
    }

    #[test]
    fn rejects_memory_outside_emulator_limits() {
        let mut spec = create_spec(NetworkMode::All);
        spec.memory_mib = 1024;
        assert!(
            validate_create_spec(&spec)
                .unwrap_err()
                .to_string()
                .contains("between 1536 and 8192")
        );
        spec.memory_mib = 8193;
        assert!(validate_create_spec(&spec).is_err());
    }

    #[test]
    fn configured_tool_paths_do_not_silently_fall_back() {
        let directory = tempdir().unwrap();
        let missing = directory.path().join("missing-emulator");
        let error = resolve_executable(Some(&missing), None, "emulator", "emulator").unwrap_err();
        assert!(error.to_string().contains("is not a file"));

        let missing_sdk = directory.path().join("missing-sdk");
        let error = resolve_sdk_root(Some(&missing_sdk), directory.path()).unwrap_err();
        assert!(error.to_string().contains("is not a directory"));
    }

    #[test]
    fn android_commands_preserve_argument_boundaries() {
        let command = remote_command(&request());
        assert!(command.starts_with("cd '/data/local/tmp/asbx/workspace' && exec env "));
        assert!(command.contains("'a b'\"'\"';$(touch nope)'"));
        assert!(command.contains("'TOKEN=x y'\"'\"'z'"));
    }

    #[test]
    fn private_avd_configuration_is_fresh_and_resource_bounded() {
        let directory = tempdir().unwrap();
        let source = directory.path().join("source.avd");
        fs::create_dir(&source).unwrap();
        fs::write(
            source.join("config.ini"),
            "target=android-36\nimage.sysdir.1=system-images/android-36/aosp/arm64-v8a/\n\
             hw.ramSize=8192\nhw.cpu.ncore=8\nfastboot.forceFastBoot=yes\n",
        )
        .unwrap();
        let device = directory.path().join("device");
        fs::create_dir(&device).unwrap();
        let avd_home = prepare_private_avd(
            &source,
            &device,
            "asbx_private",
            &create_spec(NetworkMode::All),
            "swiftshader",
        )
        .unwrap();
        let config = fs::read_to_string(avd_home.join("asbx_private.avd/config.ini")).unwrap();
        assert!(config.contains("disk.dataPartition.size=4096M"));
        assert!(config.contains("fastboot.forceColdBoot=yes"));
        assert!(config.contains("fastboot.forceFastBoot=no"));
        assert!(config.contains("hw.cpu.ncore=2"));
        assert!(config.contains("hw.gpu.mode=swiftshader"));
        assert!(config.contains("hw.ramSize=2048"));
    }

    #[test]
    fn port_claim_round_trips_owner() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("5554.claim");
        fs::write(
            &path,
            serde_json::to_vec(&PortClaim {
                sandbox: "sbx_android-emulator_test".into(),
                pid: 1234,
            })
            .unwrap(),
        )
        .unwrap();
        let claim = read_claim(&path).unwrap();
        assert_eq!(claim.sandbox, "sbx_android-emulator_test");
        assert_eq!(claim.pid, 1234);
    }

    #[test]
    fn parses_nul_delimited_directory_records() {
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
}
