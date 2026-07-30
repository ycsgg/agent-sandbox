//! Host configuration, state, and runtime-backend composition.

use std::{
    path::{Path, PathBuf},
    sync::Arc,
};

use agent_sandbox_core::AgentSandbox;
use agent_sandbox_policy::{HostConfig, parse_duration};
use agent_sandbox_runtime::{BackendId, RuntimeRegistry};
use agent_sandbox_runtime_android_emulator::{
    AndroidEmulatorRuntime, AndroidEmulatorRuntimeConfig,
};
use agent_sandbox_runtime_cuttlefish::{CuttlefishRuntime, CuttlefishRuntimeConfig};
use agent_sandbox_runtime_msb::MicrosandboxRuntime;
use agent_sandbox_runtime_qemu::{QemuRuntime, QemuRuntimeConfig};
use agent_sandbox_state::StateStore;
use anyhow::{Context, Result};

pub(super) struct Application {
    pub service: AgentSandbox,
    pub runtimes: Arc<RuntimeRegistry>,
    pub default_backend: BackendId,
    pub state_path: PathBuf,
}

impl Application {
    pub async fn load(config_path: Option<PathBuf>) -> Result<Self> {
        let config = match config_path {
            Some(path) => HostConfig::load_from(path)?,
            None => HostConfig::load()?,
        };
        let state = StateStore::open_default()?;
        let state_path = state.path().to_path_buf();
        let root = std::env::current_dir().context("cannot read current directory")?;
        let default_backend = BackendId::new(config.runtime.backend.clone())?;
        let mut runtimes = RuntimeRegistry::new(default_backend.clone())
            .with_storage_backend(BackendId::microsandbox());

        // Backend wiring is intentionally centralized here. Command handlers
        // only consume the registry and never construct concrete adapters.
        runtimes.register(Arc::new(MicrosandboxRuntime::default()))?;
        runtimes.register(Arc::new(QemuRuntime::new(QemuRuntimeConfig {
            home: state_path.parent().unwrap_or(Path::new(".")).join("qemu"),
            binary: config.qemu.binary.clone(),
            ssh_binary: config.qemu.ssh_binary.clone(),
            ssh_user: config.qemu.ssh_user.clone(),
            ssh_key: config.qemu.ssh_key.clone(),
            boot_timeout: parse_duration(&config.qemu.boot_timeout)?,
            shutdown_timeout: parse_duration(&config.qemu.shutdown_timeout)?,
        })?))?;
        runtimes.register(Arc::new(CuttlefishRuntime::new(CuttlefishRuntimeConfig {
            home: state_path
                .parent()
                .unwrap_or(Path::new("."))
                .join("cuttlefish"),
            artifacts: config.cuttlefish.artifacts.clone(),
            boot_timeout: parse_duration(&config.cuttlefish.boot_timeout)?,
            shutdown_timeout: parse_duration(&config.cuttlefish.shutdown_timeout)?,
        })?))?;
        runtimes.register(Arc::new(AndroidEmulatorRuntime::new(
            AndroidEmulatorRuntimeConfig {
                home: state_path
                    .parent()
                    .unwrap_or(Path::new("."))
                    .join("android-emulator"),
                sdk_root: config.android_emulator.sdk_root.clone(),
                emulator: config.android_emulator.emulator.clone(),
                adb: config.android_emulator.adb.clone(),
                avd: config.android_emulator.avd.clone(),
                boot_timeout: parse_duration(&config.android_emulator.boot_timeout)?,
                shutdown_timeout: parse_duration(&config.android_emulator.shutdown_timeout)?,
                gpu: config.android_emulator.gpu.clone(),
            },
        )?))?;
        runtimes.validate()?;

        let runtimes = Arc::new(runtimes);
        let service = AgentSandbox::new(runtimes.clone(), state, config, &root)?;
        for id in service.reconcile().await? {
            tracing::info!(sandbox = %id, "reclaimed expired sandbox");
        }
        Ok(Self {
            service,
            runtimes,
            default_backend,
            state_path,
        })
    }
}
