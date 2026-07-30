//! Repeatable host setup for runtime backends and Agent Skill integrations.

use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    io::{self, IsTerminal, Write},
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};

use agent_sandbox_policy::{HostConfig, parse_duration};
use agent_sandbox_runtime::SandboxRuntime;
use agent_sandbox_runtime_android_emulator::{
    AndroidEmulatorRuntime, AndroidEmulatorRuntimeConfig,
};
use agent_sandbox_runtime_cuttlefish::{CuttlefishRuntime, CuttlefishRuntimeConfig};
use agent_sandbox_runtime_msb::MicrosandboxRuntime;
use agent_sandbox_runtime_qemu::{QemuRuntime, QemuRuntimeConfig};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use tokio::process::Command;
use toml_edit::{DocumentMut, Item, Table, value};

use super::{SetupArgs, SetupBackendArg, SetupHarnessArg};

const SKILL_NAME: &str = "agent-sandbox";
const MANAGED_MARKER: &str = ".asbx-managed";
const MICROSANDBOX_LATEST_RELEASE_API: &str =
    "https://api.github.com/repos/superradcompany/microsandbox/releases/latest";
const RELEASE_LOOKUP_TIMEOUT: Duration = Duration::from_secs(20);

struct EmbeddedFile {
    path: &'static str,
    contents: &'static [u8],
    executable: bool,
}

const SKILL_FILES: &[EmbeddedFile] = &[
    EmbeddedFile {
        path: "SKILL.md",
        contents: include_bytes!("../../../../skill/agent-sandbox/SKILL.md"),
        executable: false,
    },
    EmbeddedFile {
        path: "agents/openai.yaml",
        contents: include_bytes!("../../../../skill/agent-sandbox/agents/openai.yaml"),
        executable: false,
    },
    EmbeddedFile {
        path: "references/cli.md",
        contents: include_bytes!("../../../../skill/agent-sandbox/references/cli.md"),
        executable: false,
    },
    EmbeddedFile {
        path: "references/environments.md",
        contents: include_bytes!("../../../../skill/agent-sandbox/references/environments.md"),
        executable: false,
    },
    EmbeddedFile {
        path: "references/troubleshooting.md",
        contents: include_bytes!("../../../../skill/agent-sandbox/references/troubleshooting.md"),
        executable: false,
    },
    EmbeddedFile {
        path: "scripts/check-asbx.sh",
        contents: include_bytes!("../../../../skill/agent-sandbox/scripts/check-asbx.sh"),
        executable: true,
    },
];

#[derive(Debug, Serialize)]
struct SetupSnapshot {
    host: HostView,
    config_path: PathBuf,
    default_backend: String,
    backends: Vec<BackendView>,
    harnesses: Vec<HarnessView>,
    actions: Vec<ActionView>,
    blockers: Vec<String>,
}

#[derive(Debug, Serialize)]
struct HostView {
    os: &'static str,
    architecture: &'static str,
}

#[derive(Debug, Clone, Serialize)]
struct BackendView {
    id: String,
    status: String,
    selected: bool,
    detail: String,
}

#[derive(Debug, Serialize)]
struct HarnessView {
    id: String,
    label: String,
    detected: bool,
    selected: bool,
    status: String,
    skill_path: PathBuf,
}

#[derive(Debug, Serialize)]
struct ActionView {
    kind: String,
    target: String,
    detail: String,
}

#[derive(Debug)]
enum Action {
    InstallMicrosandbox {
        release: MicrosandboxRelease,
    },
    RunInstaller {
        backend: &'static str,
        command: ExternalCommand,
    },
    WriteConfig {
        path: PathBuf,
        backend: String,
    },
    WriteSkill {
        path: PathBuf,
        harnesses: Vec<String>,
    },
}

#[derive(Debug, Clone)]
struct ExternalCommand {
    program: String,
    args: Vec<String>,
}

#[derive(Debug, Clone)]
struct MicrosandboxRelease {
    version: String,
    bundle_digest: String,
}

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    draft: bool,
    prerelease: bool,
    assets: Vec<GithubReleaseAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubReleaseAsset {
    name: String,
    digest: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SkillState {
    Ready,
    Missing,
    ManagedOutdated,
    Conflict,
}

#[derive(Debug, Clone, Copy)]
struct HarnessSpec {
    id: SetupHarnessArg,
    name: &'static str,
    label: &'static str,
    binary: &'static str,
    config_directory: &'static str,
    skill_root: SkillRoot,
}

#[derive(Debug, Clone, Copy)]
enum SkillRoot {
    Universal,
    Claude,
}

struct BackendProbe {
    view: BackendView,
    missing_runtime: bool,
    install_can_fix: bool,
}

/// Run setup without constructing normal runtime state or reconciling sessions.
pub(super) async fn run(config_argument: Option<&Path>, arguments: SetupArgs) -> Result<i32> {
    if arguments.json && !arguments.check {
        bail!("--json is only supported with --check");
    }

    let config_path = resolve_config_path(config_argument)?;
    let config = if config_path.exists() {
        HostConfig::load_from(&config_path)?
    } else {
        HostConfig::default()
    };
    let home = dirs::home_dir().context("cannot determine the user home directory")?;

    let target_default = arguments
        .default_backend
        .map(SetupBackendArg::as_str)
        .unwrap_or(config.runtime.backend.as_str())
        .to_owned();
    let mut desired_backends = arguments
        .install_backends
        .iter()
        .map(|backend| backend.as_str().to_owned())
        .collect::<BTreeSet<_>>();
    desired_backends.insert(target_default.clone());

    let mut backend_probes = probe_backends(&config).await?;
    for probe in &mut backend_probes {
        probe.view.selected = desired_backends.contains(&probe.view.id);
    }

    let harness_specs = harness_specs();
    let selected_harnesses = select_harnesses(&arguments, &harness_specs, &home);
    let mut target_harnesses = BTreeMap::<PathBuf, Vec<String>>::new();
    for specification in &harness_specs {
        if selected_harnesses.contains(&specification.id) {
            target_harnesses
                .entry(specification.skill_path(&home))
                .or_default()
                .push(specification.label.to_owned());
        }
    }

    let mut actions = Vec::new();
    let mut blockers = Vec::new();
    plan_backends(
        &config,
        &desired_backends,
        &backend_probes,
        &mut actions,
        &mut blockers,
    )
    .await;

    if !is_known_backend(&target_default) {
        blockers.push(format!(
            "configured default backend {target_default:?} is unknown; rerun with --default-backend microsandbox, qemu, cuttlefish, or android-emulator"
        ));
    } else if !config_path.exists() || config.runtime.backend != target_default {
        actions.push(Action::WriteConfig {
            path: config_path.clone(),
            backend: target_default.clone(),
        });
    }

    for (path, harnesses) in &target_harnesses {
        match inspect_skill(path)? {
            SkillState::Ready => {}
            SkillState::Missing | SkillState::ManagedOutdated => {
                actions.push(Action::WriteSkill {
                    path: path.clone(),
                    harnesses: harnesses.clone(),
                });
            }
            SkillState::Conflict if arguments.force => {
                actions.push(Action::WriteSkill {
                    path: path.clone(),
                    harnesses: harnesses.clone(),
                });
            }
            SkillState::Conflict => blockers.push(format!(
                "{} already contains a skill not managed by asbx; inspect it and rerun with --force to update the managed files",
                path.display()
            )),
        }
    }

    let harness_views = harness_specs
        .iter()
        .map(|specification| {
            let detected = specification.detected(&home);
            let selected = selected_harnesses.contains(&specification.id);
            let skill_path = specification.skill_path(&home);
            let state = inspect_skill(&skill_path).unwrap_or(SkillState::Conflict);
            let status = if selected {
                match state {
                    SkillState::Ready => "configured",
                    SkillState::Missing => "not-configured",
                    SkillState::ManagedOutdated => "update-available",
                    SkillState::Conflict => "conflict",
                }
            } else if detected {
                "detected"
            } else {
                "not-detected"
            };
            HarnessView {
                id: specification.name.into(),
                label: specification.label.into(),
                detected,
                selected,
                status: status.into(),
                skill_path,
            }
        })
        .collect();

    let action_views = actions.iter().map(Action::view).collect();
    let snapshot = SetupSnapshot {
        host: HostView {
            os: env::consts::OS,
            architecture: env::consts::ARCH,
        },
        config_path,
        default_backend: target_default,
        backends: backend_probes
            .iter()
            .map(|probe| probe.view.clone())
            .collect(),
        harnesses: harness_views,
        actions: action_views,
        blockers,
    };

    if arguments.json {
        println!("{}", serde_json::to_string_pretty(&snapshot)?);
    } else {
        print_snapshot(&snapshot);
    }

    if arguments.check {
        return Ok(
            if snapshot.actions.is_empty() && snapshot.blockers.is_empty() {
                0
            } else {
                1
            },
        );
    }
    if !snapshot.blockers.is_empty() {
        bail!("setup has unresolved blockers; no changes were applied");
    }
    if actions.is_empty() {
        if !arguments.json {
            println!("\nNo changes required.");
        }
        return Ok(0);
    }
    if !arguments.yes && !confirm(actions.len())? {
        println!("No changes applied.");
        return Ok(0);
    }

    apply_backend_actions(&actions).await?;
    verify_requested_backends(&config, &desired_backends).await?;
    apply_configuration_actions(&actions)?;
    println!("Setup complete. Run `asbx setup --check` to verify it again.");
    Ok(0)
}

async fn probe_backends(config: &HostConfig) -> Result<Vec<BackendProbe>> {
    let microsandbox_checks = MicrosandboxRuntime::default()
        .doctor()
        .await
        .context("diagnose Microsandbox")?;
    let microsandbox_ready = checks_pass(&microsandbox_checks);
    let microsandbox_missing = !microsandbox::setup::is_installed();

    let qemu_runtime = qemu_runtime(config)?;
    let qemu_checks = qemu_runtime.doctor().await.context("diagnose QEMU")?;
    let qemu_ready = checks_pass(&qemu_checks);
    let qemu_missing = qemu_binary(config).is_none();

    let cuttlefish_runtime = cuttlefish_runtime(config)?;
    let cuttlefish_checks = cuttlefish_runtime
        .doctor()
        .await
        .context("diagnose Cuttlefish")?;
    let cuttlefish_ready = checks_pass(&cuttlefish_checks);
    let cuttlefish_missing = config.cuttlefish.artifacts.is_none();

    let android_emulator_runtime = android_emulator_runtime(config)?;
    let android_emulator_checks = android_emulator_runtime
        .doctor()
        .await
        .context("diagnose Android Emulator")?;
    let android_emulator_ready =
        checks_pass(&android_emulator_checks) && config.android_emulator.avd.is_some();
    let android_emulator_missing = config.android_emulator.avd.is_none();

    Ok(vec![
        BackendProbe {
            view: BackendView {
                id: SetupBackendArg::Microsandbox.as_str().into(),
                status: backend_status(microsandbox_ready, microsandbox_missing),
                selected: false,
                detail: checks_detail(&microsandbox_checks),
            },
            missing_runtime: microsandbox_missing,
            install_can_fix: microsandbox_install_can_fix(&microsandbox_checks),
        },
        BackendProbe {
            view: BackendView {
                id: SetupBackendArg::Qemu.as_str().into(),
                status: backend_status(qemu_ready, qemu_missing),
                selected: false,
                detail: checks_detail(&qemu_checks),
            },
            missing_runtime: qemu_missing,
            install_can_fix: qemu_missing,
        },
        BackendProbe {
            view: BackendView {
                id: SetupBackendArg::Cuttlefish.as_str().into(),
                status: backend_status(cuttlefish_ready, cuttlefish_missing),
                selected: false,
                detail: checks_detail(&cuttlefish_checks),
            },
            missing_runtime: cuttlefish_missing,
            install_can_fix: false,
        },
        BackendProbe {
            view: BackendView {
                id: SetupBackendArg::AndroidEmulator.as_str().into(),
                status: backend_status(android_emulator_ready, android_emulator_missing),
                selected: false,
                detail: checks_detail(&android_emulator_checks),
            },
            missing_runtime: android_emulator_missing,
            install_can_fix: false,
        },
    ])
}

async fn plan_backends(
    config: &HostConfig,
    desired: &BTreeSet<String>,
    probes: &[BackendProbe],
    actions: &mut Vec<Action>,
    blockers: &mut Vec<String>,
) {
    for backend in desired {
        let Some(probe) = probes.iter().find(|probe| probe.view.id == *backend) else {
            blockers.push(format!(
                "backend {backend:?} is not known to this setup build"
            ));
            continue;
        };
        if probe.view.status == "ready" {
            continue;
        }
        match backend.as_str() {
            "microsandbox" if probe.missing_runtime && !probe.install_can_fix => {
                blockers.push(format!(
                    "installing Microsandbox runtime files cannot fix the host checks: {}",
                    probe.view.detail
                ));
            }
            "microsandbox" if probe.missing_runtime && microsandbox_host_supported() => {
                match fetch_latest_microsandbox_release().await {
                    Ok(release) => actions.push(Action::InstallMicrosandbox { release }),
                    Err(error) => blockers.push(format!(
                        "could not resolve the latest Microsandbox release: {error:#}"
                    )),
                }
            }
            "microsandbox" if probe.missing_runtime => blockers.push(format!(
                "Microsandbox runtime bundles are not supported on {} {}",
                env::consts::OS,
                env::consts::ARCH
            )),
            "microsandbox" => blockers.push(format!(
                "Microsandbox is installed but not ready: {}",
                probe.view.detail
            )),
            "qemu" if probe.missing_runtime && config.qemu.binary.is_some() => {
                blockers.push(format!(
                    "configured qemu.binary is unavailable: {}; update or remove it before setup",
                    config
                        .qemu
                        .binary
                        .as_deref()
                        .unwrap_or_else(|| Path::new(""))
                        .display()
                ));
            }
            "qemu" if probe.missing_runtime => match qemu_install_command() {
                Some(command) => actions.push(Action::RunInstaller {
                    backend: "qemu",
                    command,
                }),
                None => blockers.push(format!(
                    "QEMU is missing and no supported package manager was detected on {}",
                    env::consts::OS
                )),
            },
            "qemu" => blockers.push(format!(
                "QEMU is installed but not ready: {}",
                probe.view.detail
            )),
            "cuttlefish" if probe.missing_runtime => blockers.push(format!(
                "Cuttlefish Android artifacts are not configured: {}. Extract a matching \
                 cvd-host_package and device-image archive into one directory, then set \
                 cuttlefish.artifacts in the host config",
                probe.view.detail
            )),
            "cuttlefish" => blockers.push(format!(
                "Cuttlefish is configured but not ready: {}",
                probe.view.detail
            )),
            "android-emulator" if probe.missing_runtime => blockers.push(format!(
                "Android Emulator has no default AVD configured: {}. Install the Android SDK \
                 Emulator and a system image, create an AVD, then set android_emulator.avd in \
                 the host config",
                probe.view.detail
            )),
            "android-emulator" => blockers.push(format!(
                "Android Emulator is configured but not ready: {}",
                probe.view.detail
            )),
            _ => blockers.push(format!("backend {backend:?} cannot be prepared")),
        }
    }
}

async fn apply_backend_actions(actions: &[Action]) -> Result<()> {
    for action in actions {
        match action {
            Action::InstallMicrosandbox { release } => {
                microsandbox::setup::Setup::builder()
                    .version(release.version.clone())
                    .allow_ci_local_bundle(false)
                    .expected_bundle_sha256(release.bundle_digest.clone())
                    .build()
                    .install()
                    .await
                    .with_context(|| {
                        format!(
                            "install Microsandbox runtime dependencies from latest release v{}",
                            release.version
                        )
                    })?;
            }
            Action::RunInstaller { backend, command } => {
                eprintln!("Installing {backend}: {}", command.display());
                let status = Command::new(&command.program)
                    .args(&command.args)
                    .stdin(Stdio::inherit())
                    .stdout(Stdio::inherit())
                    .stderr(Stdio::inherit())
                    .status()
                    .await
                    .with_context(|| format!("start {}", command.display()))?;
                if !status.success() {
                    bail!(
                        "{} installer exited with {}",
                        backend,
                        status.code().unwrap_or(1)
                    );
                }
            }
            Action::WriteConfig { .. } | Action::WriteSkill { .. } => {}
        }
    }
    Ok(())
}

async fn fetch_latest_microsandbox_release() -> Result<MicrosandboxRelease> {
    let client = reqwest::Client::builder()
        .user_agent(format!("asbx/{}", env!("CARGO_PKG_VERSION")))
        .timeout(RELEASE_LOOKUP_TIMEOUT)
        .build()
        .context("build GitHub release client")?;
    let release = client
        .get(MICROSANDBOX_LATEST_RELEASE_API)
        .header(reqwest::header::ACCEPT, "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await
        .context("request GitHub latest-release metadata")?
        .error_for_status()
        .context("GitHub latest-release request failed")?
        .json::<GithubRelease>()
        .await
        .context("decode GitHub latest-release metadata")?;

    parse_latest_microsandbox_release(release)
}

fn parse_latest_microsandbox_release(release: GithubRelease) -> Result<MicrosandboxRelease> {
    if release.draft || release.prerelease {
        bail!("GitHub returned a draft or prerelease from the latest-release endpoint");
    }
    let raw_version = release
        .tag_name
        .strip_prefix('v')
        .context("latest Microsandbox release tag does not start with 'v'")?;
    let version = semver::Version::parse(raw_version)
        .context("latest Microsandbox release tag is not a semantic version")?
        .to_string();
    let bundle_name = microsandbox_bundle_name()?;
    let asset = release
        .assets
        .iter()
        .find(|asset| asset.name == bundle_name)
        .with_context(|| {
            format!("latest Microsandbox release v{version} has no {bundle_name} asset")
        })?;
    let digest = asset.digest.as_deref().with_context(|| {
        format!(
            "latest Microsandbox release v{version} does not publish a digest for {bundle_name}"
        )
    })?;
    let sha256 = digest.strip_prefix("sha256:").with_context(|| {
        format!(
            "latest Microsandbox release v{version} publishes an unsupported digest for {bundle_name}"
        )
    })?;
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!(
            "latest Microsandbox release v{version} publishes an invalid SHA-256 for {bundle_name}"
        );
    }

    Ok(MicrosandboxRelease {
        version,
        bundle_digest: digest.to_owned(),
    })
}

fn microsandbox_bundle_name() -> Result<String> {
    let target_os = match env::consts::OS {
        "macos" => "darwin",
        "linux" => "linux",
        "windows" => "windows",
        os => bail!("Microsandbox has no release-bundle naming rule for {os}"),
    };
    match env::consts::ARCH {
        "aarch64" | "x86_64" => {}
        architecture => {
            bail!("Microsandbox has no release bundle for architecture {architecture}")
        }
    }
    Ok(format!(
        "microsandbox-{target_os}-{}.tar.gz",
        env::consts::ARCH
    ))
}

fn apply_configuration_actions(actions: &[Action]) -> Result<()> {
    for action in actions {
        match action {
            Action::WriteConfig { path, backend } => write_default_backend(path, backend)?,
            Action::WriteSkill { path, .. } => write_skill(path)?,
            Action::InstallMicrosandbox { .. } | Action::RunInstaller { .. } => {}
        }
    }
    Ok(())
}

async fn verify_requested_backends(config: &HostConfig, desired: &BTreeSet<String>) -> Result<()> {
    let probes = probe_backends(config).await?;
    for backend in desired {
        let probe = probes
            .iter()
            .find(|probe| probe.view.id == *backend)
            .with_context(|| format!("backend {backend} disappeared after setup"))?;
        if probe.view.status != "ready" {
            bail!(
                "backend {backend} is still not ready after setup: {}",
                probe.view.detail
            );
        }
    }
    Ok(())
}

fn qemu_runtime(config: &HostConfig) -> Result<QemuRuntime> {
    let home = env::var_os("ASBX_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".agent-sandbox")))
        .context("cannot determine ASBX_HOME")?;
    Ok(QemuRuntime::new(QemuRuntimeConfig {
        home: home.join("qemu"),
        binary: config.qemu.binary.clone(),
        ssh_binary: config.qemu.ssh_binary.clone(),
        ssh_user: config.qemu.ssh_user.clone(),
        ssh_key: config.qemu.ssh_key.clone(),
        boot_timeout: parse_duration(&config.qemu.boot_timeout)?,
        shutdown_timeout: parse_duration(&config.qemu.shutdown_timeout)?,
    })?)
}

fn cuttlefish_runtime(config: &HostConfig) -> Result<CuttlefishRuntime> {
    let home = env::var_os("ASBX_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".agent-sandbox")))
        .context("cannot determine ASBX_HOME")?;
    Ok(CuttlefishRuntime::new(CuttlefishRuntimeConfig {
        home: home.join("cuttlefish"),
        artifacts: config.cuttlefish.artifacts.clone(),
        boot_timeout: parse_duration(&config.cuttlefish.boot_timeout)?,
        shutdown_timeout: parse_duration(&config.cuttlefish.shutdown_timeout)?,
    })?)
}

fn android_emulator_runtime(config: &HostConfig) -> Result<AndroidEmulatorRuntime> {
    let home = env::var_os("ASBX_HOME")
        .map(PathBuf::from)
        .or_else(|| dirs::home_dir().map(|home| home.join(".agent-sandbox")))
        .context("cannot determine ASBX_HOME")?;
    Ok(AndroidEmulatorRuntime::new(AndroidEmulatorRuntimeConfig {
        home: home.join("android-emulator"),
        sdk_root: config.android_emulator.sdk_root.clone(),
        emulator: config.android_emulator.emulator.clone(),
        adb: config.android_emulator.adb.clone(),
        avd: config.android_emulator.avd.clone(),
        boot_timeout: parse_duration(&config.android_emulator.boot_timeout)?,
        shutdown_timeout: parse_duration(&config.android_emulator.shutdown_timeout)?,
        gpu: config.android_emulator.gpu.clone(),
    })?)
}

fn qemu_binary(config: &HostConfig) -> Option<PathBuf> {
    let architecture = match env::consts::ARCH {
        "x86" | "x86_64" => "x86_64",
        "arm" | "aarch64" => "aarch64",
        "riscv64" => "riscv64",
        architecture => architecture,
    };
    let candidate = config
        .qemu
        .binary
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("qemu-system-{architecture}")));
    which::which(candidate).ok()
}

fn resolve_config_path(argument: Option<&Path>) -> Result<PathBuf> {
    if let Some(path) = argument {
        return Ok(path.to_path_buf());
    }
    if let Some(path) = env::var_os("ASBX_CONFIG") {
        return Ok(PathBuf::from(path));
    }
    Ok(dirs::home_dir()
        .context("cannot determine the user home directory")?
        .join(".agent-sandbox")
        .join("config.toml"))
}

fn select_harnesses(
    arguments: &SetupArgs,
    specifications: &[HarnessSpec],
    home: &Path,
) -> BTreeSet<SetupHarnessArg> {
    if arguments.no_harness {
        return BTreeSet::new();
    }
    if arguments.harnesses.is_empty() {
        return specifications
            .iter()
            .filter(|specification| specification.detected(home))
            .map(|specification| specification.id)
            .collect();
    }
    if arguments.harnesses.contains(&SetupHarnessArg::All) {
        return specifications
            .iter()
            .map(|specification| specification.id)
            .collect();
    }
    arguments
        .harnesses
        .iter()
        .copied()
        .filter(|harness| *harness != SetupHarnessArg::All)
        .collect()
}

fn harness_specs() -> [HarnessSpec; 5] {
    [
        HarnessSpec {
            id: SetupHarnessArg::Codex,
            name: "codex",
            label: "Codex",
            binary: "codex",
            config_directory: ".codex",
            skill_root: SkillRoot::Universal,
        },
        HarnessSpec {
            id: SetupHarnessArg::ClaudeCode,
            name: "claude-code",
            label: "Claude Code",
            binary: "claude",
            config_directory: ".claude",
            skill_root: SkillRoot::Claude,
        },
        HarnessSpec {
            id: SetupHarnessArg::Cursor,
            name: "cursor",
            label: "Cursor",
            binary: "cursor",
            config_directory: ".cursor",
            skill_root: SkillRoot::Universal,
        },
        HarnessSpec {
            id: SetupHarnessArg::Gemini,
            name: "gemini",
            label: "Gemini CLI",
            binary: "gemini",
            config_directory: ".gemini",
            skill_root: SkillRoot::Universal,
        },
        HarnessSpec {
            id: SetupHarnessArg::OpenCode,
            name: "opencode",
            label: "OpenCode",
            binary: "opencode",
            config_directory: ".config/opencode",
            skill_root: SkillRoot::Universal,
        },
    ]
}

impl HarnessSpec {
    fn detected(&self, home: &Path) -> bool {
        which::which(self.binary).is_ok() || home.join(self.config_directory).is_dir()
    }

    fn skill_path(&self, home: &Path) -> PathBuf {
        match self.skill_root {
            SkillRoot::Universal => home.join(".agents").join("skills").join(SKILL_NAME),
            SkillRoot::Claude => home.join(".claude").join("skills").join(SKILL_NAME),
        }
    }
}

impl SetupBackendArg {
    fn as_str(self) -> &'static str {
        match self {
            Self::Microsandbox => "microsandbox",
            Self::Qemu => "qemu",
            Self::Cuttlefish => "cuttlefish",
            Self::AndroidEmulator => "android-emulator",
        }
    }
}

impl Action {
    fn view(&self) -> ActionView {
        match self {
            Self::InstallMicrosandbox { release } => ActionView {
                kind: "install-backend".into(),
                target: "microsandbox".into(),
                detail: format!(
                    "download latest release v{} of the msb and libkrunfw runtime bundle",
                    release.version
                ),
            },
            Self::RunInstaller { backend, command } => ActionView {
                kind: "install-backend".into(),
                target: (*backend).into(),
                detail: command.display(),
            },
            Self::WriteConfig { path, backend } => ActionView {
                kind: "write-config".into(),
                target: path.display().to_string(),
                detail: format!("set runtime.backend = {backend:?}"),
            },
            Self::WriteSkill { path, harnesses } => ActionView {
                kind: "install-skill".into(),
                target: path.display().to_string(),
                detail: format!("configure {}", harnesses.join(", ")),
            },
        }
    }
}

impl ExternalCommand {
    fn display(&self) -> String {
        std::iter::once(self.program.as_str())
            .chain(self.args.iter().map(String::as_str))
            .map(display_argument)
            .collect::<Vec<_>>()
            .join(" ")
    }
}

fn display_argument(argument: &str) -> String {
    if argument
        .bytes()
        .all(|byte| byte.is_ascii_alphanumeric() || b"-_./:@".contains(&byte))
    {
        argument.into()
    } else {
        format!("{argument:?}")
    }
}

fn qemu_install_command() -> Option<ExternalCommand> {
    match env::consts::OS {
        "macos" if which::which("brew").is_ok() => Some(ExternalCommand {
            program: "brew".into(),
            args: vec!["install".into(), "qemu".into()],
        }),
        "macos" if which::which("port").is_ok() => {
            Some(privileged_command("port", &["install", "qemu"]))
        }
        "linux" if which::which("apt-get").is_ok() => Some(privileged_command(
            "apt-get",
            &["install", "-y", "qemu-system"],
        )),
        "linux" if which::which("dnf").is_ok() => Some(privileged_command(
            "dnf",
            &["install", "-y", "@virtualization"],
        )),
        "linux" if which::which("pacman").is_ok() => {
            Some(privileged_command("pacman", &["-S", "--needed", "qemu"]))
        }
        "linux" if which::which("zypper").is_ok() => Some(privileged_command(
            "zypper",
            &["--non-interactive", "install", "qemu"],
        )),
        "linux" if which::which("yum").is_ok() => {
            Some(privileged_command("yum", &["install", "-y", "qemu-kvm"]))
        }
        _ => None,
    }
}

fn privileged_command(program: &str, arguments: &[&str]) -> ExternalCommand {
    if which::which("sudo").is_ok() {
        ExternalCommand {
            program: "sudo".into(),
            args: std::iter::once(program.to_owned())
                .chain(arguments.iter().map(|argument| (*argument).to_owned()))
                .collect(),
        }
    } else {
        ExternalCommand {
            program: program.into(),
            args: arguments
                .iter()
                .map(|argument| (*argument).to_owned())
                .collect(),
        }
    }
}

fn microsandbox_host_supported() -> bool {
    matches!(
        (env::consts::OS, env::consts::ARCH),
        ("macos", "aarch64") | ("linux", "x86_64") | ("linux", "aarch64")
    )
}

fn microsandbox_install_can_fix(checks: &[(String, bool, String)]) -> bool {
    checks
        .iter()
        .filter(|(_, passed, _)| !passed)
        .all(|(name, _, detail)| {
            matches!(name.as_str(), "Runtime / msb" | "Runtime / libkrunfw")
                || (name == "Problem" && detail.contains("runtime could not be resolved"))
        })
}

fn is_known_backend(backend: &str) -> bool {
    matches!(
        backend,
        "microsandbox" | "qemu" | "cuttlefish" | "android-emulator"
    )
}

fn checks_pass(checks: &[(String, bool, String)]) -> bool {
    checks.iter().all(|(_, passed, _)| *passed)
}

fn backend_status(ready: bool, missing: bool) -> String {
    if ready {
        "ready"
    } else if missing {
        "missing"
    } else {
        "needs-attention"
    }
    .into()
}

fn checks_detail(checks: &[(String, bool, String)]) -> String {
    let failed = checks
        .iter()
        .filter(|(_, passed, _)| !passed)
        .map(|(name, _, detail)| format!("{name}: {detail}"))
        .collect::<Vec<_>>();
    if !failed.is_empty() {
        return failed.join("; ");
    }
    checks
        .iter()
        .take(4)
        .map(|(name, _, detail)| format!("{name}: {detail}"))
        .collect::<Vec<_>>()
        .join("; ")
}

fn inspect_skill(path: &Path) -> Result<SkillState> {
    if !path.exists() {
        return Ok(SkillState::Missing);
    }
    if !path.is_dir() {
        return Ok(SkillState::Conflict);
    }
    let exact = SKILL_FILES.iter().all(|file| {
        fs::read(path.join(file.path))
            .map(|contents| contents == file.contents)
            .unwrap_or(false)
    });
    if exact {
        return Ok(SkillState::Ready);
    }
    if path.join(MANAGED_MARKER).is_file() {
        Ok(SkillState::ManagedOutdated)
    } else {
        Ok(SkillState::Conflict)
    }
}

fn write_skill(path: &Path) -> Result<()> {
    if path
        .symlink_metadata()
        .map(|metadata| metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        bail!(
            "refusing to update non-matching symlinked skill {}",
            path.display()
        );
    }
    fs::create_dir_all(path)
        .with_context(|| format!("create skill directory {}", path.display()))?;
    for file in SKILL_FILES {
        write_atomic(
            &path.join(file.path),
            file.contents,
            if file.executable {
                Some(0o755)
            } else {
                Some(0o644)
            },
        )?;
    }
    let marker = format!("managed-by=asbx\nversion={}\n", env!("CARGO_PKG_VERSION"));
    write_atomic(&path.join(MANAGED_MARKER), marker.as_bytes(), Some(0o644))
}

fn write_default_backend(path: &Path, backend: &str) -> Result<()> {
    let mut document = if path.exists() {
        fs::read_to_string(path)
            .with_context(|| format!("read config {}", path.display()))?
            .parse::<DocumentMut>()
            .with_context(|| format!("parse config {}", path.display()))?
    } else {
        DocumentMut::new()
    };
    if !document.contains_key("runtime") {
        document["runtime"] = Item::Table(Table::new());
    }
    document["runtime"]["backend"] = value(backend);
    write_atomic(path, document.to_string().as_bytes(), Some(0o600))
}

fn write_atomic(path: &Path, contents: &[u8], unix_mode: Option<u32>) -> Result<()> {
    let parent = path
        .parent()
        .with_context(|| format!("{} has no parent directory", path.display()))?;
    fs::create_dir_all(parent).with_context(|| format!("create directory {}", parent.display()))?;
    let mut temporary =
        NamedTempFile::new_in(parent).with_context(|| format!("stage {}", path.display()))?;
    temporary
        .write_all(contents)
        .with_context(|| format!("write staged {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("sync staged {}", path.display()))?;
    #[cfg(unix)]
    if let Some(mode) = unix_mode {
        use std::os::unix::fs::PermissionsExt;
        temporary
            .as_file()
            .set_permissions(fs::Permissions::from_mode(mode))
            .with_context(|| format!("set permissions on staged {}", path.display()))?;
    }
    #[cfg(not(unix))]
    let _ = unix_mode;
    temporary
        .persist(path)
        .map_err(|error| error.error)
        .with_context(|| format!("commit {}", path.display()))?;
    Ok(())
}

fn print_snapshot(snapshot: &SetupSnapshot) {
    println!("Agent Sandbox setup");
    println!("Host: {} {}", snapshot.host.os, snapshot.host.architecture);
    println!("Config: {}", snapshot.config_path.display());
    println!("Default backend: {}", snapshot.default_backend);

    println!("\nBackends");
    for backend in &snapshot.backends {
        println!(
            "  [{:<15}] {:<12}{} {}",
            backend.status,
            backend.id,
            if backend.selected { " selected;" } else { "" },
            backend.detail
        );
    }

    println!("\nAgent harnesses");
    for harness in &snapshot.harnesses {
        println!(
            "  [{:<15}] {:<12}{} {}",
            harness.status,
            harness.label,
            if harness.selected { " selected;" } else { "" },
            harness.skill_path.display()
        );
    }

    println!("\nPlan");
    if snapshot.actions.is_empty() {
        println!("  no changes");
    } else {
        for (index, action) in snapshot.actions.iter().enumerate() {
            println!(
                "  {}. {} {} — {}",
                index + 1,
                action.kind,
                action.target,
                action.detail
            );
        }
    }
    for blocker in &snapshot.blockers {
        println!("  BLOCKED: {blocker}");
    }
}

fn confirm(action_count: usize) -> Result<bool> {
    if !io::stdin().is_terminal() {
        bail!(
            "setup needs confirmation but stdin is not interactive; review `asbx setup --check` and rerun with --yes"
        );
    }
    print!("\nApply {action_count} change(s)? [y/N] ");
    io::stdout().flush().context("flush setup prompt")?;
    let mut answer = String::new();
    io::stdin()
        .read_line(&mut answer)
        .context("read setup confirmation")?;
    Ok(matches!(
        answer.trim().to_ascii_lowercase().as_str(),
        "y" | "yes"
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn latest_microsandbox_release_uses_platform_bundle_and_digest() {
        let bundle_name = microsandbox_bundle_name().unwrap();
        let digest = format!("sha256:{}", "a".repeat(64));
        let release = GithubRelease {
            tag_name: "v1.2.3".into(),
            draft: false,
            prerelease: false,
            assets: vec![GithubReleaseAsset {
                name: bundle_name,
                digest: Some(digest.clone()),
            }],
        };

        let parsed = parse_latest_microsandbox_release(release).unwrap();
        assert_eq!(parsed.version, "1.2.3");
        assert_eq!(parsed.bundle_digest, digest);
    }

    #[test]
    fn latest_microsandbox_release_rejects_unverified_bundle() {
        let release = GithubRelease {
            tag_name: "v1.2.3".into(),
            draft: false,
            prerelease: false,
            assets: vec![GithubReleaseAsset {
                name: microsandbox_bundle_name().unwrap(),
                digest: None,
            }],
        };

        let error = parse_latest_microsandbox_release(release).unwrap_err();
        assert!(error.to_string().contains("does not publish a digest"));
    }

    #[test]
    fn skill_install_is_idempotent_and_detects_unmanaged_changes() {
        let directory = tempdir().unwrap();
        let skill = directory.path().join("agent-sandbox");

        assert_eq!(inspect_skill(&skill).unwrap(), SkillState::Missing);
        write_skill(&skill).unwrap();
        assert_eq!(inspect_skill(&skill).unwrap(), SkillState::Ready);

        fs::write(skill.join("SKILL.md"), "custom instructions").unwrap();
        assert_eq!(inspect_skill(&skill).unwrap(), SkillState::ManagedOutdated);

        fs::remove_file(skill.join(MANAGED_MARKER)).unwrap();
        assert_eq!(inspect_skill(&skill).unwrap(), SkillState::Conflict);
    }

    #[test]
    fn config_update_preserves_unrelated_content_and_comments() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("config.toml");
        fs::write(
            &path,
            "# keep this comment\n[runtime]\nbackend = \"microsandbox\"\n\n[proxy]\ninherit_env = false\n",
        )
        .unwrap();

        write_default_backend(&path, "qemu").unwrap();
        let text = fs::read_to_string(path).unwrap();
        assert!(text.contains("# keep this comment"));
        assert!(text.contains("backend = \"qemu\""));
        assert!(text.contains("[proxy]"));
        assert!(text.contains("inherit_env = false"));
    }

    #[test]
    fn shared_harnesses_resolve_to_one_universal_skill() {
        let directory = tempdir().unwrap();
        let home = directory.path();
        let specifications = harness_specs();
        let codex = specifications
            .iter()
            .find(|specification| specification.id == SetupHarnessArg::Codex)
            .unwrap();
        let gemini = specifications
            .iter()
            .find(|specification| specification.id == SetupHarnessArg::Gemini)
            .unwrap();
        let claude = specifications
            .iter()
            .find(|specification| specification.id == SetupHarnessArg::ClaudeCode)
            .unwrap();

        assert_eq!(codex.skill_path(home), gemini.skill_path(home));
        assert_ne!(codex.skill_path(home), claude.skill_path(home));
    }
}
