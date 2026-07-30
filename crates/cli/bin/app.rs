//! `asbx` command-line interface.

#![forbid(unsafe_code)]

use std::{path::PathBuf, process::ExitCode, time::Duration};

use agent_sandbox_core::RequestedPort;
use agent_sandbox_policy::parse_duration;
use agent_sandbox_runtime::BackendId;
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

mod bootstrap;
mod commands;
mod proxy;
mod request;
mod setup;

use crate::debugger;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

#[derive(Debug, Parser)]
#[command(
    name = "asbx",
    version,
    about = "Run untrusted project commands inside disposable local microVMs"
)]
struct Cli {
    /// Host configuration file. Defaults to ~/.agent-sandbox/config.toml.
    #[arg(long, global = true, env = "ASBX_CONFIG")]
    config: Option<PathBuf>,

    /// Increase wrapper diagnostics. Guest output is unaffected.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Detect, install, and reconfigure local backends and agent integrations.
    Setup(SetupArgs),
    /// Diagnose runtime and host prerequisites.
    Doctor {
        /// Backend to diagnose; defaults to runtime.backend.
        #[arg(long)]
        backend: Option<BackendId>,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Discover registered runtime backends and capabilities.
    Backend {
        #[command(subcommand)]
        command: BackendCommand,
    },
    /// Create a sandbox, execute one command, and always remove it.
    Run(RunArgs),
    /// Create a detached multi-command session.
    Open(OpenArgs),
    /// Execute a command in an open session.
    Exec(SessionExecArgs),
    /// Attach an interactive terminal to an open session.
    Shell(ShellArgs),
    /// Attach LLDB or GDB to a runtime-provided loopback debug stub.
    Debug(debugger::DebugArgs),
    /// Stop and remove an open session.
    Close {
        /// Sandbox session ID.
        id: String,
    },
    /// List wrapper-managed sessions.
    List {
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect a wrapper-managed session.
    Inspect {
        /// Sandbox session ID.
        id: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Extend a session lease.
    Touch {
        /// Sandbox session ID.
        id: String,
        /// New lease duration from now.
        #[arg(long, value_parser = duration_value)]
        ttl: Duration,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Show loopback port publications.
    Ports {
        /// Sandbox session ID.
        id: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// List or download backend-managed guest artifacts.
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommand,
    },
    /// Detect, build, inspect, and remove reusable environments.
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },
    /// Inspect and prune wrapper-managed runtime caches.
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
}

#[derive(Debug, Args)]
struct SetupArgs {
    /// Inspect setup state without changing the host.
    #[arg(long, conflicts_with = "yes")]
    check: bool,
    /// Set the backend used when --backend is omitted.
    #[arg(long, value_enum)]
    default_backend: Option<SetupBackendArg>,
    /// Prepare an additional backend without making it the default.
    #[arg(long = "install-backend", value_enum, value_delimiter = ',')]
    install_backends: Vec<SetupBackendArg>,
    /// Install the Agent Skill for a harness; repeat or comma-separate values.
    #[arg(
        long = "harness",
        value_enum,
        value_delimiter = ',',
        conflicts_with = "no_harness"
    )]
    harnesses: Vec<SetupHarnessArg>,
    /// Do not configure any agent harness.
    #[arg(long)]
    no_harness: bool,
    /// Apply the displayed plan without an interactive confirmation.
    #[arg(short = 'y', long)]
    yes: bool,
    /// Permit updating an existing skill not previously managed by asbx.
    #[arg(long)]
    force: bool,
    /// Emit machine-readable setup state and plan (requires --check).
    #[arg(long, requires = "check")]
    json: bool,
}

#[derive(Debug, Args)]
struct RunArgs {
    #[command(flatten)]
    sandbox: CommonSandboxArgs,
    /// Output format.
    #[arg(long, default_value = "text")]
    output: OutputArg,
    /// Guest executable and arguments. Use `--` before the command.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct OpenArgs {
    #[command(flatten)]
    sandbox: CommonSandboxArgs,
    /// Output format.
    #[arg(long, default_value = "text")]
    output: MetadataOutput,
}

#[derive(Debug, Args)]
struct CommonSandboxArgs {
    /// Runtime backend. Machine boot options imply qemu; Android artifacts imply cuttlefish.
    #[arg(long)]
    backend: Option<BackendId>,
    /// Project directory to copy or mount at the backend workspace path.
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Project exposure mode. Writable mounts require explicit host policy.
    #[arg(long)]
    project_mode: Option<ProjectModeArg>,
    /// Detect the environment, use `LANG@VERSION`, or select a named environment.
    #[arg(long = "env", default_value = "auto")]
    environment: String,
    /// Use an arbitrary OCI image. Takes precedence over --snapshot and --env.
    #[arg(long)]
    image: Option<String>,
    /// Use a Microsandbox snapshot. Takes precedence over --env.
    #[arg(long)]
    snapshot: Option<String>,
    /// Combined Cuttlefish host-tools and Android device-images directory.
    #[arg(long)]
    android_artifacts: Option<PathBuf>,
    /// Bootable raw or qcow2 disk for the QEMU backend.
    #[arg(long)]
    root_disk: Option<PathBuf>,
    /// Root-disk image format. Inferred from `.qcow2` when omitted.
    #[arg(long)]
    disk_format: Option<DiskFormatArg>,
    /// Attach the QEMU root disk read-only instead of using a temporary writable snapshot.
    #[arg(long)]
    root_disk_read_only: bool,
    /// Direct-boot kernel image for the QEMU backend.
    #[arg(long)]
    kernel: Option<PathBuf>,
    /// Direct-boot initramfs.
    #[arg(long, requires = "kernel")]
    initrd: Option<PathBuf>,
    /// Device-tree blob.
    #[arg(long, requires = "kernel")]
    dtb: Option<PathBuf>,
    /// Platform firmware image.
    #[arg(long)]
    firmware: Option<PathBuf>,
    /// Guest architecture (`x86_64`, `aarch64`, or `riscv64`).
    #[arg(long)]
    arch: Option<String>,
    /// QEMU machine type override.
    #[arg(long)]
    machine: Option<String>,
    /// QEMU CPU model override.
    #[arg(long)]
    cpu: Option<String>,
    /// QEMU accelerator (`auto`, `kvm`, `hvf`, `whpx`, or `tcg`).
    #[arg(long)]
    accelerator: Option<String>,
    /// Append one token or fragment to the direct-boot kernel command line.
    #[arg(long = "kernel-append", requires = "kernel")]
    kernel_append: Vec<String>,
    /// Enable a loopback-only QEMU GDB stub; omit PORT to allocate one.
    #[arg(long, num_args = 0..=1, default_missing_value = "0", value_name = "PORT")]
    gdb: Option<u16>,
    /// Start QEMU CPUs paused for debugger attachment.
    #[arg(long, requires = "gdb")]
    pause_at_boot: bool,
    /// Guest virtual CPUs.
    #[arg(long)]
    cpus: Option<u8>,
    /// Guest memory, for example 2G.
    #[arg(long)]
    memory: Option<String>,
    /// Writable root disk, for example 16G.
    #[arg(long)]
    disk: Option<String>,
    /// Guest user name, UID, or UID:GID.
    #[arg(long)]
    user: Option<String>,
    /// In-guest security profile.
    #[arg(long, default_value = "default")]
    security: SecurityArg,
    /// Guest network policy.
    #[arg(long)]
    network: Option<NetworkArg>,
    /// Allow one exact domain in `--network rules` mode.
    #[arg(long = "allow-domain")]
    allow_domains: Vec<String>,
    /// Deny one exact domain in `--network rules` mode.
    #[arg(long = "deny-domain")]
    deny_domains: Vec<String>,
    /// Allow an apex domain and all subdomains.
    #[arg(long = "allow-domain-suffix")]
    allow_domain_suffixes: Vec<String>,
    /// Deny an apex domain and all subdomains.
    #[arg(long = "deny-domain-suffix")]
    deny_domain_suffixes: Vec<String>,
    /// Allow an IP address or CIDR.
    #[arg(long = "allow-cidr")]
    allow_cidrs: Vec<String>,
    /// Deny an IP address or CIDR.
    #[arg(long = "deny-cidr")]
    deny_cidrs: Vec<String>,
    /// Allow a public destination port or inclusive port range.
    #[arg(long = "allow-port", value_parser = port_range_value)]
    allow_ports: Vec<(u16, u16)>,
    /// Deny a public destination port or inclusive port range.
    #[arg(long = "deny-port", value_parser = port_range_value)]
    deny_ports: Vec<(u16, u16)>,
    /// Allow private address ranges. Requires a host-policy override.
    #[arg(long)]
    allow_private: bool,
    /// Allow the host gateway. Requires a host-policy override.
    #[arg(long)]
    allow_host: bool,
    /// Allow cloud metadata endpoints. Requires a host-policy override.
    #[arg(long)]
    allow_metadata: bool,
    /// Per-command timeout.
    #[arg(long, value_parser = duration_value)]
    timeout: Option<Duration>,
    /// Sandbox lease duration.
    #[arg(long, value_parser = duration_value)]
    ttl: Option<Duration>,
    /// Explicit guest environment variable. Host variables are never inherited.
    #[arg(long = "env-var", value_parser = env_value)]
    env_vars: Vec<(String, String)>,
    /// Publish GUEST_PORT or GUEST_PORT:HOST_PORT on host loopback.
    #[arg(long = "publish", value_parser = publish_value)]
    publish: Vec<RequestedPort>,
}

#[derive(Debug, Args)]
struct SessionExecArgs {
    /// Sandbox session ID.
    id: String,
    /// Guest working directory. Defaults to the directory recorded by `open`.
    #[arg(long)]
    cwd: Option<String>,
    /// Guest user override.
    #[arg(long)]
    user: Option<String>,
    /// Per-command timeout.
    #[arg(long, value_parser = duration_value)]
    timeout: Option<Duration>,
    /// Explicit command environment.
    #[arg(long = "env-var", value_parser = env_value)]
    env_vars: Vec<(String, String)>,
    /// Output format.
    #[arg(long, default_value = "text")]
    output: OutputArg,
    /// Guest executable and arguments. Use `--` before the command.
    #[arg(last = true, required = true)]
    command: Vec<String>,
}

#[derive(Debug, Args)]
struct ShellArgs {
    /// Sandbox session ID.
    id: String,
    /// Guest working directory. Defaults to the directory recorded by `open`.
    #[arg(long)]
    cwd: Option<String>,
    /// Guest user override.
    #[arg(long)]
    user: Option<String>,
    /// Shell executable. Defaults to the backend's declared guest shell.
    #[arg(long)]
    shell: Option<String>,
}

#[derive(Debug, Subcommand)]
enum ArtifactCommand {
    /// List regular files below the backend artifact directory.
    List {
        /// Sandbox session ID.
        id: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Download one regular file from the backend artifact directory.
    Get {
        /// Sandbox session ID.
        id: String,
        /// Absolute guest artifact path.
        path: String,
        /// Authorized host destination.
        #[arg(long)]
        to: PathBuf,
    },
}

#[derive(Debug, Subcommand)]
enum EnvCommand {
    /// Detect Go, Rust, and Node.js/TypeScript declarations without executing code.
    Detect {
        /// Project directory.
        #[arg(long, default_value = ".")]
        project: PathBuf,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Build and snapshot a reusable multi-toolchain environment.
    Create(EnvCreateArgs),
    /// List managed environments by least-recent use.
    List {
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Inspect one managed environment and verify its snapshot exists.
    Inspect {
        /// Managed environment name.
        name: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove one managed environment and its snapshot.
    Remove {
        /// Managed environment name.
        name: String,
    },
}

#[derive(Debug, Args)]
struct EnvCreateArgs {
    /// Managed environment name.
    name: String,
    /// Base OCI image.
    #[arg(long, default_value = "ubuntu:24.04")]
    base: String,
    /// Toolchain expression such as go@1.24, rust@1.88, or node@22.
    #[arg(long, required = true)]
    toolchain: Vec<String>,
    /// Builder virtual CPUs.
    #[arg(long)]
    cpus: Option<u8>,
    /// Builder memory, for example 4G.
    #[arg(long)]
    memory: Option<String>,
    /// Builder writable root disk, for example 16G.
    #[arg(long)]
    disk: Option<String>,
    /// Replace an existing name or rebuild an identical snapshot.
    #[arg(long)]
    force: bool,
    /// Builder output format.
    #[arg(long, default_value = "text")]
    output: OutputArg,
}

#[derive(Debug, Subcommand)]
enum CacheCommand {
    /// Show wrapper state plus runtime image and environment usage.
    Status {
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Remove expired and least-recently-used cache objects.
    Prune {
        /// Logical cache target; defaults to host cache.max_size.
        #[arg(long)]
        max_size: Option<String>,
        /// Also remove objects unused for at least this duration.
        #[arg(long, value_parser = duration_value)]
        older_than: Option<Duration>,
        /// Permit pruning named environment snapshots.
        #[arg(long)]
        include_environments: bool,
        /// Print the deterministic plan without deleting anything.
        #[arg(long)]
        dry_run: bool,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProjectModeArg {
    None,
    Copy,
    MountRo,
    MountRw,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DiskFormatArg {
    Raw,
    Qcow2,
}

#[derive(Debug, Subcommand)]
enum BackendCommand {
    /// List backend feature declarations.
    List {
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum SetupBackendArg {
    Microsandbox,
    Qemu,
    Cuttlefish,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, ValueEnum)]
enum SetupHarnessArg {
    All,
    Codex,
    ClaudeCode,
    Cursor,
    Gemini,
    #[value(name = "opencode")]
    OpenCode,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum NetworkArg {
    Off,
    Public,
    Dependencies,
    Rules,
    All,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum SecurityArg {
    Default,
    Restricted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum OutputArg {
    Text,
    Json,
    Jsonl,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum MetadataOutput {
    Text,
    Json,
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

#[tokio::main]
pub(crate) async fn entry() -> ExitCode {
    let cli = Cli::parse();
    match proxy::reexec_if_needed(&cli) {
        Ok(Some(code)) => return exit_code(code),
        Ok(None) => {}
        Err(error) => {
            eprintln!("asbx: {error:#}");
            return ExitCode::FAILURE;
        }
    }
    init_logging(cli.verbose);
    match commands::run(cli).await {
        Ok(code) => exit_code(code),
        Err(error) => {
            eprintln!("asbx: {error:#}");
            ExitCode::FAILURE
        }
    }
}

fn duration_value(value: &str) -> std::result::Result<Duration, String> {
    parse_duration(value).map_err(|error| error.to_string())
}

fn env_value(value: &str) -> std::result::Result<(String, String), String> {
    let (key, value) = value
        .split_once('=')
        .ok_or_else(|| "expected KEY=VALUE".to_owned())?;
    if key.is_empty() {
        return Err("environment key cannot be empty".into());
    }
    Ok((key.into(), value.into()))
}

fn publish_value(value: &str) -> std::result::Result<RequestedPort, String> {
    let (guest, host) = value
        .split_once(':')
        .map(|(guest, host)| (guest, Some(host)))
        .unwrap_or((value, None));
    let guest_port = guest
        .parse::<u16>()
        .map_err(|_| "guest port must be between 1 and 65535".to_owned())?;
    let host_port = host
        .map(|port| {
            port.parse::<u16>()
                .map_err(|_| "host port must be between 1 and 65535".to_owned())
        })
        .transpose()?;
    Ok(RequestedPort {
        guest_port,
        host_port,
    })
}

fn port_range_value(value: &str) -> std::result::Result<(u16, u16), String> {
    let (start, end) = value
        .split_once('-')
        .map(|(start, end)| (start, Some(end)))
        .unwrap_or((value, None));
    let start = start
        .parse::<u16>()
        .map_err(|_| "port must be between 1 and 65535".to_owned())?;
    let end = end
        .map(|end| {
            end.parse::<u16>()
                .map_err(|_| "port must be between 1 and 65535".to_owned())
        })
        .transpose()?
        .unwrap_or(start);
    if start == 0 || start > end {
        return Err("port range must be ascending and between 1 and 65535".into());
    }
    Ok((start, end))
}

fn init_logging(verbose: bool) {
    let default = if verbose { "debug" } else { "warn" };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_env("ASBX_LOG").unwrap_or_else(|_| EnvFilter::new(default)),
        )
        .with_writer(std::io::stderr)
        .without_time()
        .init();
}

fn exit_code(code: i32) -> ExitCode {
    if (0..=255).contains(&code) {
        ExitCode::from(code as u8)
    } else {
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn backend_argument_accepts_registered_names_without_cli_enum_changes() {
        let cli = Cli::try_parse_from(["asbx", "doctor", "--backend", "future-backend", "--json"])
            .unwrap();
        let Command::Doctor {
            backend: Some(backend),
            json,
        } = cli.command
        else {
            panic!("doctor command was not parsed");
        };
        assert_eq!(backend.as_str(), "future-backend");
        assert!(json);
    }

    #[test]
    fn session_commands_leave_cwd_unset_for_session_resolution() {
        let exec = Cli::try_parse_from(["asbx", "exec", "sbx_test", "--", "/bin/true"]).unwrap();
        let Command::Exec(arguments) = exec.command else {
            panic!("exec command was not parsed");
        };
        assert_eq!(arguments.cwd, None);

        let shell = Cli::try_parse_from(["asbx", "shell", "sbx_test"]).unwrap();
        let Command::Shell(arguments) = shell.command else {
            panic!("shell command was not parsed");
        };
        assert_eq!(arguments.cwd, None);
        assert_eq!(arguments.shell, None);
    }

    #[test]
    fn android_artifacts_select_cuttlefish_with_offline_defaults() {
        let directory = tempfile::tempdir().unwrap();
        let cli = Cli::try_parse_from([
            "asbx",
            "run",
            "--android-artifacts",
            directory.path().to_str().unwrap(),
            "--",
            "id",
        ])
        .unwrap();
        let Command::Run(arguments) = cli.command else {
            panic!("run command was not parsed");
        };
        let options = request::sandbox_options(arguments.sandbox).unwrap();
        assert_eq!(options.backend, Some(BackendId::cuttlefish()));
        assert_eq!(
            options.android_artifacts,
            Some(directory.path().canonicalize().unwrap())
        );
        assert_eq!(
            options.network,
            Some(agent_sandbox_runtime::NetworkMode::Off)
        );
        assert_eq!(
            options.project_mode,
            agent_sandbox_runtime::ProjectMode::Copy
        );
    }

    #[test]
    fn setup_accepts_repeatable_backends_and_harnesses() {
        let cli = Cli::try_parse_from([
            "asbx",
            "setup",
            "--default-backend",
            "microsandbox",
            "--install-backend",
            "qemu",
            "--harness",
            "codex,claude-code",
            "--yes",
        ])
        .unwrap();
        let Command::Setup(arguments) = cli.command else {
            panic!("setup command was not parsed");
        };
        assert_eq!(
            arguments.default_backend,
            Some(SetupBackendArg::Microsandbox)
        );
        assert_eq!(arguments.install_backends, [SetupBackendArg::Qemu]);
        assert_eq!(
            arguments.harnesses,
            [SetupHarnessArg::Codex, SetupHarnessArg::ClaudeCode]
        );
        assert!(arguments.yes);
    }
}
