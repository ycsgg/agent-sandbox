//! `asbx` command-line interface.

#![forbid(unsafe_code)]

use std::{
    io::IsTerminal,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use agent_sandbox_core::{AgentSandbox, RequestedPort, SandboxOptions};
use agent_sandbox_exec::{ExecSummary, OutputFormat, forward};
use agent_sandbox_policy::{HostConfig, parse_duration};
use agent_sandbox_runtime::{ExecRequest, NetworkMode, SecurityMode};
use agent_sandbox_runtime_msb::MicrosandboxRuntime;
use agent_sandbox_state::StateStore;
use anyhow::{Context, Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};
use clap::{Args, Parser, Subcommand, ValueEnum};
use tracing_subscriber::EnvFilter;

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
    /// Diagnose Microsandbox runtime and host prerequisites.
    Doctor {
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Create a sandbox, execute one command, and always remove it.
    Run(RunArgs),
    /// Create a detached multi-command session.
    Open(OpenArgs),
    /// Execute a command in an open session.
    Exec(SessionExecArgs),
    /// Attach an interactive terminal to an open session.
    Shell(ShellArgs),
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
    /// List or download `/out` artifacts.
    Artifact {
        #[command(subcommand)]
        command: ArtifactCommand,
    },
    /// Detect project runtime declarations.
    Env {
        #[command(subcommand)]
        command: EnvCommand,
    },
    /// Inspect wrapper state/cache disk usage.
    Cache {
        #[command(subcommand)]
        command: CacheCommand,
    },
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
    /// Project directory to copy into `/workspace`.
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Project transfer mode. Phase 1 safely supports copy mode.
    #[arg(long, default_value = "copy")]
    project_mode: ProjectModeArg,
    /// Detect the environment, use `LANG@VERSION`, or select a named environment.
    #[arg(long = "env", default_value = "auto")]
    environment: String,
    /// Use an arbitrary OCI image. Takes precedence over --snapshot and --env.
    #[arg(long)]
    image: Option<String>,
    /// Use a Microsandbox snapshot. Takes precedence over --env.
    #[arg(long)]
    snapshot: Option<String>,
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
    /// Guest working directory.
    #[arg(long, default_value = "/workspace")]
    cwd: String,
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
    /// Guest working directory.
    #[arg(long, default_value = "/workspace")]
    cwd: String,
    /// Guest user override.
    #[arg(long)]
    user: Option<String>,
    /// Shell executable.
    #[arg(long, default_value = "/bin/sh")]
    shell: String,
}

#[derive(Debug, Subcommand)]
enum ArtifactCommand {
    /// List regular files below `/out`.
    List {
        /// Sandbox session ID.
        id: String,
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
    /// Download one regular `/out` file.
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
}

#[derive(Debug, Subcommand)]
enum CacheCommand {
    /// Show wrapper state directory disk usage.
    Status {
        /// Emit JSON.
        #[arg(long)]
        json: bool,
    },
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProjectModeArg {
    Copy,
    MountRo,
    MountRw,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum NetworkArg {
    Off,
    Public,
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
async fn main() -> ExitCode {
    let cli = Cli::parse();
    init_logging(cli.verbose);
    match run(cli).await {
        Ok(code) => exit_code(code),
        Err(error) => {
            eprintln!("asbx: {error:#}");
            ExitCode::FAILURE
        }
    }
}

async fn run(cli: Cli) -> Result<i32> {
    let config = match cli.config {
        Some(path) => HostConfig::load_from(path)?,
        None => HostConfig::load()?,
    };
    let state = StateStore::open_default()?;
    let state_path = state.path().to_path_buf();
    let root = std::env::current_dir().context("cannot read current directory")?;
    let service = AgentSandbox::new(
        Arc::new(MicrosandboxRuntime::default()),
        state,
        config,
        &root,
    )?;
    let reclaimed = service.reconcile().await?;
    for id in reclaimed {
        tracing::info!(sandbox = %id, "reclaimed expired sandbox");
    }

    match cli.command {
        Command::Doctor { json } => {
            let checks = service.doctor().await?;
            if json {
                let values: Vec<_> = checks
                    .iter()
                    .map(|(name, passed, detail)| {
                        serde_json::json!({"name": name, "passed": passed, "detail": detail})
                    })
                    .collect();
                println!("{}", serde_json::to_string_pretty(&values)?);
            } else {
                for (name, passed, detail) in &checks {
                    println!("{} {name}: {detail}", if *passed { "ok" } else { "FAIL" });
                }
            }
            Ok(if checks.iter().all(|(_, passed, _)| *passed) {
                0
            } else {
                1
            })
        }
        Command::Run(arguments) => run_one_shot(&service, arguments).await,
        Command::Open(arguments) => {
            let output = arguments.output;
            let opened = service.open(sandbox_options(arguments.sandbox)?).await?;
            match output {
                MetadataOutput::Text => {
                    println!("{}", opened.id);
                    for port in opened.ports {
                        eprintln!(
                            "{}/tcp -> http://127.0.0.1:{}",
                            port.guest_port, port.host_port
                        );
                    }
                }
                MetadataOutput::Json => println!("{}", serde_json::to_string_pretty(&opened)?),
            }
            Ok(0)
        }
        Command::Exec(arguments) => run_session_exec(&service, arguments).await,
        Command::Shell(arguments) => {
            service.require_session(&arguments.id)?;
            if !std::io::stdin().is_terminal() {
                bail!("shell requires an interactive terminal");
            }
            let code = service
                .attach(
                    &arguments.id,
                    ExecRequest {
                        command: arguments.shell,
                        args: vec![],
                        cwd: Some(arguments.cwd),
                        user: arguments.user,
                        env: vec![],
                        timeout: None,
                        tty: true,
                    },
                )
                .await?;
            Ok(code)
        }
        Command::Close { id } => {
            service.close(&id).await?;
            Ok(0)
        }
        Command::List { json } => {
            let sessions = service.list().await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&sessions)?);
            } else if sessions.is_empty() {
                println!("no open sessions");
            } else {
                for view in sessions {
                    let status = view
                        .runtime
                        .as_ref()
                        .map(|runtime| runtime.status.as_str())
                        .unwrap_or("missing");
                    println!(
                        "{}\t{}\t{}\t{}",
                        view.session.id,
                        status,
                        view.session.expires_at.to_rfc3339(),
                        view.session.project.display()
                    );
                }
            }
            Ok(0)
        }
        Command::Inspect { id, json } => {
            let view = service.inspect(&id).await?;
            if json {
                println!("{}", serde_json::to_string_pretty(&view)?);
            } else {
                println!("id: {}", view.session.id);
                println!("project: {}", view.session.project.display());
                println!("root: {}", view.session.root);
                println!("expires: {}", view.session.expires_at.to_rfc3339());
                println!(
                    "status: {}",
                    view.runtime
                        .map(|runtime| runtime.status)
                        .unwrap_or_else(|| "missing".into())
                );
            }
            Ok(0)
        }
        Command::Touch { id, ttl, json } => {
            let session = service.touch(&id, ttl)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&session)?);
            } else {
                println!("{}", session.expires_at.to_rfc3339());
            }
            Ok(0)
        }
        Command::Ports { id, json } => {
            let ports = service.ports(&id)?;
            if json {
                println!("{}", serde_json::to_string_pretty(&ports)?);
            } else {
                for port in ports {
                    println!(
                        "{}/tcp -> http://127.0.0.1:{}",
                        port.guest_port, port.host_port
                    );
                }
            }
            Ok(0)
        }
        Command::Artifact { command } => match command {
            ArtifactCommand::List { id, json } => {
                let artifacts = service.artifacts(&id).await?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&artifacts)?);
                } else {
                    for artifact in artifacts {
                        println!("{}\t{}", artifact.size, artifact.path);
                    }
                }
                Ok(0)
            }
            ArtifactCommand::Get { id, path, to } => {
                service.get_artifact(&id, &path, &to).await?;
                println!("{}", to.display());
                Ok(0)
            }
        },
        Command::Env { command } => match command {
            EnvCommand::Detect { project, json } => {
                let detection = service.detect(project)?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&detection)?);
                } else {
                    for language in detection.languages {
                        println!(
                            "{}\t{}\t{}",
                            language.name,
                            language.version.as_deref().unwrap_or("unspecified"),
                            language.source
                        );
                    }
                    for warning in detection.warnings {
                        eprintln!("warning: {warning}");
                    }
                }
                Ok(0)
            }
        },
        Command::Cache { command } => match command {
            CacheCommand::Status { json } => {
                let directory = state_path.parent().unwrap_or(Path::new("."));
                let status = agent_sandbox_cache::status(directory)?;
                if json {
                    println!(
                        "{}",
                        serde_json::json!({"path": directory, "files": status.files, "bytes": status.bytes})
                    );
                } else {
                    println!("path: {}", directory.display());
                    println!("files: {}", status.files);
                    println!("bytes: {}", status.bytes);
                }
                Ok(0)
            }
        },
    }
}

async fn run_one_shot(service: &AgentSandbox, arguments: RunArgs) -> Result<i32> {
    let output = arguments.output;
    let command = exec_request(
        arguments.command,
        Some("/workspace".into()),
        None,
        vec![],
        arguments.sandbox.timeout,
        false,
    )?;
    let opened = service
        .create_one_shot(sandbox_options(arguments.sandbox)?)
        .await?;
    if output == OutputArg::Jsonl {
        println!(
            "{}",
            serde_json::json!({"type":"sandbox.ready","id":opened.id,"root":opened.root})
        );
    }
    let result = async {
        let stream = service.exec(&opened.id, command).await?;
        consume_output(stream, output, opened.memory_tail_bytes).await
    }
    .await;
    let cleanup = service.cleanup(&opened.id).await;
    if let Err(error) = cleanup {
        if output == OutputArg::Jsonl {
            println!(
                "{}",
                serde_json::json!({
                    "type": "sandbox.cleanup_failed",
                    "id": opened.id,
                    "message": error.to_string(),
                })
            );
        }
        return Err(error.into());
    }
    if output == OutputArg::Jsonl {
        println!(
            "{}",
            serde_json::json!({"type":"sandbox.removed","id":opened.id})
        );
    }
    result
}

async fn run_session_exec(service: &AgentSandbox, arguments: SessionExecArgs) -> Result<i32> {
    service.require_session(&arguments.id)?;
    let output = arguments.output;
    let request = exec_request(
        arguments.command,
        Some(arguments.cwd),
        arguments.user,
        arguments.env_vars,
        arguments.timeout,
        false,
    )?;
    let stream = service.exec(&arguments.id, request).await?;
    let tail =
        agent_sandbox_policy::parse_bytes(&service.config().output.memory_tail, "memory_tail")?;
    consume_output(stream, output, usize::try_from(tail).unwrap_or(usize::MAX)).await
}

async fn consume_output(
    stream: agent_sandbox_runtime::ExecStream,
    output: OutputArg,
    tail_capacity: usize,
) -> Result<i32> {
    let format = match output {
        OutputArg::Text => OutputFormat::Text,
        OutputArg::Json => OutputFormat::Capture,
        OutputArg::Jsonl => OutputFormat::JsonLines,
    };
    let summary = forward(stream, format, tail_capacity).await?;
    if output == OutputArg::Json {
        print_summary(&summary)?;
    }
    Ok(summary.exit_code)
}

fn print_summary(summary: &ExecSummary) -> Result<()> {
    println!(
        "{}",
        serde_json::to_string_pretty(&serde_json::json!({
            "exit_code": summary.exit_code,
            "stdout": String::from_utf8_lossy(&summary.stdout_tail),
            "stdout_base64": STANDARD.encode(&summary.stdout_tail),
            "stdout_truncated": summary.stdout_truncated,
            "stderr": String::from_utf8_lossy(&summary.stderr_tail),
            "stderr_base64": STANDARD.encode(&summary.stderr_tail),
            "stderr_truncated": summary.stderr_truncated,
        }))?
    );
    Ok(())
}

fn sandbox_options(arguments: CommonSandboxArgs) -> Result<SandboxOptions> {
    if !matches!(arguments.project_mode, ProjectModeArg::Copy) {
        bail!(
            "project mode {:?} is not enabled in Phase 1; use the safe default --project-mode copy",
            arguments.project_mode
        );
    }
    Ok(SandboxOptions {
        project: arguments.project,
        image: arguments.image,
        snapshot: arguments.snapshot,
        environment: Some(arguments.environment),
        cpus: arguments.cpus,
        memory: arguments.memory,
        disk: arguments.disk,
        user: arguments.user,
        security: match arguments.security {
            SecurityArg::Default => SecurityMode::Default,
            SecurityArg::Restricted => SecurityMode::Restricted,
        },
        network: arguments.network.map(|network| match network {
            NetworkArg::Off => NetworkMode::Off,
            NetworkArg::Public => NetworkMode::Public,
            NetworkArg::All => NetworkMode::All,
        }),
        timeout: arguments.timeout,
        ttl: arguments.ttl,
        env: arguments.env_vars,
        ports: arguments.publish,
    })
}

fn exec_request(
    mut command: Vec<String>,
    cwd: Option<String>,
    user: Option<String>,
    env: Vec<(String, String)>,
    timeout: Option<Duration>,
    tty: bool,
) -> Result<ExecRequest> {
    if command.is_empty() {
        bail!("guest command is required");
    }
    let executable = command.remove(0);
    Ok(ExecRequest {
        command: executable,
        args: command,
        cwd,
        user,
        env,
        timeout,
        tty,
    })
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
