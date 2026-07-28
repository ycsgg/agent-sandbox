//! `asbx` command-line interface.

#![forbid(unsafe_code)]

use std::{
    io::IsTerminal,
    path::{Path, PathBuf},
    process::ExitCode,
    sync::Arc,
    time::Duration,
};

use agent_sandbox_core::{
    AgentSandbox, CachePruneOptions, EnvironmentBuildOptions, PreparedEnvironment, RequestedPort,
    SandboxOptions,
};
use agent_sandbox_exec::{ExecSummary, OutputFormat, forward};
use agent_sandbox_policy::{HostConfig, parse_duration};
use agent_sandbox_runtime::{
    ExecRequest, NetworkMode, NetworkRule, NetworkRuleAction, NetworkRuleTarget, ProjectMode,
    SecurityMode,
};
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
    /// Project directory to copy or mount at `/workspace`.
    #[arg(long, default_value = ".")]
    project: PathBuf,
    /// Project exposure mode. Writable mounts require explicit host policy.
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
    Copy,
    MountRo,
    MountRw,
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
            EnvCommand::Create(arguments) => create_environment(&service, arguments).await,
            EnvCommand::List { json } => {
                let environments = service.list_environments()?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&environments)?);
                } else if environments.is_empty() {
                    println!("no managed environments");
                } else {
                    for environment in environments {
                        println!(
                            "{}\t{}\t{}\t{}",
                            environment.name,
                            environment.snapshot,
                            environment.last_used_at.to_rfc3339(),
                            environment.toolchains.join(",")
                        );
                    }
                }
                Ok(0)
            }
            EnvCommand::Inspect { name, json } => {
                let environment = service.inspect_environment(&name).await?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&environment)?);
                } else {
                    println!("name: {}", environment.name);
                    println!("snapshot: {}", environment.snapshot);
                    println!("base: {}", environment.base);
                    println!("toolchains: {}", environment.toolchains.join(", "));
                    println!("cache key: {}", environment.cache_key);
                    println!("size: {}", environment.size_bytes);
                    println!("last used: {}", environment.last_used_at.to_rfc3339());
                }
                Ok(0)
            }
            EnvCommand::Remove { name } => {
                service.remove_environment(&name).await?;
                println!("{name}");
                Ok(0)
            }
        },
        Command::Cache { command } => match command {
            CacheCommand::Status { json } => {
                let directory = state_path.parent().unwrap_or(Path::new("."));
                let status = agent_sandbox_cache::status(directory)?;
                let inventory = service.cache_inventory().await?;
                if json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "state": {
                                "path": directory,
                                "files": status.files,
                                "bytes": status.bytes,
                            },
                            "runtime": inventory,
                        }))?
                    );
                } else {
                    println!("state path: {}", directory.display());
                    println!("state files: {}", status.files);
                    println!("state bytes: {}", status.bytes);
                    println!("images: {}", inventory.images.len());
                    println!("environments: {}", inventory.environments.len());
                    println!("runtime logical bytes: {}", inventory.logical_bytes);
                }
                Ok(0)
            }
            CacheCommand::Prune {
                max_size,
                older_than,
                include_environments,
                dry_run,
                json,
            } => {
                let maximum = max_size
                    .as_deref()
                    .unwrap_or(&service.config().cache.max_size);
                let maximum_bytes = agent_sandbox_policy::parse_bytes(maximum, "cache max_size")?;
                let report = service
                    .prune_cache(CachePruneOptions {
                        maximum_bytes,
                        older_than,
                        include_environments,
                        dry_run,
                    })
                    .await?;
                if json {
                    println!("{}", serde_json::to_string_pretty(&report)?);
                } else {
                    println!(
                        "{}: {} -> {} logical bytes (target {})",
                        if report.dry_run { "plan" } else { "pruned" },
                        report.plan.before_bytes,
                        report.after_bytes,
                        report.plan.maximum_bytes
                    );
                    for entry in &report.plan.selected {
                        println!(
                            "{}\t{:?}\t{}\t{}",
                            if report.dry_run {
                                "would-remove"
                            } else {
                                "selected"
                            },
                            entry.kind,
                            entry.size_bytes,
                            entry.key
                        );
                    }
                    for failure in &report.failures {
                        eprintln!(
                            "warning: could not remove {}: {}",
                            failure.entry.key, failure.message
                        );
                    }
                    if !report.target_met {
                        eprintln!(
                            "warning: cache target was not reached; protected or in-use entries remain"
                        );
                    }
                }
                Ok(if report.failures.is_empty() { 0 } else { 1 })
            }
        },
    }
}

async fn create_environment(service: &AgentSandbox, arguments: EnvCreateArgs) -> Result<i32> {
    let output = arguments.output;
    match service
        .prepare_environment(EnvironmentBuildOptions {
            name: arguments.name,
            base: arguments.base,
            toolchains: arguments.toolchain,
            cpus: arguments.cpus,
            memory: arguments.memory,
            disk: arguments.disk,
            force: arguments.force,
        })
        .await?
    {
        PreparedEnvironment::Cached(record) => {
            match output {
                OutputArg::Text => {
                    println!("cache hit: {} ({})", record.name, record.snapshot);
                }
                OutputArg::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &serde_json::json!({"cached": true, "environment": record})
                    )?
                ),
                OutputArg::Jsonl => println!(
                    "{}",
                    serde_json::json!({"type": "environment.ready", "cached": true, "environment": record})
                ),
            }
            Ok(0)
        }
        PreparedEnvironment::Building(mut builder) => {
            let builder_id = builder.id.clone();
            if output == OutputArg::Jsonl {
                println!(
                    "{}",
                    serde_json::json!({
                        "type": "environment.builder_started",
                        "id": builder_id,
                        "name": builder.build.name,
                        "cache_key": builder.build.cache_key,
                    })
                );
            }
            let stream = builder.take_stream()?;
            let format = match output {
                OutputArg::Text => OutputFormat::Text,
                OutputArg::Json => OutputFormat::Capture,
                OutputArg::Jsonl => OutputFormat::JsonLines,
            };
            let summary = match forward(stream, format, builder.memory_tail_bytes).await {
                Ok(summary) => summary,
                Err(error) => {
                    let cleanup = service.abort_environment(&builder_id).await;
                    if let Err(cleanup_error) = cleanup {
                        return Err(anyhow::anyhow!(
                            "{error}; additionally failed to clean up builder {builder_id}: {cleanup_error}"
                        ));
                    }
                    return Err(error.into());
                }
            };
            if summary.exit_code != 0 {
                service.abort_environment(&builder_id).await?;
                if output == OutputArg::Json {
                    println!(
                        "{}",
                        serde_json::to_string_pretty(&serde_json::json!({
                            "cached": false,
                            "builder_id": builder_id,
                            "exit_code": summary.exit_code,
                            "stdout": String::from_utf8_lossy(&summary.stdout_tail),
                            "stdout_base64": STANDARD.encode(&summary.stdout_tail),
                            "stdout_truncated": summary.stdout_truncated,
                            "stderr": String::from_utf8_lossy(&summary.stderr_tail),
                            "stderr_base64": STANDARD.encode(&summary.stderr_tail),
                            "stderr_truncated": summary.stderr_truncated,
                        }))?
                    );
                }
                return Ok(summary.exit_code);
            }
            let record = service.finalize_environment(*builder).await?;
            match output {
                OutputArg::Text => {
                    println!("environment ready: {} ({})", record.name, record.snapshot);
                }
                OutputArg::Json => println!(
                    "{}",
                    serde_json::to_string_pretty(&serde_json::json!({
                        "cached": false,
                        "environment": record,
                        "exit_code": summary.exit_code,
                        "stdout": String::from_utf8_lossy(&summary.stdout_tail),
                        "stdout_base64": STANDARD.encode(&summary.stdout_tail),
                        "stdout_truncated": summary.stdout_truncated,
                        "stderr": String::from_utf8_lossy(&summary.stderr_tail),
                        "stderr_base64": STANDARD.encode(&summary.stderr_tail),
                        "stderr_truncated": summary.stderr_truncated,
                    }))?
                ),
                OutputArg::Jsonl => println!(
                    "{}",
                    serde_json::json!({"type": "environment.ready", "cached": false, "environment": record})
                ),
            }
            Ok(0)
        }
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
    let project_mode = match arguments.project_mode {
        ProjectModeArg::Copy => ProjectMode::Copy,
        ProjectModeArg::MountRo => ProjectMode::MountReadOnly,
        ProjectModeArg::MountRw => ProjectMode::MountReadWrite,
    };
    if project_mode == ProjectMode::MountReadWrite {
        eprintln!(
            "warning: --project-mode mount-rw lets guest processes modify the authorized host project"
        );
    }
    let mut network_rules = Vec::new();
    extend_string_rules(
        &mut network_rules,
        NetworkRuleAction::Allow,
        arguments.allow_domains,
        NetworkRuleTarget::Domain,
    );
    extend_string_rules(
        &mut network_rules,
        NetworkRuleAction::Deny,
        arguments.deny_domains,
        NetworkRuleTarget::Domain,
    );
    extend_string_rules(
        &mut network_rules,
        NetworkRuleAction::Allow,
        arguments.allow_domain_suffixes,
        NetworkRuleTarget::DomainSuffix,
    );
    extend_string_rules(
        &mut network_rules,
        NetworkRuleAction::Deny,
        arguments.deny_domain_suffixes,
        NetworkRuleTarget::DomainSuffix,
    );
    extend_string_rules(
        &mut network_rules,
        NetworkRuleAction::Allow,
        arguments.allow_cidrs,
        NetworkRuleTarget::Cidr,
    );
    extend_string_rules(
        &mut network_rules,
        NetworkRuleAction::Deny,
        arguments.deny_cidrs,
        NetworkRuleTarget::Cidr,
    );
    network_rules.extend(
        arguments
            .allow_ports
            .into_iter()
            .map(|(start, end)| NetworkRule {
                action: NetworkRuleAction::Allow,
                target: NetworkRuleTarget::PublicPort { start, end },
            }),
    );
    network_rules.extend(
        arguments
            .deny_ports
            .into_iter()
            .map(|(start, end)| NetworkRule {
                action: NetworkRuleAction::Deny,
                target: NetworkRuleTarget::PublicPort { start, end },
            }),
    );
    for (enabled, target) in [
        (arguments.allow_private, NetworkRuleTarget::Private),
        (arguments.allow_host, NetworkRuleTarget::Host),
        (arguments.allow_metadata, NetworkRuleTarget::Metadata),
    ] {
        if enabled {
            network_rules.push(NetworkRule {
                action: NetworkRuleAction::Allow,
                target,
            });
        }
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
            NetworkArg::Dependencies => NetworkMode::Dependencies,
            NetworkArg::Rules => NetworkMode::Rules,
            NetworkArg::All => NetworkMode::All,
        }),
        network_rules,
        project_mode,
        timeout: arguments.timeout,
        ttl: arguments.ttl,
        env: arguments.env_vars,
        ports: arguments.publish,
    })
}

fn extend_string_rules(
    rules: &mut Vec<NetworkRule>,
    action: NetworkRuleAction,
    values: Vec<String>,
    target: impl Fn(String) -> NetworkRuleTarget,
) {
    rules.extend(values.into_iter().map(|value| NetworkRule {
        action,
        target: target(value),
    }));
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
