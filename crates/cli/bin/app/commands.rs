//! CLI command dispatch and user-facing command workflows.

use std::{io::IsTerminal, path::Path};

use agent_sandbox_core::{
    AgentSandbox, CachePruneOptions, EnvironmentBuildOptions, PreparedEnvironment,
};
use agent_sandbox_exec::{ExecSummary, OutputFormat, forward};
use agent_sandbox_runtime::{ExecRequest, ProjectMode};
use anyhow::{Result, bail};
use base64::{Engine, engine::general_purpose::STANDARD};

use crate::debugger;

use super::{
    ArtifactCommand, BackendCommand, CacheCommand, Cli, Command, EnvCommand, EnvCreateArgs,
    MetadataOutput, OutputArg, RunArgs, SessionExecArgs,
    bootstrap::Application,
    proxy,
    request::{exec_request, sandbox_options},
    setup,
};

pub(super) async fn run(cli: Cli) -> Result<i32> {
    let Cli {
        config, command, ..
    } = cli;
    let command = match command {
        Command::Setup(arguments) => return setup::run(config.as_deref(), arguments).await,
        command => command,
    };
    let Application {
        service,
        runtimes,
        default_backend,
        state_path,
    } = Application::load(config).await?;

    match command {
        Command::Setup(_) => unreachable!("setup returned before application bootstrap"),
        Command::Doctor { backend, json } => {
            let backend = backend.unwrap_or(default_backend);
            let mut checks = runtimes.doctor_backend(&backend).await?;
            checks.extend(proxy::doctor_checks(service.config())?);
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
        Command::Backend { command } => match command {
            BackendCommand::List { json } => {
                let capabilities = runtimes.all_capabilities();
                if json {
                    println!("{}", serde_json::to_string_pretty(&capabilities)?);
                } else {
                    for capability in capabilities {
                        println!(
                            "{}\tboot={}\tfeatures={}\tarch={}\taccel={}",
                            capability.backend,
                            join_debug(&capability.boot_sources),
                            join_debug(&capability.features),
                            capability.architectures.join(","),
                            capability.accelerators.join(",")
                        );
                    }
                }
                Ok(0)
            }
        },
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
            let session = service.require_session(&arguments.id)?;
            let layout = service.guest_layout(&session.backend)?;
            if !std::io::stdin().is_terminal() {
                bail!("shell requires an interactive terminal");
            }
            let code = service
                .attach(
                    &arguments.id,
                    ExecRequest {
                        command: arguments.shell.unwrap_or(layout.shell),
                        args: vec![],
                        cwd: Some(arguments.cwd.unwrap_or(session.default_cwd)),
                        user: arguments.user,
                        env: vec![],
                        timeout: None,
                        tty: true,
                    },
                )
                .await?;
            Ok(code)
        }
        Command::Debug(arguments) => debugger::run(&service, arguments).await,
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
                        "{}\t{}\t{}\t{}\t{}",
                        view.session.id,
                        view.session.backend,
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
                println!("backend: {}", view.session.backend);
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
    let options = sandbox_options(arguments.sandbox)?;
    let project_mode = options.project_mode;
    let command_environment = options.env.clone();
    let command_timeout = options.timeout;
    let opened = service.create_one_shot(options).await?;
    if output == OutputArg::Jsonl {
        println!(
            "{}",
            serde_json::json!({"type":"sandbox.ready","id":opened.id,"root":opened.root})
        );
    }
    let cwd = if project_mode == ProjectMode::None {
        opened.guest_layout.root.clone()
    } else {
        opened.guest_layout.workspace.clone()
    };
    let result = async {
        let command = exec_request(
            arguments.command,
            Some(cwd),
            None,
            command_environment,
            command_timeout,
            false,
        )?;
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
    let session = service.require_session(&arguments.id)?;
    let output = arguments.output;
    let request = exec_request(
        arguments.command,
        Some(arguments.cwd.unwrap_or(session.default_cwd)),
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

fn join_debug<T: std::fmt::Debug>(values: &[T]) -> String {
    values
        .iter()
        .map(|value| format!("{value:?}"))
        .collect::<Vec<_>>()
        .join(",")
}
