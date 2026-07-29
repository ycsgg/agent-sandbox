//! Host debugger discovery and attachment for typed runtime debug contexts.

use std::{
    ffi::{OsStr, OsString},
    fs::File,
    io::Read,
    net::SocketAddr,
    path::{Path, PathBuf},
    process::Stdio,
};

use agent_sandbox_core::AgentSandbox;
use agent_sandbox_runtime::DebugProtocol;
use anyhow::{Context, Result, bail};
use clap::{Args, ValueEnum};

/// Arguments for `asbx debug`.
#[derive(Debug, Args)]
pub(crate) struct DebugArgs {
    /// Sandbox session ID exposing a remote-debugging capability.
    pub(crate) id: String,

    /// Uncompressed executable with matching symbols, normally `vmlinux`.
    #[arg(long)]
    symbols: Option<PathBuf>,

    /// Debugger family. Auto prefers LLDB on macOS and GDB elsewhere.
    #[arg(long, default_value = "auto")]
    debugger: DebuggerArg,

    /// Explicit debugger executable path or name.
    #[arg(long)]
    debugger_binary: Option<PathBuf>,

    /// Pass one additional argument to the debugger. Repeat as needed.
    #[arg(long = "debugger-arg", allow_hyphen_values = true)]
    debugger_args: Vec<String>,

    /// Execute one debugger command after connecting. Repeat as needed.
    #[arg(long = "command")]
    commands: Vec<String>,

    /// Print the resolved executable and argument array without launching it.
    #[arg(long)]
    print_command: bool,

    /// Emit the command plan as JSON. Requires --print-command.
    #[arg(long, requires = "print_command")]
    json: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
enum DebuggerArg {
    Auto,
    Gdb,
    Lldb,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DebuggerKind {
    Gdb,
    Lldb,
}

impl DebuggerKind {
    fn as_str(self) -> &'static str {
        match self {
            Self::Gdb => "gdb",
            Self::Lldb => "lldb",
        }
    }
}

struct DebugPlan {
    kind: DebuggerKind,
    program: PathBuf,
    arguments: Vec<OsString>,
    endpoint: SocketAddr,
    architecture: String,
    accelerator: String,
    status: String,
    symbols: Option<PathBuf>,
    boot_kernel: Option<PathBuf>,
    symbol_mode: &'static str,
    warnings: Vec<String>,
}

/// Resolve and optionally launch a host debugger for one sandbox session.
pub(crate) async fn run(service: &AgentSandbox, arguments: DebugArgs) -> Result<i32> {
    let plan = build_plan(service, &arguments).await?;
    if arguments.print_command {
        print_plan(&plan, arguments.json)?;
        return Ok(0);
    }

    for warning in &plan.warnings {
        eprintln!("warning: {warning}");
    }
    eprintln!(
        "attaching {} to {} ({}, {}, {})",
        plan.kind.as_str(),
        plan.endpoint,
        plan.architecture,
        plan.accelerator,
        plan.status
    );
    let status = tokio::process::Command::new(&plan.program)
        .args(&plan.arguments)
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .status()
        .await
        .with_context(|| format!("cannot launch debugger {}", plan.program.display()))?;
    Ok(status.code().unwrap_or(1))
}

async fn build_plan(service: &AgentSandbox, arguments: &DebugArgs) -> Result<DebugPlan> {
    let context = service.debug_context(&arguments.id).await?;
    if !context.is_active() {
        bail!(
            "session {} is not running (status {})",
            arguments.id,
            context.status
        );
    }
    let endpoint = match context.protocol {
        DebugProtocol::GdbRemote => validate_loopback_endpoint(context.endpoint)?,
        protocol => bail!("unsupported remote debugger protocol {protocol:?}"),
    };
    let architecture = context.architecture;
    let accelerator = context.accelerator.unwrap_or_else(|| "unknown".into());

    let explicit_symbols = arguments
        .symbols
        .as_deref()
        .map(|path| canonical_file("symbol file", path))
        .transpose()?;
    let boot_kernel = context.boot_kernel.filter(|path| path.is_file());
    let symbol_mode = if explicit_symbols.is_some() {
        "symbols"
    } else {
        "none"
    };
    let linux_kernel = explicit_symbols
        .as_deref()
        .or(boot_kernel.as_deref())
        .is_some_and(looks_like_linux_kernel);
    let mut warnings = debugger_warnings(
        explicit_symbols.is_some(),
        boot_kernel.is_some(),
        &accelerator,
        context.paused_at_boot,
        context.kaslr_disabled,
        linux_kernel,
        &context.status,
    );
    if let Some(symbols) = &explicit_symbols {
        match detect_architecture(symbols)? {
            Some(detected) if !architectures_match(&detected, &architecture) => {
                bail!(
                    "debug target {} is {detected}, but the guest architecture is {architecture}",
                    symbols.display()
                );
            }
            None => warnings.push(format!(
                "could not determine the architecture of {}; the debugger must validate it",
                symbols.display()
            )),
            Some(_) => {}
        }
    }

    let (kind, program) = resolve_debugger(
        arguments.debugger,
        arguments.debugger_binary.as_deref(),
        &architecture,
    )?;
    let command_arguments = debugger_arguments(
        kind,
        explicit_symbols.as_deref(),
        endpoint,
        &arguments.debugger_args,
        &arguments.commands,
    );
    Ok(DebugPlan {
        kind,
        program,
        arguments: command_arguments,
        endpoint,
        architecture,
        accelerator,
        status: context.status,
        symbols: explicit_symbols,
        boot_kernel,
        symbol_mode,
        warnings,
    })
}

fn debugger_warnings(
    explicit_symbols: bool,
    has_boot_kernel: bool,
    accelerator: &str,
    paused_at_boot: Option<bool>,
    kaslr_disabled: Option<bool>,
    linux_kernel: bool,
    status: &str,
) -> Vec<String> {
    let mut warnings = Vec::new();
    if !explicit_symbols {
        warnings.push(if has_boot_kernel {
            "no --symbols file was supplied; the debugger will attach without loading the guest boot image"
                .into()
        } else {
            "no --symbols file is available; debugging is limited to raw registers, memory, and remote disassembly"
                .into()
        });
    }
    if accelerator != "tcg" {
        warnings.push(format!(
            "accelerator {accelerator} may provide fewer breakpoint or watchpoint features than tcg"
        ));
    }
    if paused_at_boot != Some(true) {
        warnings.push(if status == "prelaunch" {
            "the runtime is paused, but metadata cannot confirm --pause-at-boot".into()
        } else {
            "the guest was not opened with --pause-at-boot; early startup code may already have executed"
                .into()
        });
    }
    if linux_kernel && kaslr_disabled != Some(true) {
        warnings.push(
            "KASLR is not confirmed disabled; add --kernel-append nokaslr for stable symbol addresses"
                .into(),
        );
    }
    warnings
}

fn looks_like_linux_kernel(path: &Path) -> bool {
    let name = path
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    name == "image"
        || name == "bzimage"
        || name.starts_with("vmlinux")
        || name.starts_with("vmlinuz")
}

fn validate_loopback_endpoint(endpoint: SocketAddr) -> Result<SocketAddr> {
    if !endpoint.ip().is_loopback() {
        bail!("refusing non-loopback GDB endpoint {endpoint}");
    }
    Ok(endpoint)
}

fn canonical_file(label: &str, path: &Path) -> Result<PathBuf> {
    let canonical = path
        .canonicalize()
        .with_context(|| format!("cannot resolve {label} {}", path.display()))?;
    if !canonical.is_file() {
        bail!("{label} {} is not a regular file", canonical.display());
    }
    Ok(canonical)
}

fn resolve_debugger(
    requested: DebuggerArg,
    configured: Option<&Path>,
    architecture: &str,
) -> Result<(DebuggerKind, PathBuf)> {
    if let Some(configured) = configured {
        let program = which::which(configured).with_context(|| {
            format!(
                "cannot find configured debugger executable {}",
                configured.display()
            )
        })?;
        let kind = match requested {
            DebuggerArg::Gdb => DebuggerKind::Gdb,
            DebuggerArg::Lldb => DebuggerKind::Lldb,
            DebuggerArg::Auto => infer_debugger_kind(&program)?,
        };
        return Ok((kind, program));
    }

    let mut candidates = Vec::new();
    match requested {
        DebuggerArg::Gdb => add_gdb_candidates(&mut candidates, architecture),
        DebuggerArg::Lldb => candidates.push((DebuggerKind::Lldb, "lldb")),
        DebuggerArg::Auto => {
            #[cfg(target_os = "macos")]
            candidates.push((DebuggerKind::Lldb, "lldb"));
            add_gdb_candidates(&mut candidates, architecture);
            #[cfg(not(target_os = "macos"))]
            candidates.push((DebuggerKind::Lldb, "lldb"));
        }
    }
    for (kind, candidate) in &candidates {
        if let Ok(program) = which::which(candidate) {
            return Ok((*kind, program));
        }
    }
    let names = candidates
        .iter()
        .map(|(_, name)| *name)
        .collect::<Vec<_>>()
        .join(", ");
    bail!("no supported debugger found; tried {names}")
}

fn add_gdb_candidates(candidates: &mut Vec<(DebuggerKind, &'static str)>, architecture: &str) {
    match normalize_architecture(architecture) {
        "aarch64" => {
            candidates.push((DebuggerKind::Gdb, "aarch64-linux-gnu-gdb"));
            candidates.push((DebuggerKind::Gdb, "aarch64-none-elf-gdb"));
        }
        "x86_64" => candidates.push((DebuggerKind::Gdb, "x86_64-linux-gnu-gdb")),
        "riscv64" => {
            candidates.push((DebuggerKind::Gdb, "riscv64-linux-gnu-gdb"));
            candidates.push((DebuggerKind::Gdb, "riscv64-unknown-elf-gdb"));
        }
        _ => {}
    }
    candidates.push((DebuggerKind::Gdb, "gdb-multiarch"));
    candidates.push((DebuggerKind::Gdb, "gdb"));
}

fn infer_debugger_kind(program: &Path) -> Result<DebuggerKind> {
    let name = program
        .file_name()
        .and_then(OsStr::to_str)
        .unwrap_or_default()
        .to_ascii_lowercase();
    if name.contains("lldb") {
        Ok(DebuggerKind::Lldb)
    } else if name.contains("gdb") {
        Ok(DebuggerKind::Gdb)
    } else {
        bail!(
            "cannot infer debugger family from {}; specify --debugger gdb or --debugger lldb",
            program.display()
        )
    }
}

fn debugger_arguments(
    kind: DebuggerKind,
    target: Option<&Path>,
    endpoint: SocketAddr,
    additional: &[String],
    commands: &[String],
) -> Vec<OsString> {
    let mut arguments = additional.iter().map(OsString::from).collect::<Vec<_>>();
    match kind {
        DebuggerKind::Gdb => {
            arguments.push("--nx".into());
            arguments.push("-iex".into());
            arguments.push("set auto-load off".into());
            if let Some(target) = target {
                arguments.push(target.as_os_str().to_owned());
            }
            arguments.push("-ex".into());
            arguments.push(format!("target remote {endpoint}").into());
            for command in commands {
                arguments.push("-ex".into());
                arguments.push(command.into());
            }
        }
        DebuggerKind::Lldb => {
            arguments.push("--no-lldbinit".into());
            arguments.push("--one-line-before-file".into());
            arguments.push("settings set target.load-script-from-symbol-file false".into());
            if let Some(target) = target {
                arguments.push(target.as_os_str().to_owned());
            }
            arguments.push("--one-line".into());
            arguments.push(format!("gdb-remote {endpoint}").into());
            for command in commands {
                arguments.push("--one-line".into());
                arguments.push(command.into());
            }
        }
    }
    arguments
}

fn print_plan(plan: &DebugPlan, json: bool) -> Result<()> {
    let arguments = plan
        .arguments
        .iter()
        .map(|argument| argument.to_string_lossy().into_owned())
        .collect::<Vec<_>>();
    if json {
        println!(
            "{}",
            serde_json::to_string_pretty(&serde_json::json!({
                "debugger": plan.kind.as_str(),
                "program": plan.program,
                "arguments": arguments,
                "endpoint": plan.endpoint.to_string(),
                "architecture": plan.architecture,
                "accelerator": plan.accelerator,
                "status": plan.status,
                "symbols": plan.symbols,
                "boot_kernel": plan.boot_kernel,
                "symbol_mode": plan.symbol_mode,
                "ready": true,
                "warnings": plan.warnings,
            }))?
        );
    } else {
        for warning in &plan.warnings {
            eprintln!("warning: {warning}");
        }
        println!("program: {}", plan.program.display());
        println!("arguments: {}", serde_json::to_string(&arguments)?);
    }
    Ok(())
}

fn detect_architecture(path: &Path) -> Result<Option<String>> {
    let mut file =
        File::open(path).with_context(|| format!("cannot inspect {}", path.display()))?;
    let mut header = [0_u8; 512];
    let read = file
        .read(&mut header)
        .with_context(|| format!("cannot read {}", path.display()))?;
    let header = &header[..read];

    if header.starts_with(b"\x7fELF") && header.len() >= 20 {
        let machine = match header[5] {
            1 => u16::from_le_bytes([header[18], header[19]]),
            2 => u16::from_be_bytes([header[18], header[19]]),
            _ => return Ok(None),
        };
        return Ok(elf_machine_architecture(machine));
    }
    if header.starts_with(b"MZ") && header.len() >= 0x40 {
        let pe_offset =
            u32::from_le_bytes([header[0x3c], header[0x3d], header[0x3e], header[0x3f]]) as usize;
        if pe_offset
            .checked_add(6)
            .is_some_and(|required| required <= header.len())
            && &header[pe_offset..pe_offset + 4] == b"PE\0\0"
        {
            let machine = u16::from_le_bytes([header[pe_offset + 4], header[pe_offset + 5]]);
            return Ok(pe_machine_architecture(machine));
        }
    }
    Ok(None)
}

fn elf_machine_architecture(machine: u16) -> Option<String> {
    match machine {
        0x003e => Some("x86_64".into()),
        0x00b7 => Some("aarch64".into()),
        0x00f3 => Some("riscv64".into()),
        _ => None,
    }
}

fn pe_machine_architecture(machine: u16) -> Option<String> {
    match machine {
        0x8664 => Some("x86_64".into()),
        0xaa64 => Some("aarch64".into()),
        0x5064 => Some("riscv64".into()),
        _ => None,
    }
}

fn architectures_match(left: &str, right: &str) -> bool {
    normalize_architecture(left) == normalize_architecture(right)
}

fn normalize_architecture(value: &str) -> &str {
    match value {
        "arm64" => "aarch64",
        "amd64" | "x64" => "x86_64",
        other => other,
    }
}

#[cfg(test)]
mod tests {
    use std::io::Write;

    use tempfile::NamedTempFile;

    use super::*;

    #[test]
    fn only_loopback_debug_endpoints_are_accepted() {
        assert_eq!(
            validate_loopback_endpoint("127.0.0.1:1234".parse().unwrap()).unwrap(),
            "127.0.0.1:1234".parse().unwrap()
        );
        assert_eq!(
            validate_loopback_endpoint("[::1]:4321".parse().unwrap()).unwrap(),
            "[::1]:4321".parse().unwrap()
        );
        assert!(validate_loopback_endpoint("0.0.0.0:1234".parse().unwrap()).is_err());
    }

    #[test]
    fn debugger_arguments_preserve_boundaries() {
        let arguments = debugger_arguments(
            DebuggerKind::Lldb,
            Some(Path::new("/tmp/kernel symbols")),
            "127.0.0.1:1234".parse().unwrap(),
            &["--batch".into()],
            &["register read pc".into()],
        );
        assert_eq!(
            arguments,
            [
                "--batch",
                "--no-lldbinit",
                "--one-line-before-file",
                "settings set target.load-script-from-symbol-file false",
                "/tmp/kernel symbols",
                "--one-line",
                "gdb-remote 127.0.0.1:1234",
                "--one-line",
                "register read pc",
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn gdb_disables_init_and_symbol_script_auto_loading() {
        let arguments = debugger_arguments(
            DebuggerKind::Gdb,
            None,
            "127.0.0.1:1234".parse().unwrap(),
            &["--batch".into()],
            &["info registers".into()],
        );
        assert_eq!(
            arguments,
            [
                "--batch",
                "--nx",
                "-iex",
                "set auto-load off",
                "-ex",
                "target remote 127.0.0.1:1234",
                "-ex",
                "info registers",
            ]
            .map(OsString::from)
        );
    }

    #[test]
    fn detects_elf_and_pe_architectures() {
        let mut elf = NamedTempFile::new().unwrap();
        let mut elf_header = [0_u8; 64];
        elf_header[..6].copy_from_slice(b"\x7fELF\x02\x01");
        elf_header[18..20].copy_from_slice(&183_u16.to_le_bytes());
        elf.write_all(&elf_header).unwrap();
        assert_eq!(
            detect_architecture(elf.path()).unwrap().as_deref(),
            Some("aarch64")
        );

        let mut pe = NamedTempFile::new().unwrap();
        let mut pe_header = [0_u8; 128];
        pe_header[..2].copy_from_slice(b"MZ");
        pe_header[0x3c..0x40].copy_from_slice(&64_u32.to_le_bytes());
        pe_header[64..68].copy_from_slice(b"PE\0\0");
        pe_header[68..70].copy_from_slice(&0xaa64_u16.to_le_bytes());
        pe.write_all(&pe_header).unwrap();
        assert_eq!(
            detect_architecture(pe.path()).unwrap().as_deref(),
            Some("aarch64")
        );
    }

    #[test]
    fn warnings_explain_reduced_debug_quality() {
        let warnings = debugger_warnings(
            false,
            true,
            "hvf",
            Some(false),
            Some(false),
            true,
            "running",
        );
        assert!(warnings.iter().any(|warning| warning.contains("--symbols")));
        assert!(warnings.iter().any(|warning| warning.contains("tcg")));
        assert!(
            warnings
                .iter()
                .any(|warning| warning.contains("--pause-at-boot"))
        );
        assert!(warnings.iter().any(|warning| warning.contains("nokaslr")));
    }
}
