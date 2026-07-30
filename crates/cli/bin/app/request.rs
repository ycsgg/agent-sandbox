//! Translation from CLI arguments into runtime-neutral core requests.

use std::{
    path::{Path, PathBuf},
    time::Duration,
};

use agent_sandbox_core::SandboxOptions;
use agent_sandbox_runtime::{
    BackendId, DiskImageFormat, DiskImageSpec, ExecRequest, MachineBootSpec, MachineDebugSpec,
    NetworkMode, NetworkRule, NetworkRuleAction, NetworkRuleTarget, ProjectMode, SecurityMode,
};
use anyhow::{Context, Result, bail};

use super::{CommonSandboxArgs, DiskFormatArg, NetworkArg, ProjectModeArg, SecurityArg};

pub(super) fn sandbox_options(arguments: CommonSandboxArgs) -> Result<SandboxOptions> {
    let machine_requested = arguments.root_disk.is_some()
        || arguments.kernel.is_some()
        || arguments.initrd.is_some()
        || arguments.dtb.is_some()
        || arguments.firmware.is_some()
        || arguments.arch.is_some()
        || arguments.machine.is_some()
        || arguments.cpu.is_some()
        || arguments.accelerator.is_some()
        || !arguments.kernel_append.is_empty()
        || arguments.gdb.is_some();
    let android_requested = arguments.android_artifacts.is_some();
    if machine_requested && android_requested {
        bail!("Android artifacts cannot be combined with QEMU machine boot options");
    }
    let backend = match (arguments.backend, machine_requested, android_requested) {
        (Some(backend), _, _) => Some(backend),
        (None, true, false) => Some(BackendId::qemu()),
        (None, false, true) => Some(BackendId::cuttlefish()),
        (None, false, false) => None,
        (None, true, true) => unreachable!("mixed boot inputs were rejected"),
    };
    if backend
        .as_ref()
        .is_some_and(|backend| backend.as_str() == BackendId::QEMU)
        && !machine_requested
    {
        bail!("the qemu backend requires --root-disk and/or --kernel");
    }
    if android_requested
        && backend
            .as_ref()
            .is_some_and(|backend| backend.as_str() != BackendId::CUTTLEFISH)
    {
        bail!("--android-artifacts requires the cuttlefish backend");
    }
    if backend
        .as_ref()
        .is_some_and(|backend| backend.as_str() == BackendId::CUTTLEFISH)
        && machine_requested
    {
        bail!("the cuttlefish backend cannot use QEMU machine boot options");
    }
    if arguments.disk_format.is_some() && arguments.root_disk.is_none() {
        bail!("--disk-format requires --root-disk");
    }
    if arguments.root_disk_read_only && arguments.root_disk.is_none() {
        bail!("--root-disk-read-only requires --root-disk");
    }
    if machine_requested && arguments.disk.is_some() {
        bail!("--disk controls Microsandbox root size and cannot be used with QEMU machine boot");
    }
    let machine = if machine_requested {
        let disk = arguments
            .root_disk
            .as_deref()
            .map(|path| {
                let path = canonical_input("root disk", path)?;
                let format = arguments
                    .disk_format
                    .map(DiskImageFormat::from)
                    .unwrap_or_else(|| {
                        if path
                            .extension()
                            .is_some_and(|extension| extension.eq_ignore_ascii_case("qcow2"))
                        {
                            DiskImageFormat::Qcow2
                        } else {
                            DiskImageFormat::Raw
                        }
                    });
                Ok::<DiskImageSpec, anyhow::Error>(DiskImageSpec {
                    path,
                    format,
                    read_only: arguments.root_disk_read_only,
                })
            })
            .transpose()?;
        Some(MachineBootSpec {
            architecture: arguments
                .arch
                .clone()
                .unwrap_or_else(|| std::env::consts::ARCH.into()),
            machine: arguments.machine.clone(),
            cpu: arguments.cpu.clone(),
            accelerator: arguments.accelerator.clone(),
            disk,
            kernel: arguments
                .kernel
                .as_deref()
                .map(|path| canonical_input("kernel", path))
                .transpose()?,
            initrd: arguments
                .initrd
                .as_deref()
                .map(|path| canonical_input("initrd", path))
                .transpose()?,
            dtb: arguments
                .dtb
                .as_deref()
                .map(|path| canonical_input("DTB", path))
                .transpose()?,
            firmware: arguments
                .firmware
                .as_deref()
                .map(|path| canonical_input("firmware", path))
                .transpose()?,
            kernel_append: arguments.kernel_append.clone(),
            debug: arguments.gdb.map(|gdb_port| MachineDebugSpec {
                gdb_port,
                pause_at_boot: arguments.pause_at_boot,
            }),
        })
    } else {
        None
    };
    let android_artifacts = arguments
        .android_artifacts
        .as_deref()
        .map(|path| canonical_directory("Android artifacts", path))
        .transpose()?;
    let project_mode = match arguments.project_mode.unwrap_or(if machine_requested {
        ProjectModeArg::None
    } else {
        ProjectModeArg::Copy
    }) {
        ProjectModeArg::None => ProjectMode::None,
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
    let network = arguments
        .network
        .map(|network| match network {
            NetworkArg::Off => NetworkMode::Off,
            NetworkArg::Public => NetworkMode::Public,
            NetworkArg::Dependencies => NetworkMode::Dependencies,
            NetworkArg::Rules => NetworkMode::Rules,
            NetworkArg::All => NetworkMode::All,
        })
        .or(
            if machine_requested
                || backend
                    .as_ref()
                    .is_some_and(|backend| backend.as_str() == BackendId::CUTTLEFISH)
            {
                Some(NetworkMode::Off)
            } else {
                None
            },
        );
    Ok(SandboxOptions {
        backend,
        machine,
        android_artifacts,
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
        network,
        network_rules,
        project_mode,
        timeout: arguments.timeout,
        ttl: arguments.ttl,
        env: arguments.env_vars,
        ports: arguments.publish,
    })
}

pub(super) fn exec_request(
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

fn canonical_input(label: &str, path: &Path) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .with_context(|| format!("cannot resolve {label} {}", path.display()))?;
    if !path.is_file() {
        bail!("{label} {} is not a regular file", path.display());
    }
    Ok(path)
}

fn canonical_directory(label: &str, path: &Path) -> Result<PathBuf> {
    let path = path
        .canonicalize()
        .with_context(|| format!("cannot resolve {label} {}", path.display()))?;
    if !path.is_dir() {
        bail!("{label} {} is not a directory", path.display());
    }
    Ok(path)
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

impl From<DiskFormatArg> for DiskImageFormat {
    fn from(value: DiskFormatArg) -> Self {
        match value {
            DiskFormatArg::Raw => Self::Raw,
            DiskFormatArg::Qcow2 => Self::Qcow2,
        }
    }
}
