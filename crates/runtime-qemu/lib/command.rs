//! Deterministic QEMU command-line construction.

use std::path::{Path, PathBuf};

use agent_sandbox_runtime::{
    CreateSpec, DiskImageFormat, MachineBootSpec, NetworkMode, Result, RootSource, RuntimeError,
};

use crate::QemuRuntimeConfig;

#[derive(Debug, Clone)]
pub(crate) struct LaunchPlan {
    pub binary: PathBuf,
    pub arguments: Vec<String>,
    pub architecture: String,
    pub accelerator: String,
    pub ssh_port: Option<u16>,
    pub gdb_port: Option<u16>,
}

pub(crate) fn build(
    config: &QemuRuntimeConfig,
    spec: &CreateSpec,
    qmp_port: u16,
    ssh_port: Option<u16>,
    gdb_port: Option<u16>,
    serial_log: &Path,
) -> Result<LaunchPlan> {
    let RootSource::Machine(machine) = &spec.root else {
        return Err(RuntimeError::Unsupported(
            "QEMU requires a machine boot source (--root-disk and/or --kernel)".into(),
        ));
    };
    validate_machine(machine)?;
    validate_spec(spec, ssh_port)?;

    let architecture = normalize_architecture(&machine.architecture)?;
    let binary = resolve_binary(config, &architecture)?;
    let accelerator = resolve_accelerator(
        machine.accelerator.as_deref().unwrap_or("auto"),
        &architecture,
    )?;
    let machine_type = machine
        .machine
        .clone()
        .unwrap_or_else(|| default_machine(&architecture).into());
    validate_qemu_token("machine", &machine_type)?;
    let cpu = machine
        .cpu
        .clone()
        .unwrap_or_else(|| if accelerator == "tcg" { "max" } else { "host" }.into());
    validate_qemu_token("CPU", &cpu)?;

    let mut arguments = vec![
        "-name".into(),
        spec.id.clone(),
        "-machine".into(),
        format!("{machine_type},accel={accelerator}"),
        "-cpu".into(),
        cpu,
        "-smp".into(),
        spec.cpus.to_string(),
        "-m".into(),
        spec.memory_mib.to_string(),
        "-display".into(),
        "none".into(),
        "-monitor".into(),
        "none".into(),
        "-no-reboot".into(),
        "-qmp".into(),
        format!("tcp:127.0.0.1:{qmp_port},server=on,wait=off"),
        "-serial".into(),
        format!("file:{}", serial_log.display()),
    ];

    if let Some(firmware) = &machine.firmware {
        add_path_option(&mut arguments, "-bios", firmware);
    }
    if let Some(kernel) = &machine.kernel {
        add_path_option(&mut arguments, "-kernel", kernel);
    }
    if let Some(initrd) = &machine.initrd {
        add_path_option(&mut arguments, "-initrd", initrd);
    }
    if let Some(dtb) = &machine.dtb {
        add_path_option(&mut arguments, "-dtb", dtb);
    }
    if !machine.kernel_append.is_empty() {
        arguments.push("-append".into());
        arguments.push(machine.kernel_append.join(" "));
    }
    if let Some(port) = gdb_port {
        arguments.extend(["-gdb".into(), format!("tcp:127.0.0.1:{port}")]);
        if machine.debug.is_some_and(|debug| debug.pause_at_boot) {
            arguments.push("-S".into());
        }
    }
    if let Some(disk) = &machine.disk {
        let format = match disk.format {
            DiskImageFormat::Raw => "raw",
            DiskImageFormat::Qcow2 => "qcow2",
        };
        arguments.extend([
            "-drive".into(),
            format!(
                "file={},if=none,id=root,format={format},readonly={}",
                disk.path.display(),
                if disk.read_only { "on" } else { "off" }
            ),
            "-device".into(),
            "virtio-blk-pci,drive=root".into(),
        ]);
        if !disk.read_only {
            // QEMU's temporary snapshot mode preserves the caller-owned base
            // image while keeping the guest-visible disk writable.
            arguments.push("-snapshot".into());
        }
    }

    add_network_arguments(&mut arguments, spec, ssh_port);
    Ok(LaunchPlan {
        binary,
        arguments,
        architecture,
        accelerator,
        ssh_port,
        gdb_port,
    })
}

fn validate_machine(machine: &MachineBootSpec) -> Result<()> {
    if machine.disk.is_none() && machine.kernel.is_none() {
        return Err(RuntimeError::Configuration(
            "QEMU machine boot requires a disk image or direct-boot kernel".into(),
        ));
    }
    for (label, path) in [
        ("root disk", machine.disk.as_ref().map(|disk| &disk.path)),
        ("kernel", machine.kernel.as_ref()),
        ("initrd", machine.initrd.as_ref()),
        ("DTB", machine.dtb.as_ref()),
        ("firmware", machine.firmware.as_ref()),
    ] {
        if let Some(path) = path
            && !path.is_file()
        {
            return Err(RuntimeError::Configuration(format!(
                "{label} {} is not a regular file",
                path.display()
            )));
        }
    }
    if let Some(disk) = &machine.disk
        && disk.path.to_string_lossy().contains(',')
    {
        return Err(RuntimeError::Configuration(format!(
            "root disk path {} contains a comma, which QEMU drive syntax cannot represent safely",
            disk.path.display()
        )));
    }
    if machine.kernel.is_none()
        && (machine.initrd.is_some() || machine.dtb.is_some() || !machine.kernel_append.is_empty())
    {
        return Err(RuntimeError::Configuration(
            "initrd, DTB, and kernel arguments require --kernel".into(),
        ));
    }
    Ok(())
}

fn validate_spec(spec: &CreateSpec, ssh_port: Option<u16>) -> Result<()> {
    if !matches!(
        spec.workspace,
        agent_sandbox_runtime::WorkspaceSpec::None | agent_sandbox_runtime::WorkspaceSpec::Copy
    ) {
        return Err(RuntimeError::Unsupported(
            "QEMU host workspace mounts are not implemented; use copy or none".into(),
        ));
    }
    if matches!(
        spec.network,
        NetworkMode::Public | NetworkMode::Dependencies | NetworkMode::Rules
    ) {
        return Err(RuntimeError::Unsupported(
            "QEMU currently supports network modes off and all; filtered egress needs a platform network helper"
                .into(),
        ));
    }
    if !spec.network_rules.is_empty() {
        return Err(RuntimeError::Unsupported(
            "QEMU custom network rules are not implemented".into(),
        ));
    }
    if ssh_port.is_none() && matches!(spec.workspace, agent_sandbox_runtime::WorkspaceSpec::Copy) {
        return Err(RuntimeError::Configuration(
            "QEMU copy mode requires SSH transport; configure qemu.ssh_user or use --project-mode none"
                .into(),
        ));
    }
    Ok(())
}

fn add_network_arguments(arguments: &mut Vec<String>, spec: &CreateSpec, ssh_port: Option<u16>) {
    let needs_network =
        ssh_port.is_some() || !spec.ports.is_empty() || spec.network == NetworkMode::All;
    if !needs_network {
        arguments.extend(["-nic".into(), "none".into()]);
        return;
    }

    let mut netdev = format!(
        "user,id=net0,restrict={}",
        if spec.network == NetworkMode::All {
            "off"
        } else {
            "on"
        }
    );
    if let Some(port) = ssh_port {
        netdev.push_str(&format!(",hostfwd=tcp:127.0.0.1:{port}-:22"));
    }
    for port in &spec.ports {
        netdev.push_str(&format!(
            ",hostfwd=tcp:127.0.0.1:{}-:{}",
            port.host_port, port.guest_port
        ));
    }
    arguments.extend([
        "-netdev".into(),
        netdev,
        "-device".into(),
        "virtio-net-pci,netdev=net0".into(),
    ]);
}

fn add_path_option(arguments: &mut Vec<String>, option: &str, path: &Path) {
    arguments.push(option.into());
    arguments.push(path.display().to_string());
}

fn resolve_binary(config: &QemuRuntimeConfig, architecture: &str) -> Result<PathBuf> {
    let candidate = config
        .binary
        .clone()
        .unwrap_or_else(|| PathBuf::from(format!("qemu-system-{architecture}")));
    which::which(&candidate).map_err(|error| {
        RuntimeError::Configuration(format!(
            "cannot find QEMU binary {}: {error}",
            candidate.display()
        ))
    })
}

pub(crate) fn normalize_architecture(value: &str) -> Result<String> {
    match value.to_ascii_lowercase().as_str() {
        "x86_64" | "x64" | "amd64" => Ok("x86_64".into()),
        "aarch64" | "arm64" => Ok("aarch64".into()),
        "riscv64" => Ok("riscv64".into()),
        other => Err(RuntimeError::Configuration(format!(
            "unsupported QEMU architecture {other:?}; expected x86_64, aarch64, or riscv64"
        ))),
    }
}

pub(crate) fn resolve_accelerator(requested: &str, guest_architecture: &str) -> Result<String> {
    let host = normalize_architecture(std::env::consts::ARCH)
        .unwrap_or_else(|_| std::env::consts::ARCH.into());
    if requested != "auto" {
        if !matches!(requested, "kvm" | "hvf" | "whpx" | "tcg") {
            return Err(RuntimeError::Configuration(format!(
                "unsupported QEMU accelerator {requested:?}"
            )));
        }
        if requested != "tcg" && host != guest_architecture {
            return Err(RuntimeError::Configuration(format!(
                "QEMU accelerator {requested} cannot run {guest_architecture} on a {host} host; use tcg"
            )));
        }
        let platform = platform_accelerator();
        if requested != "tcg" && requested != platform {
            return Err(RuntimeError::Configuration(format!(
                "QEMU accelerator {requested} is not available on {}; use {platform} or tcg",
                std::env::consts::OS
            )));
        }
        #[cfg(target_os = "linux")]
        if requested == "kvm" && !kvm_available() {
            return Err(RuntimeError::Configuration(
                "KVM was requested but /dev/kvm is unavailable or inaccessible; use tcg".into(),
            ));
        }
        return Ok(requested.into());
    }

    if host != guest_architecture {
        return Ok("tcg".into());
    }
    #[cfg(target_os = "linux")]
    {
        return Ok(if kvm_available() { "kvm" } else { "tcg" }.into());
    }
    #[cfg(target_os = "macos")]
    {
        return Ok("hvf".into());
    }
    #[cfg(target_os = "windows")]
    {
        return Ok("whpx".into());
    }
    #[allow(unreachable_code)]
    Ok("tcg".into())
}

#[cfg(target_os = "linux")]
fn kvm_available() -> bool {
    std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open("/dev/kvm")
        .is_ok()
}

fn platform_accelerator() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "kvm"
    }
    #[cfg(target_os = "macos")]
    {
        "hvf"
    }
    #[cfg(target_os = "windows")]
    {
        "whpx"
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        "tcg"
    }
}

fn default_machine(architecture: &str) -> &'static str {
    match architecture {
        "x86_64" => "q35",
        "aarch64" | "riscv64" => "virt",
        _ => "virt",
    }
}

fn validate_qemu_token(label: &str, value: &str) -> Result<()> {
    if value.is_empty()
        || value
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || "._-".contains(character)))
    {
        return Err(RuntimeError::Configuration(format!(
            "{label} value {value:?} contains unsupported characters"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use agent_sandbox_runtime::{
        BackendId, DiskImageSpec, MachineBootSpec, MachineDebugSpec, SecurityMode, WorkspaceSpec,
    };
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn builds_direct_kernel_command_with_safe_defaults() {
        let directory = tempdir().unwrap();
        let binary = fake_executable(directory.path(), "qemu-system-aarch64");
        let kernel = directory.path().join("Image");
        std::fs::write(&kernel, []).unwrap();
        let config = QemuRuntimeConfig {
            home: directory.path().join("home"),
            binary: Some(binary),
            ssh_binary: None,
            ssh_user: None,
            ssh_key: None,
            boot_timeout: Duration::from_secs(1),
            shutdown_timeout: Duration::from_secs(1),
        };
        let spec = CreateSpec {
            id: "sbx_qemu_test".into(),
            backend: BackendId::qemu(),
            root: RootSource::Machine(Box::new(MachineBootSpec {
                architecture: "arm64".into(),
                machine: None,
                cpu: None,
                accelerator: Some("tcg".into()),
                disk: None,
                kernel: Some(kernel),
                initrd: None,
                dtb: None,
                firmware: None,
                kernel_append: vec!["console=ttyAMA0".into()],
                debug: Some(MachineDebugSpec {
                    gdb_port: 0,
                    pause_at_boot: true,
                }),
            })),
            cpus: 2,
            memory_mib: 1024,
            disk_mib: 0,
            user: None,
            security: SecurityMode::Default,
            network: NetworkMode::Off,
            network_rules: vec![],
            workspace: WorkspaceSpec::None,
            env: vec![],
            ports: vec![],
            max_duration: Duration::from_secs(60),
            ephemeral: true,
            detached: true,
        };

        let plan = build(
            &config,
            &spec,
            4444,
            None,
            Some(5555),
            directory.path().join("serial.log").as_path(),
        )
        .unwrap();
        assert_eq!(plan.architecture, "aarch64");
        assert_eq!(plan.accelerator, "tcg");
        assert!(
            plan.arguments
                .windows(2)
                .any(|pair| pair == ["-nic", "none"])
        );
        assert!(plan.arguments.contains(&"console=ttyAMA0".into()));
        assert!(
            plan.arguments
                .windows(2)
                .any(|pair| pair == ["-gdb", "tcp:127.0.0.1:5555"])
        );
        assert!(plan.arguments.contains(&"-S".into()));
    }

    #[test]
    fn writable_disk_uses_temporary_snapshot() {
        let directory = tempdir().unwrap();
        let binary = fake_executable(directory.path(), "qemu-system-x86_64");
        let disk = directory.path().join("root.qcow2");
        std::fs::write(&disk, []).unwrap();
        let config = QemuRuntimeConfig {
            home: directory.path().join("home"),
            binary: Some(binary),
            ssh_binary: None,
            ssh_user: None,
            ssh_key: None,
            boot_timeout: Duration::from_secs(1),
            shutdown_timeout: Duration::from_secs(1),
        };
        let mut spec = base_machine_spec(directory.path(), "x86_64");
        spec.root = RootSource::Machine(Box::new(MachineBootSpec {
            architecture: "x86_64".into(),
            machine: None,
            cpu: None,
            accelerator: Some("tcg".into()),
            disk: Some(DiskImageSpec {
                path: disk,
                format: DiskImageFormat::Qcow2,
                read_only: false,
            }),
            kernel: None,
            initrd: None,
            dtb: None,
            firmware: None,
            kernel_append: vec![],
            debug: None,
        }));
        let plan = build(
            &config,
            &spec,
            4444,
            None,
            None,
            directory.path().join("serial.log").as_path(),
        )
        .unwrap();
        assert!(plan.arguments.contains(&"-snapshot".into()));
    }

    fn base_machine_spec(directory: &Path, architecture: &str) -> CreateSpec {
        let kernel = directory.join("kernel");
        std::fs::write(&kernel, []).unwrap();
        CreateSpec {
            id: "sbx_qemu_test".into(),
            backend: BackendId::qemu(),
            root: RootSource::Machine(Box::new(MachineBootSpec {
                architecture: architecture.into(),
                machine: None,
                cpu: None,
                accelerator: Some("tcg".into()),
                disk: None,
                kernel: Some(kernel),
                initrd: None,
                dtb: None,
                firmware: None,
                kernel_append: vec![],
                debug: None,
            })),
            cpus: 1,
            memory_mib: 512,
            disk_mib: 0,
            user: None,
            security: SecurityMode::Default,
            network: NetworkMode::Off,
            network_rules: vec![],
            workspace: WorkspaceSpec::None,
            env: vec![],
            ports: vec![],
            max_duration: Duration::from_secs(60),
            ephemeral: true,
            detached: true,
        }
    }

    fn fake_executable(directory: &Path, name: &str) -> PathBuf {
        let path = directory
            .join(name)
            .with_extension(std::env::consts::EXE_EXTENSION);
        std::fs::write(&path, []).unwrap();
        make_executable(&path);
        path
    }

    #[cfg(unix)]
    fn make_executable(path: &Path) {
        use std::os::unix::fs::PermissionsExt;

        let mut permissions = std::fs::metadata(path).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(path, permissions).unwrap();
    }

    #[cfg(not(unix))]
    fn make_executable(_path: &Path) {}
}
