//! Microsandbox v0.6.7 runtime adapter.

#![forbid(unsafe_code)]

use std::{
    collections::{BTreeMap, HashMap},
    path::Path,
    sync::Mutex,
    time::Duration,
};

use agent_sandbox_runtime::{
    BackendCapabilities, BackendId, BootSourceKind, CommandRuntime, CreateSpec, ExecEvent,
    ExecRequest, ExecStream, FileTransferRuntime, GuestEntry, ImageInfo, ImageRuntime, NetworkMode,
    NetworkRule, NetworkRuleAction, NetworkRuleTarget, OutputStream, Result, RootSource,
    RuntimeError, RuntimeFeature, SandboxInfo, SandboxRuntime, SecurityMode, SnapshotInfo,
    SnapshotRuntime, TerminalRuntime, WorkspaceSpec,
};
use async_trait::async_trait;
use chrono::{DateTime, Utc};
use ipnet::IpNet;
use microsandbox::{
    ExecEvent as MsbExecEvent, Sandbox, Snapshot,
    sandbox::{FsEntryKind, FsSetAttrs, NetworkPolicy, NetworkProfile, SecurityProfile},
    setup::CheckState,
};
use microsandbox_network::policy::NetworkPolicyBuilder;
use tokio::sync::mpsc;

//--------------------------------------------------------------------------------------------------
// Types
//--------------------------------------------------------------------------------------------------

/// Runtime adapter backed by the Microsandbox Rust SDK.
#[derive(Default)]
pub struct MicrosandboxRuntime {
    attached: Mutex<HashMap<String, Sandbox>>,
}

//--------------------------------------------------------------------------------------------------
// Trait Implementations
//--------------------------------------------------------------------------------------------------

#[async_trait]
impl SandboxRuntime for MicrosandboxRuntime {
    fn backend_id(&self) -> BackendId {
        BackendId::microsandbox()
    }

    fn capabilities(&self) -> BackendCapabilities {
        BackendCapabilities {
            backend: self.backend_id(),
            boot_sources: vec![BootSourceKind::OciImage, BootSourceKind::Snapshot],
            features: vec![
                RuntimeFeature::Exec,
                RuntimeFeature::Attach,
                RuntimeFeature::FileTransfer,
                RuntimeFeature::ReadOnlyMount,
                RuntimeFeature::ReadWriteMount,
                RuntimeFeature::PortForward,
                RuntimeFeature::NetworkRules,
                RuntimeFeature::Snapshots,
                RuntimeFeature::ImageCache,
            ],
            architectures: vec!["x86_64".into(), "aarch64".into()],
            accelerators: platform_accelerators(),
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

    fn snapshot_runtime(&self) -> Option<&dyn SnapshotRuntime> {
        Some(self)
    }

    fn image_runtime(&self) -> Option<&dyn ImageRuntime> {
        Some(self)
    }

    async fn create(&self, spec: &CreateSpec) -> Result<SandboxInfo> {
        if spec.backend != self.backend_id() {
            return Err(RuntimeError::Configuration(format!(
                "Microsandbox received a create request for backend {:?}",
                spec.backend
            )));
        }
        let mut builder = Sandbox::builder(&spec.id)
            .cpus(spec.cpus)
            .memory(spec.memory_mib)
            .security(match spec.security {
                SecurityMode::Default => SecurityProfile::Default,
                SecurityMode::Restricted => SecurityProfile::Restricted,
            })
            .max_duration(spec.max_duration.as_secs())
            .ephemeral(spec.ephemeral)
            .detached(spec.detached)
            .replace();

        builder = match &spec.root {
            RootSource::Image(image) => builder.image(image.as_str()).root_disk(spec.disk_mib),
            RootSource::Snapshot(snapshot) => builder.from_snapshot(snapshot),
            RootSource::Machine(_) => {
                return Err(RuntimeError::Unsupported(
                    "Microsandbox does not accept full-system machine boot specifications".into(),
                ));
            }
            _ => {
                return Err(RuntimeError::Unsupported(
                    "Microsandbox does not accept this root source".into(),
                ));
            }
        };
        builder = match spec.network {
            NetworkMode::Off => builder.disable_network(),
            NetworkMode::Public => builder.network(|network| {
                network.policy(NetworkPolicy::from_profiles([NetworkProfile::Public]))
            }),
            NetworkMode::Dependencies | NetworkMode::Rules => {
                let policy = build_custom_network_policy(&spec.network_rules)?;
                builder.network(|network| network.policy(policy))
            }
            NetworkMode::All => {
                builder.network(|network| network.policy(NetworkPolicy::allow_all()))
            }
        };
        if let WorkspaceSpec::Mount {
            host,
            read_only,
            write_quota_mib,
        } = &spec.workspace
        {
            let host = host.clone();
            let read_only = *read_only;
            let write_quota_mib = *write_quota_mib;
            builder = builder.volume("/workspace", move |mount| {
                let mut mount = mount.bind(host).nodev().nosuid();
                if read_only {
                    mount = mount.readonly();
                } else if let Some(quota_mib) = write_quota_mib {
                    mount = mount.quota(quota_mib);
                }
                mount
            });
        }
        if let Some(user) = &spec.user {
            builder = builder.user(user);
        }
        for (key, value) in &spec.env {
            builder = builder.env(key, value);
        }
        for port in &spec.ports {
            builder = builder.port(port.host_port, port.guest_port);
        }

        let sandbox = builder
            .create()
            .await
            .map_err(|error| backend("create sandbox", error))?;
        let status = sandbox
            .status()
            .await
            .map_err(|error| backend("read sandbox status", error))?;
        if !spec.detached {
            self.attached
                .lock()
                .expect("attached sandbox lock poisoned")
                .insert(spec.id.clone(), sandbox.clone());
        }
        Ok(SandboxInfo {
            id: sandbox.name().into(),
            backend: self.backend_id(),
            status: status_name(status),
            created_at: None,
            metadata: BTreeMap::new(),
        })
    }

    async fn stop(&self, sandbox: &str) -> Result<()> {
        self.stop_impl(sandbox).await
    }

    async fn kill(&self, sandbox: &str) -> Result<()> {
        self.kill_impl(sandbox).await
    }

    async fn remove(&self, sandbox: &str) -> Result<()> {
        self.remove_impl(sandbox).await
    }

    async fn list(&self) -> Result<Vec<SandboxInfo>> {
        self.list_impl().await
    }

    async fn inspect(&self, sandbox: &str) -> Result<SandboxInfo> {
        self.inspect_impl(sandbox).await
    }

    async fn doctor(&self) -> Result<Vec<(String, bool, String)>> {
        self.doctor_impl().await
    }
}

#[async_trait]
impl CommandRuntime for MicrosandboxRuntime {
    async fn exec_stream(&self, sandbox: &str, request: ExecRequest) -> Result<ExecStream> {
        let sandbox = self.connect(sandbox).await?;
        let ExecRequest {
            command,
            args,
            cwd,
            user,
            env,
            timeout,
            tty,
        } = request;
        let handle = sandbox
            .exec_stream_with(command, |mut options| {
                options = options.args(args).tty(tty);
                if let Some(cwd) = cwd {
                    options = options.cwd(cwd);
                }
                if let Some(user) = user {
                    options = options.user(user);
                }
                if let Some(timeout) = timeout {
                    options = options.timeout(timeout);
                }
                options.envs(env)
            })
            .await
            .map_err(|error| backend("start guest command", error))?;
        let (sender, receiver) = mpsc::channel(64);
        tokio::spawn(async move {
            let mut handle = handle;
            let mut deadline = timeout.map(|duration| Box::pin(tokio::time::sleep(duration)));
            let mut dropped_stdout = 0_u64;
            let mut dropped_stderr = 0_u64;
            loop {
                let event = match deadline.as_mut() {
                    Some(deadline) => {
                        tokio::select! {
                            biased;
                            event = handle.recv() => event,
                            () = deadline.as_mut() => {
                                match terminate_timed_out_process(&mut handle, &sandbox).await {
                                    Ok(termination) => {
                                        dropped_stdout = dropped_stdout
                                            .saturating_add(termination.discarded_stdout);
                                        dropped_stderr = dropped_stderr
                                            .saturating_add(termination.discarded_stderr);
                                        if send_final_drop_notices(
                                            &sender,
                                            dropped_stdout,
                                            dropped_stderr,
                                        )
                                        .await
                                        .is_ok()
                                        {
                                            let _ = sender
                                                .send(Ok(ExecEvent::TimedOut {
                                                    after: timeout
                                                        .expect("deadline exists only for a timeout"),
                                                    sandbox_terminated: termination
                                                        .sandbox_terminated,
                                                }))
                                                .await;
                                        }
                                    }
                                    Err(error) => {
                                        let _ = sender.send(Err(error)).await;
                                    }
                                }
                                break;
                            }
                        }
                    }
                    None => handle.recv().await,
                };
                let Some(event) = event else {
                    break;
                };
                match event {
                    MsbExecEvent::Started { pid } => {
                        if sender.send(Ok(ExecEvent::Started { pid })).await.is_err() {
                            break;
                        }
                    }
                    MsbExecEvent::Stdout(data) => {
                        if !try_report_drop(&sender, OutputStream::Stdout, &mut dropped_stdout) {
                            break;
                        }
                        match sender.try_send(Ok(ExecEvent::Stdout(data.clone()))) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                dropped_stdout = dropped_stdout.saturating_add(data.len() as u64);
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    }
                    MsbExecEvent::Stderr(data) => {
                        if !try_report_drop(&sender, OutputStream::Stderr, &mut dropped_stderr) {
                            break;
                        }
                        match sender.try_send(Ok(ExecEvent::Stderr(data.clone()))) {
                            Ok(()) => {}
                            Err(mpsc::error::TrySendError::Full(_)) => {
                                dropped_stderr = dropped_stderr.saturating_add(data.len() as u64);
                            }
                            Err(mpsc::error::TrySendError::Closed(_)) => break,
                        }
                    }
                    MsbExecEvent::Exited { code } => {
                        if send_final_drop_notices(&sender, dropped_stdout, dropped_stderr)
                            .await
                            .is_err()
                        {
                            break;
                        }
                        let _ = sender.send(Ok(ExecEvent::Exited { code })).await;
                        break;
                    }
                    MsbExecEvent::Failed(error) => {
                        if send_final_drop_notices(&sender, dropped_stdout, dropped_stderr)
                            .await
                            .is_err()
                        {
                            break;
                        }
                        let _ = sender
                            .send(Ok(ExecEvent::Failed(format!("{error:?}"))))
                            .await;
                        break;
                    }
                    MsbExecEvent::StdinError(error) => {
                        if sender
                            .send(Err(RuntimeError::Backend {
                                operation: "write guest stdin",
                                message: format!("{error:?}"),
                            }))
                            .await
                            .is_err()
                        {
                            break;
                        }
                    }
                }
            }
        });
        Ok(receiver)
    }
}

#[async_trait]
impl TerminalRuntime for MicrosandboxRuntime {
    async fn attach(&self, sandbox: &str, request: ExecRequest) -> Result<i32> {
        let sandbox = self.connect(sandbox).await?;
        let ExecRequest {
            command,
            args,
            cwd,
            user,
            env,
            ..
        } = request;
        sandbox
            .attach_with(command, |mut options| {
                options = options.args(args);
                if let Some(cwd) = cwd {
                    options = options.cwd(cwd);
                }
                if let Some(user) = user {
                    options = options.user(user);
                }
                for (key, value) in env {
                    options = options.env(key, value);
                }
                options
            })
            .await
            .map_err(|error| backend("attach guest terminal", error))
    }
}

#[async_trait]
impl FileTransferRuntime for MicrosandboxRuntime {
    async fn mkdir(&self, sandbox: &str, guest_path: &str) -> Result<()> {
        self.connect(sandbox)
            .await?
            .fs()
            .mkdir(guest_path)
            .await
            .map_err(|error| backend("create guest directory", error))
    }

    async fn put_file(
        &self,
        sandbox: &str,
        host_path: &Path,
        guest_path: &str,
        mode: u32,
    ) -> Result<()> {
        let sandbox = self.connect(sandbox).await?;
        let filesystem = sandbox.fs();
        filesystem
            .copy_from_host(host_path, guest_path)
            .await
            .map_err(|error| backend("upload project file", error))?;
        filesystem
            .set_stat(
                guest_path,
                true,
                FsSetAttrs {
                    mode: Some(mode),
                    ..Default::default()
                },
            )
            .await
            .map_err(|error| backend("set guest file mode", error))
    }

    async fn symlink(&self, sandbox: &str, target: &str, guest_path: &str) -> Result<()> {
        self.connect(sandbox)
            .await?
            .fs()
            .symlink(target, guest_path)
            .await
            .map_err(|error| backend("create guest symlink", error))
    }

    async fn set_mode(&self, sandbox: &str, guest_path: &str, mode: u32) -> Result<()> {
        self.connect(sandbox)
            .await?
            .fs()
            .set_stat(
                guest_path,
                true,
                FsSetAttrs {
                    mode: Some(mode),
                    ..Default::default()
                },
            )
            .await
            .map_err(|error| backend("set guest path mode", error))
    }

    async fn list_dir(&self, sandbox: &str, guest_path: &str) -> Result<Vec<GuestEntry>> {
        let entries = self
            .connect(sandbox)
            .await?
            .fs()
            .list(guest_path)
            .await
            .map_err(|error| backend("list guest directory", error))?;
        Ok(entries
            .into_iter()
            .map(|entry| GuestEntry {
                path: entry.path,
                directory: entry.kind == FsEntryKind::Directory,
                symlink: entry.kind == FsEntryKind::Symlink,
                size: entry.size,
                mode: entry.mode,
            })
            .collect())
    }

    async fn get_file(&self, sandbox: &str, guest_path: &str, host_path: &Path) -> Result<()> {
        self.connect(sandbox)
            .await?
            .fs()
            .copy_to_host(guest_path, host_path)
            .await
            .map_err(|error| backend("download artifact", error))
    }
}

impl MicrosandboxRuntime {
    async fn stop_impl(&self, sandbox: &str) -> Result<()> {
        let attached = {
            self.attached
                .lock()
                .expect("attached sandbox lock poisoned")
                .get(sandbox)
                .cloned()
        };
        let result = match attached {
            Some(attached) => attached
                .stop()
                .await
                .map_err(|error| backend("stop sandbox", error)),
            None => Sandbox::get(sandbox)
                .await
                .map_err(|error| backend("find sandbox to stop", error))?
                .stop()
                .await
                .map_err(|error| backend("stop sandbox", error)),
        };
        if result.is_ok() {
            self.attached
                .lock()
                .expect("attached sandbox lock poisoned")
                .remove(sandbox);
        }
        result
    }

    async fn kill_impl(&self, sandbox: &str) -> Result<()> {
        let attached = {
            self.attached
                .lock()
                .expect("attached sandbox lock poisoned")
                .get(sandbox)
                .cloned()
        };
        let result = match attached {
            Some(attached) => attached
                .kill()
                .await
                .map_err(|error| backend("kill sandbox", error)),
            None => Sandbox::get(sandbox)
                .await
                .map_err(|error| backend("find sandbox to kill", error))?
                .kill()
                .await
                .map_err(|error| backend("kill sandbox", error)),
        };
        self.attached
            .lock()
            .expect("attached sandbox lock poisoned")
            .remove(sandbox);
        result
    }

    async fn remove_impl(&self, sandbox: &str) -> Result<()> {
        Sandbox::get(sandbox)
            .await
            .map_err(|error| backend("find sandbox to remove", error))?
            .remove()
            .await
            .map_err(|error| backend("remove sandbox", error))
    }

    async fn list_impl(&self) -> Result<Vec<SandboxInfo>> {
        let handles = Sandbox::list()
            .await
            .map_err(|error| backend("list sandboxes", error))?;
        Ok(handles
            .into_iter()
            .map(|handle| SandboxInfo {
                id: handle.name().into(),
                backend: self.backend_id(),
                status: status_name(handle.status_snapshot()),
                created_at: handle.created_at(),
                metadata: BTreeMap::new(),
            })
            .collect())
    }

    async fn inspect_impl(&self, sandbox: &str) -> Result<SandboxInfo> {
        let handle = Sandbox::get(sandbox)
            .await
            .map_err(|error| backend("inspect sandbox", error))?;
        Ok(SandboxInfo {
            id: handle.name().into(),
            backend: self.backend_id(),
            status: status_name(handle.status_snapshot()),
            created_at: handle.created_at(),
            metadata: BTreeMap::new(),
        })
    }

    async fn doctor_impl(&self) -> Result<Vec<(String, bool, String)>> {
        let diagnosis = microsandbox::setup::diagnose();
        let mut checks = Vec::new();
        for section in diagnosis.sections {
            for check in section.checks {
                let passed = !matches!(check.state, CheckState::Fail);
                let label = if section.title == "Runtime" && check.label == "Version" {
                    "SDK version"
                } else {
                    check.label.as_str()
                };
                if section.title == "Runtime" && check.label == "msb" && passed {
                    let (version_passed, version) = installed_msb_version(&check.value).await;
                    checks.push(("Runtime / msb version".into(), version_passed, version));
                }
                checks.push((
                    format!("{} / {}", section.title, label),
                    passed,
                    check.value,
                ));
            }
        }
        for problem in diagnosis.problems {
            checks.push(("Problem".into(), false, problem.headline));
        }
        Ok(checks)
    }
}

async fn installed_msb_version(path: &str) -> (bool, String) {
    let output = match tokio::process::Command::new(path)
        .arg("--version")
        .output()
        .await
    {
        Ok(output) => output,
        Err(error) => return (false, format!("could not run msb: {error}")),
    };
    if !output.status.success() {
        return (
            false,
            format!("msb --version exited with {}", output.status),
        );
    }
    let stdout = match String::from_utf8(output.stdout) {
        Ok(stdout) => stdout,
        Err(error) => return (false, format!("msb --version was not UTF-8: {error}")),
    };
    match stdout.trim().strip_prefix("msb ") {
        Some(version) if !version.is_empty() => (true, format!("v{version}")),
        _ => (
            false,
            format!("unexpected msb --version output: {:?}", stdout.trim()),
        ),
    }
}

#[async_trait]
impl SnapshotRuntime for MicrosandboxRuntime {
    async fn create_snapshot(
        &self,
        name: &str,
        sandbox: &str,
        labels: &BTreeMap<String, String>,
    ) -> Result<SnapshotInfo> {
        let mut builder = Snapshot::builder(name).from_sandbox(sandbox);
        for (key, value) in labels {
            builder = builder.label(key, value);
        }
        let snapshot = builder
            .create()
            .await
            .map_err(|error| backend("create environment snapshot", error))?;
        Ok(snapshot_info(name, &snapshot))
    }

    async fn list_snapshots(&self) -> Result<Vec<SnapshotInfo>> {
        let handles = Snapshot::list()
            .await
            .map_err(|error| backend("list snapshots", error))?;
        let mut snapshots = Vec::with_capacity(handles.len());
        for handle in handles {
            let name = handle.name().unwrap_or(handle.digest()).to_owned();
            let snapshot = handle
                .open()
                .await
                .map_err(|error| backend("open snapshot metadata", error))?;
            snapshots.push(snapshot_info(&name, &snapshot));
        }
        Ok(snapshots)
    }

    async fn inspect_snapshot(&self, name: &str) -> Result<SnapshotInfo> {
        let snapshot = Snapshot::open(name)
            .await
            .map_err(|error| backend("inspect snapshot", error))?;
        Ok(snapshot_info(name, &snapshot))
    }

    async fn remove_snapshot(&self, name: &str) -> Result<()> {
        Snapshot::remove(name, false)
            .await
            .map_err(|error| backend("remove snapshot", error))
    }
}

#[async_trait]
impl ImageRuntime for MicrosandboxRuntime {
    async fn list_images(&self) -> Result<Vec<ImageInfo>> {
        Ok(microsandbox::image::Image::list()
            .await
            .map_err(|error| backend("list cached images", error))?
            .into_iter()
            .map(|image| ImageInfo {
                reference: image.reference().to_owned(),
                manifest_digest: image.manifest_digest().map(str::to_owned),
                size_bytes: image
                    .size_bytes()
                    .and_then(|size| u64::try_from(size).ok())
                    .unwrap_or(0),
                last_used_at: image.last_used_at(),
                created_at: image.created_at(),
            })
            .collect())
    }

    async fn remove_image(&self, reference: &str) -> Result<()> {
        microsandbox::image::Image::remove(reference, false)
            .await
            .map_err(|error| backend("remove cached image", error))
    }
}

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

fn platform_accelerators() -> Vec<String> {
    #[cfg(target_os = "linux")]
    {
        vec!["kvm".into()]
    }
    #[cfg(target_os = "macos")]
    {
        vec!["hvf".into()]
    }
    #[cfg(target_os = "windows")]
    {
        vec!["whpx".into()]
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
    {
        Vec::new()
    }
}

impl MicrosandboxRuntime {
    async fn connect(&self, name: &str) -> Result<Sandbox> {
        let attached = {
            self.attached
                .lock()
                .expect("attached sandbox lock poisoned")
                .get(name)
                .cloned()
        };
        if let Some(sandbox) = attached {
            return Ok(sandbox);
        }
        Sandbox::get(name)
            .await
            .map_err(|error| backend("find sandbox", error))?
            .connect()
            .await
            .map_err(|error| backend("connect sandbox", error))
    }
}

fn try_report_drop(
    sender: &mpsc::Sender<Result<ExecEvent>>,
    stream: OutputStream,
    dropped: &mut u64,
) -> bool {
    if *dropped == 0 {
        return !sender.is_closed();
    }
    match sender.try_send(Ok(ExecEvent::OutputTruncated {
        stream,
        dropped_bytes: *dropped,
    })) {
        Ok(()) => {
            *dropped = 0;
            true
        }
        Err(mpsc::error::TrySendError::Full(_)) => true,
        Err(mpsc::error::TrySendError::Closed(_)) => false,
    }
}

fn build_custom_network_policy(rules: &[NetworkRule]) -> Result<NetworkPolicy> {
    let allowances = protected_allowances(rules);
    let mut builder = NetworkPolicy::builder()
        .default_deny()
        .egress(|rule| rule.tcp().udp().port(53).allow_host())
        .egress(|rule| {
            if !allowances.private {
                rule.deny_private();
            }
            if !allowances.host {
                rule.deny_host();
            }
            if !allowances.metadata {
                rule.deny_meta();
            }
            if !allowances.loopback {
                rule.deny_loopback();
            }
            if !allowances.link_local {
                rule.deny_link_local();
            }
            if !allowances.multicast {
                rule.deny_multicast();
            }
            rule
        })
        .ingress(|rule| rule.allow().any());
    for rule in rules {
        builder = add_network_rule(builder, rule);
    }
    builder.build().map_err(|error| RuntimeError::Backend {
        operation: "build network policy",
        message: error.to_string(),
    })
}

#[derive(Debug, Default)]
struct ProtectedAllowances {
    private: bool,
    host: bool,
    metadata: bool,
    loopback: bool,
    link_local: bool,
    multicast: bool,
}

fn protected_allowances(rules: &[NetworkRule]) -> ProtectedAllowances {
    let mut result = ProtectedAllowances::default();
    for rule in rules {
        if rule.action != NetworkRuleAction::Allow {
            continue;
        }
        match &rule.target {
            NetworkRuleTarget::Private => result.private = true,
            NetworkRuleTarget::Host => result.host = true,
            NetworkRuleTarget::Metadata => {
                result.metadata = true;
                result.link_local = true;
            }
            NetworkRuleTarget::Cidr(value) => {
                let Ok(network) = value.parse::<IpNet>() else {
                    continue;
                };
                result.private |= overlaps_any(
                    network,
                    &[
                        "10.0.0.0/8",
                        "100.64.0.0/10",
                        "172.16.0.0/12",
                        "192.168.0.0/16",
                        "fc00::/7",
                    ],
                );
                result.loopback |= overlaps_any(network, &["127.0.0.0/8", "::1/128"]);
                result.link_local |= overlaps_any(network, &["169.254.0.0/16", "fe80::/10"]);
                result.metadata |=
                    overlaps_any(network, &["169.254.169.254/32", "fd00:ec2::254/128"]);
                result.multicast |= overlaps_any(network, &["224.0.0.0/4", "ff00::/8"]);
            }
            NetworkRuleTarget::Domain(_)
            | NetworkRuleTarget::DomainSuffix(_)
            | NetworkRuleTarget::PublicPort { .. } => {}
        }
    }
    result
}

fn overlaps_any(network: IpNet, protected: &[&str]) -> bool {
    protected.iter().any(|protected| {
        let protected = protected
            .parse::<IpNet>()
            .expect("hard-coded protected network is valid");
        network.contains(&protected.network()) || protected.contains(&network.network())
    })
}

fn add_network_rule(builder: NetworkPolicyBuilder, rule: &NetworkRule) -> NetworkPolicyBuilder {
    builder.egress(|builder| {
        match (&rule.action, &rule.target) {
            (NetworkRuleAction::Allow, NetworkRuleTarget::Domain(value)) => {
                builder.allow().domain(value);
            }
            (NetworkRuleAction::Deny, NetworkRuleTarget::Domain(value)) => {
                builder.deny().domain(value);
            }
            (NetworkRuleAction::Allow, NetworkRuleTarget::DomainSuffix(value)) => {
                builder.allow().domain_suffix(value);
            }
            (NetworkRuleAction::Deny, NetworkRuleTarget::DomainSuffix(value)) => {
                builder.deny().domain_suffix(value);
            }
            (NetworkRuleAction::Allow, NetworkRuleTarget::Cidr(value)) => {
                builder.allow().cidr(value);
            }
            (NetworkRuleAction::Deny, NetworkRuleTarget::Cidr(value)) => {
                builder.deny().cidr(value);
            }
            (action, NetworkRuleTarget::PublicPort { start, end }) => {
                builder.tcp().udp().port_range(*start, *end);
                match action {
                    NetworkRuleAction::Allow => {
                        builder.allow_public();
                    }
                    NetworkRuleAction::Deny => {
                        builder.deny_public();
                    }
                }
            }
            (NetworkRuleAction::Allow, NetworkRuleTarget::Private) => {
                builder.allow_private();
            }
            (NetworkRuleAction::Deny, NetworkRuleTarget::Private) => {
                builder.deny_private();
            }
            (NetworkRuleAction::Allow, NetworkRuleTarget::Host) => {
                builder.allow_host();
            }
            (NetworkRuleAction::Deny, NetworkRuleTarget::Host) => {
                builder.deny_host();
            }
            (NetworkRuleAction::Allow, NetworkRuleTarget::Metadata) => {
                builder.allow_meta();
            }
            (NetworkRuleAction::Deny, NetworkRuleTarget::Metadata) => {
                builder.deny_meta();
            }
        }
        builder
    })
}

fn snapshot_info(name: &str, snapshot: &Snapshot) -> SnapshotInfo {
    let manifest = snapshot.manifest();
    SnapshotInfo {
        name: name.to_owned(),
        digest: snapshot.digest().to_owned(),
        image: manifest.image.reference.clone(),
        image_manifest_digest: manifest.image.manifest_digest.clone(),
        size_bytes: snapshot.size_bytes().unwrap_or(0),
        created_at: manifest.created_at.parse::<DateTime<Utc>>().ok(),
        labels: manifest.labels.clone(),
    }
}

#[derive(Debug, Default)]
struct TimeoutTermination {
    discarded_stdout: u64,
    discarded_stderr: u64,
    sandbox_terminated: bool,
}

async fn terminate_timed_out_process(
    handle: &mut microsandbox::ExecHandle,
    sandbox: &Sandbox,
) -> Result<TimeoutTermination> {
    let process_kill_error = handle.kill().await.err();
    let mut result = TimeoutTermination::default();
    let exited = tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(event) = handle.recv().await {
            match event {
                MsbExecEvent::Stdout(data) => {
                    result.discarded_stdout =
                        result.discarded_stdout.saturating_add(data.len() as u64);
                }
                MsbExecEvent::Stderr(data) => {
                    result.discarded_stderr =
                        result.discarded_stderr.saturating_add(data.len() as u64);
                }
                MsbExecEvent::Exited { .. } | MsbExecEvent::Failed(_) => return true,
                MsbExecEvent::Started { .. } | MsbExecEvent::StdinError(_) => {}
            }
        }
        false
    })
    .await
    .unwrap_or(false);

    if exited {
        return Ok(result);
    }

    sandbox
        .kill()
        .await
        .map_err(|sandbox_error| RuntimeError::Backend {
            operation: "enforce guest command timeout",
            message: match process_kill_error {
                Some(process_error) => format!(
                    "process kill failed ({process_error}); sandbox kill failed ({sandbox_error})"
                ),
                None => format!(
                    "guest process did not exit after SIGKILL; sandbox kill failed ({sandbox_error})"
                ),
            },
        })?;
    result.sandbox_terminated = true;
    Ok(result)
}

async fn send_final_drop_notices(
    sender: &mpsc::Sender<Result<ExecEvent>>,
    stdout: u64,
    stderr: u64,
) -> std::result::Result<(), ()> {
    for (stream, dropped_bytes) in [
        (OutputStream::Stdout, stdout),
        (OutputStream::Stderr, stderr),
    ] {
        if dropped_bytes > 0
            && sender
                .send(Ok(ExecEvent::OutputTruncated {
                    stream,
                    dropped_bytes,
                }))
                .await
                .is_err()
        {
            return Err(());
        }
    }
    Ok(())
}

fn backend(operation: &'static str, error: microsandbox::MicrosandboxError) -> RuntimeError {
    match error {
        microsandbox::MicrosandboxError::SandboxNotFound(name)
        | microsandbox::MicrosandboxError::SnapshotNotFound(name)
        | microsandbox::MicrosandboxError::ImageNotFound(name) => RuntimeError::NotFound(name),
        error => RuntimeError::Backend {
            operation,
            message: error.to_string(),
        },
    }
}

fn status_name(status: microsandbox::sandbox::SandboxStatus) -> String {
    format!("{status:?}").to_ascii_lowercase()
}

//--------------------------------------------------------------------------------------------------
// Tests
//--------------------------------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn truncation_notice_waits_for_bounded_channel_capacity() {
        let (sender, mut receiver) = mpsc::channel(1);
        sender
            .send(Ok(ExecEvent::Started { pid: 1 }))
            .await
            .unwrap();
        let mut dropped = 4096;
        assert!(try_report_drop(&sender, OutputStream::Stdout, &mut dropped));
        assert_eq!(dropped, 4096);

        receiver.recv().await.unwrap().unwrap();
        assert!(try_report_drop(&sender, OutputStream::Stdout, &mut dropped));
        assert_eq!(dropped, 0);
        assert!(matches!(
            receiver.recv().await.unwrap().unwrap(),
            ExecEvent::OutputTruncated {
                stream: OutputStream::Stdout,
                dropped_bytes: 4096,
            }
        ));
    }

    #[test]
    fn domain_rules_do_not_relax_protected_address_groups() {
        let allowances = protected_allowances(&[NetworkRule {
            action: NetworkRuleAction::Allow,
            target: NetworkRuleTarget::DomainSuffix("example.com".into()),
        }]);
        assert!(!allowances.private);
        assert!(!allowances.host);
        assert!(!allowances.metadata);
        assert!(!allowances.loopback);
        assert!(!allowances.link_local);
        build_custom_network_policy(&[NetworkRule {
            action: NetworkRuleAction::Allow,
            target: NetworkRuleTarget::Domain("example.com".into()),
        }])
        .unwrap();
    }

    #[test]
    fn approved_protected_cidr_relaxes_only_overlapping_groups() {
        let allowances = protected_allowances(&[NetworkRule {
            action: NetworkRuleAction::Allow,
            target: NetworkRuleTarget::Cidr("10.20.0.0/16".into()),
        }]);
        assert!(allowances.private);
        assert!(!allowances.host);
        assert!(!allowances.metadata);
        assert!(!allowances.loopback);
        assert!(!allowances.link_local);
    }
}
