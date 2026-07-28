//! Microsandbox v0.6.7 runtime adapter.

#![forbid(unsafe_code)]

use std::{collections::HashMap, path::Path, sync::Mutex, time::Duration};

use agent_sandbox_runtime::{
    CreateSpec, ExecEvent, ExecRequest, ExecStream, GuestEntry, NetworkMode, OutputStream, Result,
    RootSource, RuntimeError, SandboxInfo, SandboxRuntime, SecurityMode,
};
use async_trait::async_trait;
use microsandbox::{
    ExecEvent as MsbExecEvent, Sandbox,
    sandbox::{FsEntryKind, FsSetAttrs, NetworkPolicy, NetworkProfile, SecurityProfile},
    setup::CheckState,
};
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
    async fn create(&self, spec: &CreateSpec) -> Result<SandboxInfo> {
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
        };
        builder = match spec.network {
            NetworkMode::Off => builder.disable_network(),
            NetworkMode::Public => builder.network(|network| {
                network.policy(NetworkPolicy::from_profiles([NetworkProfile::Public]))
            }),
            NetworkMode::All => {
                builder.network(|network| network.policy(NetworkPolicy::allow_all()))
            }
        };
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
            status: status_name(status),
            created_at: None,
        })
    }

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

    async fn stop(&self, sandbox: &str) -> Result<()> {
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

    async fn kill(&self, sandbox: &str) -> Result<()> {
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

    async fn remove(&self, sandbox: &str) -> Result<()> {
        Sandbox::get(sandbox)
            .await
            .map_err(|error| backend("find sandbox to remove", error))?
            .remove()
            .await
            .map_err(|error| backend("remove sandbox", error))
    }

    async fn list(&self) -> Result<Vec<SandboxInfo>> {
        let handles = Sandbox::list()
            .await
            .map_err(|error| backend("list sandboxes", error))?;
        Ok(handles
            .into_iter()
            .map(|handle| SandboxInfo {
                id: handle.name().into(),
                status: status_name(handle.status_snapshot()),
                created_at: handle.created_at(),
            })
            .collect())
    }

    async fn inspect(&self, sandbox: &str) -> Result<SandboxInfo> {
        let handle = Sandbox::get(sandbox)
            .await
            .map_err(|error| backend("inspect sandbox", error))?;
        Ok(SandboxInfo {
            id: handle.name().into(),
            status: status_name(handle.status_snapshot()),
            created_at: handle.created_at(),
        })
    }

    async fn doctor(&self) -> Result<Vec<(String, bool, String)>> {
        let diagnosis = microsandbox::setup::diagnose();
        let mut checks = Vec::new();
        for section in diagnosis.sections {
            for check in section.checks {
                checks.push((
                    format!("{} / {}", section.title, check.label),
                    !matches!(check.state, CheckState::Fail),
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

//--------------------------------------------------------------------------------------------------
// Functions
//--------------------------------------------------------------------------------------------------

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
        microsandbox::MicrosandboxError::SandboxNotFound(name) => RuntimeError::NotFound(name),
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
}
