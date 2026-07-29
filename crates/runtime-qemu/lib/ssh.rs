//! OpenSSH transport used by QEMU guests that expose an SSH server.

use std::{
    path::{Path, PathBuf},
    process::Stdio,
    sync::atomic::{AtomicU64, Ordering},
    time::Duration,
};

use agent_sandbox_runtime::{Result, RuntimeError};
use tokio::{process::Command, time::Instant};

use crate::state::MachineState;

static DOWNLOAD_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone)]
pub(crate) struct SshTools {
    pub ssh: PathBuf,
    pub connect_timeout: Duration,
}

impl SshTools {
    pub(crate) fn resolve(ssh: Option<&Path>, connect_timeout: Duration) -> Result<Self> {
        Ok(Self {
            ssh: resolve_tool(ssh, "ssh")?,
            connect_timeout,
        })
    }

    pub(crate) async fn wait_ready(&self, state: &MachineState, timeout: Duration) -> Result<()> {
        let deadline = Instant::now() + timeout;
        loop {
            let last_error = match self.run(state, None, "true").await {
                Ok(output) if output.status.success() => return Ok(()),
                Ok(output) => String::from_utf8_lossy(&output.stderr).trim().to_owned(),
                Err(error) => error.to_string(),
            };
            if Instant::now() >= deadline {
                return Err(RuntimeError::Backend {
                    operation: "wait for QEMU guest transport",
                    message: if last_error.is_empty() {
                        "SSH readiness timed out".into()
                    } else {
                        format!("SSH readiness timed out: {last_error}")
                    },
                });
            }
            tokio::time::sleep(Duration::from_millis(250)).await;
        }
    }

    pub(crate) fn command(
        &self,
        state: &MachineState,
        user: Option<&str>,
        remote_command: &str,
        tty: bool,
    ) -> Result<Command> {
        let mut command = Command::new(&self.ssh);
        let mut options = self.ssh_options(state, user)?;
        if tty {
            let target = options
                .pop()
                .expect("SSH options always end with the target");
            options.push("-tt".into());
            options.push(target);
        }
        command.args(options);
        command.arg(remote_command);
        Ok(command)
    }

    pub(crate) async fn run(
        &self,
        state: &MachineState,
        user: Option<&str>,
        remote_command: &str,
    ) -> Result<std::process::Output> {
        self.command(state, user, remote_command, false)?
            .stdin(Stdio::null())
            .output()
            .await
            .map_err(|error| transport_error("run SSH command", error))
    }

    pub(crate) async fn upload(
        &self,
        state: &MachineState,
        host: &Path,
        guest: &str,
    ) -> Result<()> {
        let remote = format!("umask 077; cat > {}", shell_quote(guest));
        let mut command = self.command(state, None, &remote, false)?;
        command
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|error| transport_error("start SSH upload", error))?;
        let mut input = tokio::fs::File::open(host)
            .await
            .map_err(|error| transport_error("open upload source", error))?;
        let mut remote_input = child.stdin.take().expect("piped SSH stdin is available");
        if let Err(error) = tokio::io::copy(&mut input, &mut remote_input).await {
            let _ = child.kill().await;
            return Err(transport_error("stream SSH upload", error));
        }
        drop(remote_input);
        let output = child
            .wait_with_output()
            .await
            .map_err(|error| transport_error("finish SSH upload", error))?;
        ensure_success("upload file over SSH", output)
    }

    pub(crate) async fn download(
        &self,
        state: &MachineState,
        guest: &str,
        host: &Path,
    ) -> Result<()> {
        let remote = format!("cat < {}", shell_quote(guest));
        let mut command = self.command(state, None, &remote, false)?;
        command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .kill_on_drop(true);
        let mut child = command
            .spawn()
            .map_err(|error| transport_error("start SSH download", error))?;
        let mut remote_output = child.stdout.take().expect("piped SSH stdout is available");
        let temporary = download_temporary_path(host);
        let mut output_file = tokio::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&temporary)
            .await
            .map_err(|error| transport_error("create download destination", error))?;
        if let Err(error) = tokio::io::copy(&mut remote_output, &mut output_file).await {
            let _ = child.kill().await;
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(transport_error("stream SSH download", error));
        }
        drop(output_file);
        let output = match child.wait_with_output().await {
            Ok(output) => output,
            Err(error) => {
                let _ = tokio::fs::remove_file(&temporary).await;
                return Err(transport_error("finish SSH download", error));
            }
        };
        if let Err(error) = ensure_success("download file over SSH", output) {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(error);
        }
        if let Err(error) = tokio::fs::hard_link(&temporary, host).await {
            let _ = tokio::fs::remove_file(&temporary).await;
            return Err(transport_error("commit SSH download", error));
        }
        tokio::fs::remove_file(&temporary)
            .await
            .map_err(|error| transport_error("remove SSH download staging file", error))?;
        Ok(())
    }

    fn ssh_options(&self, state: &MachineState, user: Option<&str>) -> Result<Vec<String>> {
        let port = state.ssh_port.ok_or_else(no_transport)?;
        let user = user
            .or(state.ssh_user.as_deref())
            .ok_or_else(no_transport)?;
        validate_user(user)?;
        let mut arguments = common_options(state, self.connect_timeout);
        arguments.extend(["-p".into(), port.to_string()]);
        arguments.push(format!("{user}@127.0.0.1"));
        Ok(arguments)
    }
}

pub(crate) fn remote_command(
    command: &str,
    arguments: &[String],
    cwd: Option<&str>,
    environment: &[(String, String)],
) -> String {
    let mut components = Vec::new();
    if let Some(cwd) = cwd {
        components.push(format!("cd -- {}", shell_quote(cwd)));
    }
    let mut invocation = String::new();
    if !environment.is_empty() {
        invocation.push_str("env");
        for (key, value) in environment {
            invocation.push(' ');
            invocation.push_str(&shell_quote(&format!("{key}={value}")));
        }
        invocation.push(' ');
    }
    invocation.push_str(&shell_quote(command));
    for argument in arguments {
        invocation.push(' ');
        invocation.push_str(&shell_quote(argument));
    }
    components.push(invocation);
    components.join(" && ")
}

pub(crate) fn shell_quote(value: &str) -> String {
    format!("'{}'", value.replace('\'', "'\"'\"'"))
}

fn common_options(state: &MachineState, connect_timeout: Duration) -> Vec<String> {
    let seconds = connect_timeout.as_secs().max(1);
    let mut arguments = vec![
        "-o".into(),
        "BatchMode=yes".into(),
        "-o".into(),
        "StrictHostKeyChecking=no".into(),
        "-o".into(),
        "UserKnownHostsFile=/dev/null".into(),
        "-o".into(),
        "LogLevel=ERROR".into(),
        "-o".into(),
        format!("ConnectTimeout={seconds}"),
    ];
    if let Some(key) = &state.ssh_key {
        arguments.extend(["-i".into(), key.display().to_string()]);
    }
    arguments
}

fn download_temporary_path(destination: &Path) -> PathBuf {
    let parent = destination.parent().unwrap_or_else(|| Path::new("."));
    let name = destination
        .file_name()
        .map(|name| name.to_string_lossy())
        .unwrap_or_default();
    parent.join(format!(
        ".{name}.asbx-{}-{}.part",
        std::process::id(),
        DOWNLOAD_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ))
}

fn resolve_tool(configured: Option<&Path>, fallback: &str) -> Result<PathBuf> {
    let candidate = configured.unwrap_or_else(|| Path::new(fallback));
    which::which(candidate).map_err(|error| {
        RuntimeError::Configuration(format!(
            "cannot find {fallback} executable {}: {error}",
            candidate.display()
        ))
    })
}

fn validate_user(user: &str) -> Result<()> {
    if user.is_empty()
        || user
            .chars()
            .any(|character| !(character.is_ascii_alphanumeric() || "._-".contains(character)))
    {
        return Err(RuntimeError::Configuration(format!(
            "invalid SSH user {user:?}"
        )));
    }
    Ok(())
}

fn no_transport() -> RuntimeError {
    RuntimeError::Unsupported(
        "QEMU guest transport is disabled; configure qemu.ssh_user and a guest SSH service".into(),
    )
}

fn ensure_success(operation: &'static str, output: std::process::Output) -> Result<()> {
    if output.status.success() {
        return Ok(());
    }
    Err(RuntimeError::Backend {
        operation,
        message: String::from_utf8_lossy(&output.stderr).trim().to_owned(),
    })
}

fn transport_error(operation: &'static str, error: impl std::fmt::Display) -> RuntimeError {
    RuntimeError::Backend {
        operation,
        message: error.to_string(),
    }
}

#[cfg(test)]
mod tests {
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    #[cfg(unix)]
    use chrono::Utc;
    #[cfg(unix)]
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn remote_commands_quote_every_untrusted_component() {
        let command = remote_command(
            "printf",
            &["%s".into(), "a'b; touch /tmp/no".into()],
            Some("/workspace/a b"),
            &[("TOKEN".into(), "x y".into())],
        );
        assert_eq!(
            command,
            "cd -- '/workspace/a b' && env 'TOKEN=x y' 'printf' '%s' 'a'\"'\"'b; touch /tmp/no'"
        );
    }

    #[test]
    fn ssh_options_are_well_formed_pairs() {
        let state = MachineState {
            version: crate::state::STATE_VERSION,
            id: "sbx_qemu_test".into(),
            pid: 1,
            process_started_at: 1,
            created_at: chrono::Utc::now(),
            architecture: "aarch64".into(),
            accelerator: "tcg".into(),
            qmp_port: 1,
            ssh_port: Some(22),
            gdb_port: None,
            debug_paused_at_boot: false,
            kaslr_disabled: false,
            kernel: None,
            ssh_user: Some("root".into()),
            ssh_key: Some(PathBuf::from("guest key")),
            serial_log: PathBuf::from("serial.log"),
            process_log: PathBuf::from("qemu.log"),
        };

        assert_eq!(
            common_options(&state, Duration::from_secs(3)),
            [
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=no",
                "-o",
                "UserKnownHostsFile=/dev/null",
                "-o",
                "LogLevel=ERROR",
                "-o",
                "ConnectTimeout=3",
                "-i",
                "guest key",
            ]
        );
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn streams_uploads_and_downloads_without_scp() {
        let directory = tempdir().unwrap();
        let ssh = directory.path().join("fake ssh");
        std::fs::write(
            &ssh,
            "#!/bin/sh\n\
             while [ \"$#\" -gt 0 ]; do\n\
               case \"$1\" in\n\
                 -o|-p|-i) shift 2 ;;\n\
                 *@*) shift; break ;;\n\
                 *) shift ;;\n\
               esac\n\
             done\n\
             exec /bin/sh -c \"$1\"\n",
        )
        .unwrap();
        let mut permissions = std::fs::metadata(&ssh).unwrap().permissions();
        permissions.set_mode(0o755);
        std::fs::set_permissions(&ssh, permissions).unwrap();

        let state = MachineState {
            version: crate::state::STATE_VERSION,
            id: "sbx_qemu_test".into(),
            pid: std::process::id(),
            process_started_at: 1,
            created_at: Utc::now(),
            architecture: "aarch64".into(),
            accelerator: "tcg".into(),
            qmp_port: 1,
            ssh_port: Some(22),
            gdb_port: None,
            debug_paused_at_boot: false,
            kaslr_disabled: false,
            kernel: None,
            ssh_user: Some("root".into()),
            ssh_key: None,
            serial_log: directory.path().join("serial.log"),
            process_log: directory.path().join("qemu.log"),
        };
        let tools = SshTools {
            ssh,
            connect_timeout: Duration::from_secs(1),
        };
        let upload_source = directory.path().join("upload source");
        let guest = directory.path().join("guest file");
        let download = directory.path().join("download result");
        std::fs::write(&upload_source, b"streamed data").unwrap();

        tools
            .upload(&state, &upload_source, guest.to_str().unwrap())
            .await
            .unwrap();
        tools
            .download(&state, guest.to_str().unwrap(), &download)
            .await
            .unwrap();
        assert_eq!(std::fs::read(download).unwrap(), b"streamed data");
    }
}
