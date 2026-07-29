//! Durable per-machine state used to reconnect across CLI processes.

use std::{
    fs,
    path::{Path, PathBuf},
};

use agent_sandbox_runtime::{Result, RuntimeError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub(crate) const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct MachineState {
    pub version: u32,
    pub id: String,
    pub pid: u32,
    #[serde(default)]
    pub process_started_at: u64,
    pub created_at: DateTime<Utc>,
    pub architecture: String,
    pub accelerator: String,
    pub qmp_port: u16,
    pub ssh_port: Option<u16>,
    #[serde(default)]
    pub gdb_port: Option<u16>,
    #[serde(default)]
    pub debug_paused_at_boot: bool,
    #[serde(default)]
    pub kaslr_disabled: bool,
    #[serde(default)]
    pub kernel: Option<PathBuf>,
    pub ssh_user: Option<String>,
    pub ssh_key: Option<PathBuf>,
    pub serial_log: PathBuf,
    pub process_log: PathBuf,
}

pub(crate) fn load(path: &Path) -> Result<MachineState> {
    let bytes = fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            RuntimeError::NotFound(
                path.parent()
                    .and_then(Path::file_name)
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string()),
            )
        } else {
            io_error("read QEMU state", path, error)
        }
    })?;
    let state: MachineState =
        serde_json::from_slice(&bytes).map_err(|error| RuntimeError::Backend {
            operation: "decode QEMU state",
            message: format!("{}: {error}", path.display()),
        })?;
    if state.version != STATE_VERSION {
        return Err(RuntimeError::Backend {
            operation: "decode QEMU state",
            message: format!(
                "{} uses unsupported state version {}",
                path.display(),
                state.version
            ),
        });
    }
    Ok(state)
}

pub(crate) fn save(path: &Path, state: &MachineState) -> Result<()> {
    let parent = path.parent().ok_or_else(|| RuntimeError::Backend {
        operation: "persist QEMU state",
        message: format!("{} has no parent directory", path.display()),
    })?;
    fs::create_dir_all(parent)
        .map_err(|error| io_error("create QEMU state directory", parent, error))?;
    let temporary = parent.join(format!(".state-{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec_pretty(state).map_err(|error| RuntimeError::Backend {
        operation: "encode QEMU state",
        message: error.to_string(),
    })?;
    fs::write(&temporary, bytes)
        .map_err(|error| io_error("write QEMU state", &temporary, error))?;
    fs::rename(&temporary, path).map_err(|error| io_error("commit QEMU state", path, error))?;
    Ok(())
}

pub(crate) fn io_error(
    operation: &'static str,
    path: &Path,
    error: std::io::Error,
) -> RuntimeError {
    RuntimeError::Backend {
        operation,
        message: format!("{}: {error}", path.display()),
    }
}

#[cfg(test)]
mod tests {
    use tempfile::tempdir;

    use super::*;

    #[test]
    fn older_v1_state_defaults_new_debug_context() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.json");
        fs::write(
            &path,
            r#"{
                "version": 1,
                "id": "sbx_qemu_legacy",
                "pid": 42,
                "process_started_at": 1,
                "created_at": "2026-01-01T00:00:00Z",
                "architecture": "aarch64",
                "accelerator": "tcg",
                "qmp_port": 1234,
                "ssh_port": null,
                "gdb_port": 1235,
                "ssh_user": null,
                "ssh_key": null,
                "serial_log": "serial.log",
                "process_log": "qemu.log"
            }"#,
        )
        .unwrap();

        let state = load(&path).unwrap();
        assert!(!state.debug_paused_at_boot);
        assert!(!state.kaslr_disabled);
        assert_eq!(state.kernel, None);
    }
}
