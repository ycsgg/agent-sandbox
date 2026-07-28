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
