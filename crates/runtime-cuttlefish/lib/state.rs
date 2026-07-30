//! Durable Cuttlefish instance state used across CLI processes.

use std::{
    fs,
    path::{Path, PathBuf},
};

use agent_sandbox_runtime::{Result, RuntimeError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub(crate) const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct DeviceState {
    pub version: u32,
    pub id: String,
    pub artifacts: PathBuf,
    pub instance_num: u16,
    pub serial: String,
    pub adb_server_port: u16,
    pub default_user: Option<String>,
    pub default_env: Vec<(String, String)>,
    pub created_at: DateTime<Utc>,
    pub active: bool,
}

pub(crate) fn load(path: &Path) -> Result<DeviceState> {
    let bytes = fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            RuntimeError::NotFound(
                path.parent()
                    .and_then(Path::file_name)
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string()),
            )
        } else {
            io_error("read Cuttlefish state", path, error)
        }
    })?;
    let state: DeviceState =
        serde_json::from_slice(&bytes).map_err(|error| RuntimeError::Backend {
            operation: "decode Cuttlefish state",
            message: format!("{}: {error}", path.display()),
        })?;
    if state.version != STATE_VERSION {
        return Err(RuntimeError::Backend {
            operation: "decode Cuttlefish state",
            message: format!(
                "{} uses unsupported state version {}",
                path.display(),
                state.version
            ),
        });
    }
    Ok(state)
}

pub(crate) fn save(path: &Path, state: &DeviceState) -> Result<()> {
    let parent = path.parent().ok_or_else(|| RuntimeError::Backend {
        operation: "persist Cuttlefish state",
        message: format!("{} has no parent directory", path.display()),
    })?;
    fs::create_dir_all(parent)
        .map_err(|error| io_error("create Cuttlefish state directory", parent, error))?;
    let temporary = parent.join(format!(".state-{}.tmp", std::process::id()));
    let bytes = serde_json::to_vec_pretty(state).map_err(|error| RuntimeError::Backend {
        operation: "encode Cuttlefish state",
        message: error.to_string(),
    })?;
    fs::write(&temporary, bytes)
        .map_err(|error| io_error("write Cuttlefish state", &temporary, error))?;
    fs::rename(&temporary, path)
        .map_err(|error| io_error("commit Cuttlefish state", path, error))?;
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
    fn state_round_trips_android_identity() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.json");
        let expected = DeviceState {
            version: STATE_VERSION,
            id: "sbx_cuttlefish_test".into(),
            artifacts: directory.path().join("artifacts"),
            instance_num: 7,
            serial: "127.0.0.1:6526".into(),
            adb_server_port: 7506,
            default_user: Some("shell".into()),
            default_env: vec![("CI".into(), "1".into())],
            created_at: Utc::now(),
            active: true,
        };
        save(&path, &expected).unwrap();
        let actual = load(&path).unwrap();
        assert_eq!(actual.id, expected.id);
        assert_eq!(actual.instance_num, 7);
        assert_eq!(actual.serial, "127.0.0.1:6526");
        assert_eq!(actual.adb_server_port, 7506);
        assert!(actual.active);
    }
}
