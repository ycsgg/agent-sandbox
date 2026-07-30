//! Durable Android Emulator state used across CLI processes.

use std::{
    fs,
    io::Write,
    path::{Path, PathBuf},
};

use agent_sandbox_runtime::{Result, RuntimeError};
use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub(crate) const STATE_VERSION: u32 = 1;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct EmulatorState {
    pub version: u32,
    pub id: String,
    pub source_avd: String,
    pub private_avd: String,
    pub sdk_root: PathBuf,
    pub emulator: PathBuf,
    pub adb: PathBuf,
    pub pid: u32,
    pub process_started_at: u64,
    pub console_port: u16,
    pub adb_port: u16,
    pub adb_server_port: u16,
    pub serial: String,
    pub created_at: DateTime<Utc>,
    pub default_user: Option<String>,
    pub default_env: Vec<(String, String)>,
    pub active: bool,
}

pub(crate) fn load(path: &Path) -> Result<EmulatorState> {
    let bytes = fs::read(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            RuntimeError::NotFound(
                path.parent()
                    .and_then(Path::file_name)
                    .map(|name| name.to_string_lossy().into_owned())
                    .unwrap_or_else(|| path.display().to_string()),
            )
        } else {
            io_error("read Android Emulator state", path, error)
        }
    })?;
    let state: EmulatorState =
        serde_json::from_slice(&bytes).map_err(|error| RuntimeError::Backend {
            operation: "decode Android Emulator state",
            message: format!("{}: {error}", path.display()),
        })?;
    if state.version != STATE_VERSION {
        return Err(RuntimeError::Backend {
            operation: "decode Android Emulator state",
            message: format!(
                "{} uses unsupported state version {}",
                path.display(),
                state.version
            ),
        });
    }
    Ok(state)
}

pub(crate) fn save(path: &Path, state: &EmulatorState) -> Result<()> {
    let parent = path.parent().ok_or_else(|| RuntimeError::Backend {
        operation: "persist Android Emulator state",
        message: format!("{} has no parent directory", path.display()),
    })?;
    fs::create_dir_all(parent)
        .map_err(|error| io_error("create Android Emulator state directory", parent, error))?;
    let bytes = serde_json::to_vec_pretty(state).map_err(|error| RuntimeError::Backend {
        operation: "encode Android Emulator state",
        message: error.to_string(),
    })?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .map_err(|error| io_error("create temporary Android Emulator state", parent, error))?;
    temporary
        .write_all(&bytes)
        .map_err(|error| io_error("write Android Emulator state", temporary.path(), error))?;
    temporary
        .as_file()
        .sync_all()
        .map_err(|error| io_error("sync Android Emulator state", temporary.path(), error))?;
    temporary
        .persist(path)
        .map_err(|error| io_error("commit Android Emulator state", path, error.error))?;
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
    fn state_round_trips_process_and_avd_identity() {
        let directory = tempdir().unwrap();
        let path = directory.path().join("state.json");
        let mut expected = EmulatorState {
            version: STATE_VERSION,
            id: "sbx_android-emulator_test".into(),
            source_avd: "Pixel_API_36".into(),
            private_avd: "asbx_test".into(),
            sdk_root: directory.path().join("sdk"),
            emulator: directory.path().join("emulator"),
            adb: directory.path().join("adb"),
            pid: 42,
            process_started_at: 7,
            console_port: 5554,
            adb_port: 5555,
            adb_server_port: 7600,
            serial: "emulator-5554".into(),
            created_at: Utc::now(),
            default_user: Some("shell".into()),
            default_env: vec![("CI".into(), "1".into())],
            active: true,
        };
        save(&path, &expected).unwrap();
        let actual = load(&path).unwrap();
        assert_eq!(actual.id, expected.id);
        assert_eq!(actual.source_avd, "Pixel_API_36");
        assert_eq!(actual.console_port, 5554);
        assert_eq!(actual.adb_server_port, 7600);
        assert!(actual.active);

        expected.active = false;
        save(&path, &expected).unwrap();
        assert!(!load(&path).unwrap().active);
    }
}
