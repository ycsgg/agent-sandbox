use std::{fs, process::Command};

#[test]
fn setup_check_is_non_mutating_and_reports_unconfigured_cuttlefish() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    let home = directory.path().join("home");
    fs::create_dir(&home).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_asbx"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("ASBX_HOME", directory.path().join("state"))
        .env("MSB_HOME", directory.path().join("microsandbox"))
        .args(["--config"])
        .arg(&config)
        .args([
            "setup",
            "--check",
            "--default-backend",
            "cuttlefish",
            "--no-harness",
            "--json",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!config.exists());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["default_backend"], "cuttlefish");
    assert!(
        report["backends"]
            .as_array()
            .unwrap()
            .iter()
            .any(|backend| backend["id"] == "cuttlefish"
                && backend["status"] == "missing"
                && backend["selected"] == true)
    );
    assert!(
        report["blockers"]
            .as_array()
            .is_some_and(|blockers| !blockers.is_empty())
    );
}
