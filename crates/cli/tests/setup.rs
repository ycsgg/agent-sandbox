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

#[test]
fn setup_check_human_output_is_grouped_and_log_safe() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("config.toml");
    let home = directory.path().join("home");
    fs::create_dir(&home).unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_asbx"))
        .env("HOME", &home)
        .env("USERPROFILE", &home)
        .env("ASBX_HOME", directory.path().join("state"))
        .env("MSB_HOME", directory.path().join("microsandbox"))
        .env("NO_COLOR", "1")
        .args(["--config"])
        .arg(&config)
        .args([
            "setup",
            "--check",
            "--default-backend",
            "cuttlefish",
            "--no-harness",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!config.exists());
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.contains("Agent Sandbox setup"));
    assert!(report.contains("Backends"));
    assert!(report.contains("Cuttlefish"));
    assert!(report.contains("selected"));
    assert!(report.contains("Agent integrations"));
    assert!(report.contains("Blockers"));
    assert!(!report.contains("\u{1b}["));
}

#[test]
fn setup_dry_run_never_prompts_or_mutates() {
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
            "--dry-run",
            "--default-backend",
            "cuttlefish",
            "--no-harness",
        ])
        .output()
        .unwrap();

    assert!(!output.status.success());
    assert!(!config.exists());
    let report = String::from_utf8(output.stdout).unwrap();
    assert!(report.contains("Plan"));
    assert!(report.contains("Dry run complete. No changes applied."));
    let errors = String::from_utf8(output.stderr).unwrap();
    assert!(!errors.contains("needs confirmation"));
}
