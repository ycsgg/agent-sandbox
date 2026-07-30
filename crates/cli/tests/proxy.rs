use std::{fs, process::Command};

use tempfile::tempdir;

#[test]
fn file_proxy_configuration_survives_one_time_reexec() {
    let directory = tempdir().unwrap();
    let config = directory.path().join("config.toml");
    fs::write(
        &config,
        r#"
[proxy]
inherit_env = false
http = "http://secret:token@127.0.0.1:7890"
https = "http://secret:token@127.0.0.1:7890"
"#,
    )
    .unwrap();

    let output = Command::new(env!("CARGO_BIN_EXE_asbx"))
        .args(["--config", config.to_str().unwrap(), "doctor", "--json"])
        .env("ASBX_HOME", directory.path().join("state"))
        .env("MSB_HOME", directory.path().join("microsandbox"))
        .env_remove("ASBX_INTERNAL_PROXY_APPLIED")
        .env_remove("HTTP_PROXY")
        .env_remove("http_proxy")
        .env_remove("HTTPS_PROXY")
        .env_remove("https_proxy")
        .env_remove("ALL_PROXY")
        .env_remove("all_proxy")
        .output()
        .unwrap();
    let stdout = String::from_utf8(output.stdout).unwrap();
    let stderr = String::from_utf8(output.stderr).unwrap();

    assert!(stdout.contains("\"name\": \"Proxy / host clients\""));
    assert!(stdout.contains("HTTP=configured, HTTPS=configured"));
    assert!(!stdout.contains("secret"));
    assert!(!stdout.contains("token"));
    assert!(!stderr.contains("secret"));
    assert!(!stderr.contains("token"));
}
