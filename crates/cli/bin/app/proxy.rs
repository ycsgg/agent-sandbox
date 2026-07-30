//! Process-level proxy application for clients constructed by dependencies.

use std::{
    env,
    process::{Command, Stdio},
};

use agent_sandbox_policy::{HostConfig, ProxyEnvironment};
use anyhow::{Context, Result};

use super::{Cli, Command as CliCommand};

const APPLIED_MARKER: &str = "ASBX_INTERNAL_PROXY_APPLIED";
const HTTP_KEYS: &[&str] = &["HTTP_PROXY", "http_proxy"];
const HTTPS_KEYS: &[&str] = &["HTTPS_PROXY", "https_proxy"];
const NO_PROXY_KEYS: &[&str] = &["NO_PROXY", "no_proxy"];
const ALL_PROXY_KEYS: &[&str] = &["ALL_PROXY", "all_proxy"];

/// Re-execute once when file-backed proxy settings must be visible while HTTP
/// clients are constructed. This avoids mutating a multithreaded process
/// environment and does not introduce a resident helper process.
pub(super) fn reexec_if_needed(cli: &Cli) -> Result<Option<i32>> {
    if env::var_os(APPLIED_MARKER).is_some() {
        return Ok(None);
    }

    let config = match cli.config.as_deref() {
        Some(path) if path.exists() => HostConfig::load_from(path)?,
        Some(_) if matches!(&cli.command, CliCommand::Setup(_)) => HostConfig::default(),
        Some(path) => HostConfig::load_from(path)?,
        None => HostConfig::load()?,
    };
    if !config.proxy.requires_reexec() {
        return Ok(None);
    }

    let proxy = config.proxy.environment()?;
    let executable = env::current_exe().context("resolve current asbx executable")?;
    let mut child = Command::new(executable);
    child
        .args(env::args_os().skip(1))
        .stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit())
        .env(APPLIED_MARKER, "1");
    apply_environment(&mut child, &proxy);

    let status = child
        .status()
        .context("start proxy-configured asbx process")?;
    Ok(Some(status.code().unwrap_or(1)))
}

/// Add non-secret proxy state to `doctor`.
pub(super) fn doctor_checks(config: &HostConfig) -> Result<Vec<(String, bool, String)>> {
    let proxy = config.proxy.environment()?;
    let host = if proxy.is_direct() {
        "direct; no HTTP(S) proxy is active".into()
    } else {
        format!(
            "HTTP={}, HTTPS={}, ALL={}, environment inheritance={}",
            source(config.proxy.http.is_some(), proxy.http()),
            source(config.proxy.https.is_some(), proxy.https()),
            source(config.proxy.all.is_some(), proxy.all()),
            if config.proxy.inherit_env {
                "enabled"
            } else {
                "disabled"
            }
        )
    };

    let guest_ready = !config.proxy.inject_guest || !proxy.is_direct();
    let guest = if config.proxy.inject_guest {
        if proxy.is_direct() {
            "enabled, but no HTTP(S) proxy is active".into()
        } else {
            "enabled; the configured endpoint must be reachable from the guest".into()
        }
    } else {
        "disabled (host proxy still applies to image pulls)".into()
    };

    Ok(vec![
        ("Proxy / host clients".into(), true, host),
        ("Proxy / guest injection".into(), guest_ready, guest),
    ])
}

fn source(explicit: bool, effective: Option<&str>) -> &'static str {
    match (explicit, effective.is_some()) {
        (true, true) => "configured",
        (false, true) => "inherited",
        (_, false) => "unset",
    }
}

fn apply_environment(command: &mut Command, proxy: &ProxyEnvironment) {
    for key in HTTP_KEYS
        .iter()
        .chain(HTTPS_KEYS)
        .chain(ALL_PROXY_KEYS)
        .chain(NO_PROXY_KEYS)
    {
        command.env_remove(key);
    }
    set_pair(command, HTTP_KEYS, proxy.http());
    set_pair(command, HTTPS_KEYS, proxy.https());
    set_pair(command, ALL_PROXY_KEYS, proxy.all());
    set_pair(command, NO_PROXY_KEYS, proxy.no_proxy());
}

fn set_pair(command: &mut Command, keys: &[&str], value: Option<&str>) {
    if let Some(value) = value {
        for key in keys {
            command.env(key, value);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn explicit_proxy_details_do_not_expose_credentials() {
        let config = HostConfig {
            proxy: agent_sandbox_policy::ProxyConfig {
                inherit_env: false,
                http: Some("http://secret:token@127.0.0.1:7890".into()),
                https: Some("http://secret:token@127.0.0.1:7890".into()),
                ..agent_sandbox_policy::ProxyConfig::default()
            },
            ..HostConfig::default()
        };

        let checks = doctor_checks(&config).unwrap();
        let output = format!("{checks:?}");
        assert!(!output.contains("secret"));
        assert!(!output.contains("token"));
        assert!(output.contains("configured"));
    }

    #[test]
    fn child_environment_sets_both_standard_casings() {
        let config = HostConfig {
            proxy: agent_sandbox_policy::ProxyConfig {
                inherit_env: false,
                all: Some("http://127.0.0.1:7890".into()),
                no_proxy: vec!["localhost".into()],
                ..agent_sandbox_policy::ProxyConfig::default()
            },
            ..HostConfig::default()
        };
        let proxy = config.proxy.environment().unwrap();
        let mut command = Command::new("asbx");
        apply_environment(&mut command, &proxy);
        let values = command
            .get_envs()
            .map(|(key, value)| {
                (
                    key.to_string_lossy().into_owned(),
                    value.map(|value| value.to_string_lossy().into_owned()),
                )
            })
            .collect::<Vec<_>>();

        if cfg!(windows) {
            for (key, expected) in [
                ("ALL_PROXY", "http://127.0.0.1:7890"),
                ("NO_PROXY", "localhost"),
            ] {
                assert!(values.iter().any(|(candidate, value)| {
                    candidate.eq_ignore_ascii_case(key) && value.as_deref() == Some(expected)
                }));
            }
        } else {
            assert!(values.contains(&("ALL_PROXY".into(), Some("http://127.0.0.1:7890".into()))));
            assert!(values.contains(&("all_proxy".into(), Some("http://127.0.0.1:7890".into()))));
            assert!(values.contains(&("NO_PROXY".into(), Some("localhost".into()))));
            assert!(values.contains(&("no_proxy".into(), Some("localhost".into()))));
        }
    }
}
