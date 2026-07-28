---
name: agent-sandbox
description: Run, build, test, audit, or inspect untrusted software inside disposable local microVM sandboxes. Use when an agent needs to execute repository code, install project dependencies, validate generated changes, start a local service, test Go/Rust/Node versions, or inspect suspicious build and test behavior without running it directly on the host.
---

# Agent Sandbox

Use the local `asbx` CLI whenever a task would execute project code, dependency
install hooks, build scripts, tests, or downloaded binaries.

## Choose a workflow

1. Run `scripts/check-asbx.sh` if runtime readiness is unknown.
2. Run `asbx env detect --project . --json` before choosing an environment.
3. Use `asbx run` for one command. It creates, streams, and removes one VM.
4. Use `open → exec → close` for dependency installation, multiple commands,
   debugging, or services.
5. Use `asbx shell ID` only when an interactive terminal is necessary.

Never run a project's install, build, test, or audit command directly on the
host as a fallback. Diagnose the sandbox or ask the user how to proceed.

## Select boundaries deliberately

- Keep the default copy mode. It prevents guest writes from changing the host
  project, honors `.gitignore` and `.agent-sandbox-ignore`, and excludes
  `.git`, dependency, build, and coverage directories.
- Choose `--network off` for offline checks and `--network public` when package
  installation needs the Internet. Public mode still denies host and private
  networks.
- Use `--network all` only if the host configuration permits it and the task
  truly requires private/host access.
- Pass only specific values with `--env-var KEY=VALUE`. Host environment
  variables and credentials are not inherited.
- Write reports or build outputs that must leave the VM below `/out`.
- Use `--user root` when package or OS installation requires guest root.

## One-shot

```bash
asbx run --project . --env auto --network public -- cargo test --workspace
```

The CLI exit code is the guest command exit code. A failed command is still a
successful isolation workflow; inspect its streamed stderr before changing the
environment.

## Session or service

```bash
id="$(asbx open --project . --env node@22 --network public --publish 3000)"
asbx exec "$id" -- npm ci
asbx exec "$id" -- npm test
asbx exec "$id" -- npm run dev -- --host 0.0.0.0
asbx ports "$id"
asbx artifact list "$id"
asbx close "$id"
```

Always close sessions after collecting diagnostics and artifacts. If an
operation fails, inspect first, then close:

```bash
asbx inspect ID --json
asbx artifact list ID --json
asbx close ID
```

Read [references/cli.md](references/cli.md) for command forms,
[references/environments.md](references/environments.md) when auto detection is
insufficient, and [references/troubleshooting.md](references/troubleshooting.md)
when startup, execution, or cleanup fails.
