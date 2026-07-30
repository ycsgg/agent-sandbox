---
name: agent-sandbox
description: Run, build, test, audit, or inspect untrusted software inside disposable local microVM sandboxes. Use when an agent needs to execute repository code, install project dependencies, validate generated changes, start a local service, test Go/Rust/Node versions, or inspect suspicious build and test behavior without running it directly on the host.
---

# Agent Sandbox

Use the local `asbx` CLI whenever a task would execute project code, dependency
install hooks, build scripts, tests, or downloaded binaries.

## Choose a workflow

1. Run `scripts/check-asbx.sh` if runtime readiness is unknown. If it fails,
   use `asbx setup` for an interactive repair or `asbx setup --check --json`
   for a machine-readable plan.
2. Run `asbx env detect --project . --json` before choosing an environment.
3. Use `asbx run` for one command. It creates, streams, and removes one VM.
4. Use `open → exec → close` for dependency installation, multiple commands,
   debugging, or services.
5. Use `asbx shell ID` only when an interactive terminal is necessary.
6. For QEMU machine debugging, open with `--gdb` and use
   `asbx debug ID --print-command --json` before attaching symbols or an
   interactive debugger.

Use the default Microsandbox backend for OCI images and project workflows.
Select `--backend qemu` only when the task supplies a bootable disk or kernel
and needs full-system, cross-architecture, serial, QMP, or GDB capabilities.
Select `--backend cuttlefish` (or pass `--android-artifacts`) only for Android
phone-image workflows on a configured Linux KVM host. Cuttlefish supports ADB
command, terminal, project-copy, and artifact-transfer workflows; it does not
provide OCI environments or snapshots.
Select `--backend android-emulator` (or pass `--android-avd NAME`) for a local
Android SDK AVD on macOS, Windows, or Linux. It provides the same ADB command,
terminal, project-copy, and artifact-transfer workflow, but requires explicit
host-gated `--network all`.
Check declared features with `asbx backend list --json`; use
`asbx setup --check --no-harness` to verify that the configured backend is
actually installed and ready.

For a paused, symbol-aware machine debug session:

```bash
id="$(asbx open --backend qemu --kernel ./Image --initrd ./initramfs \
  --accelerator tcg --kernel-append nokaslr --gdb --pause-at-boot \
  --project-mode none --network off)"
asbx debug "$id" --symbols ./vmlinux
asbx close "$id"
```

The debug command discovers the loopback endpoint and host debugger. Prefer
`--print-command --json` when another Agent or IDE will launch the debugger.

Never run a project's install, build, test, or audit command directly on the
host as a fallback. Diagnose the sandbox or ask the user how to proceed.

## Select boundaries deliberately

- Keep the default copy mode. It prevents guest writes from changing the host
  project, honors `.gitignore` and `.agent-sandbox-ignore`, and excludes
  `.git`, dependency, build, and coverage directories.
- Use `--project-mode mount-ro` when the guest needs a live view of host edits.
  Use `mount-rw` only when host-file mutation is required and the user accepts
  that boundary; host policy must enable it and applies a write quota.
- Choose `--network off` for offline checks and `--network public` when package
  installation needs the Internet. Public mode still denies host and private
  networks.
- Prefer `--network dependencies` for Go, Cargo, or npm registry access. Use
  `--network rules` with explicit domain/CIDR/port flags for a custom
  deny-by-default policy. Private, host, and metadata allows require an
  explicit host-policy override.
- Use `--network all` only if the host configuration permits it and the task
  genuinely requires unrestricted access.
- Pass only specific values with `--env-var KEY=VALUE`. Host environment
  variables and credentials are not inherited.
- Write reports or build outputs that must leave the VM below `/out` on
  Microsandbox/QEMU, or `/data/local/tmp/asbx/out` on either Android backend.
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

## Android Cuttlefish

```bash
asbx doctor --backend cuttlefish
id="$(asbx open --backend cuttlefish --project . --network off)"
asbx exec "$id" -- ls /data/local/tmp/asbx/workspace
asbx exec "$id" -- sh -c \
  'getprop > /data/local/tmp/asbx/out/properties.txt'
asbx artifact list "$id"
asbx close "$id"
```

Use `--android-artifacts PATH` when the combined host-tools/device-images
directory is not configured globally. Keep `--network off` unless unrestricted
Android networking is genuinely required and host policy permits
`--network all`. Cuttlefish does not support filtered network modes, project
mounts, port publication, or `--security restricted`.

## Android SDK Emulator

```bash
asbx doctor --backend android-emulator
id="$(asbx open --android-avd TestPhone --project . --network all)"
asbx exec "$id" -- ls /data/local/tmp/asbx/workspace
asbx exec "$id" -- sh -c \
  'getprop > /data/local/tmp/asbx/out/properties.txt'
asbx artifact list "$id"
asbx close "$id"
```

The source AVD is never run or modified directly; asbx cold-boots a private
copy of its configuration with fresh data state. Use this backend only when
the task genuinely permits unrestricted Android networking and the host has
`network.allow_all_mode = true`. It rejects offline/filtered networking,
project mounts, port publication, snapshots, OCI images, and
`--security restricted`.

Read [references/cli.md](references/cli.md) for command forms,
[references/environments.md](references/environments.md) when auto detection is
insufficient, and [references/troubleshooting.md](references/troubleshooting.md)
when startup, execution, or cleanup fails.
