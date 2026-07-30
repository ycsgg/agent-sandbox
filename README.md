# Agent Sandbox

English | [简体中文](README.zh-CN.md)

Agent Sandbox is a local isolation runtime for coding agents. A person installs
the `asbx` CLI, prepares one or more virtualization backends, and installs the
bundled Agent Skill. The agent then decides when and how to create disposable
sandboxes.

The integration path is:

```text
Codex / Claude Code / Cursor / Gemini CLI / OpenCode
                         │
                  Agent Skill + shell
                         │
                       asbx
                         │
        Microsandbox / QEMU / Cuttlefish / Android Emulator
```

This README is for the person who provisions the machine or integrates another
backend. Agent workflows and command-selection guidance live in the bundled
[`agent-sandbox` Skill](skill/agent-sandbox/SKILL.md).

## Install the CLI

Prebuilt binaries are not published yet. Install from a checkout with Rust 1.94
or newer:

```bash
cargo install --path crates/cli
asbx --version
```

Run setup once after installing or upgrading the CLI:

```bash
asbx setup
```

Setup detects installed agent harnesses and backends, displays the changes it
would make, and asks before modifying the machine. It can install the
Microsandbox runtime, invoke a supported package manager for QEMU, create the
host configuration, and install the Agent Skill.

For an explicit or non-interactive installation:

```bash
asbx setup \
  --default-backend microsandbox \
  --harness codex,claude-code \
  --yes

asbx setup --check --json
```

`--yes` applies the displayed plan without prompting. `--check` is read-only
and exits non-zero when an action or manual fix is still required.

The Skill is installed in:

- `~/.agents/skills/agent-sandbox` for Codex, Cursor, Gemini CLI, and OpenCode
- `~/.claude/skills/agent-sandbox` for Claude Code

Re-run `asbx setup` after upgrading so managed Skill files stay in sync with
the CLI. Agent Sandbox uses a Skill and the agent's existing shell capability;
it does not require an MCP server or a resident `asbx` daemon.

## Choose a backend

The backends are intentionally different. Choose the one that matches the
workload instead of treating them as interchangeable VM implementations.

| Backend | Use it for | Host support | Setup behavior |
|---|---|---|---|
| `microsandbox` | Normal repository builds, tests, OCI images, and language environments | Automatic setup on Apple Silicon macOS and x86_64/ARM64 Linux | Downloads and verifies the runtime |
| `android-emulator` | Existing Android SDK AVDs | macOS, Linux, Windows | Verifies tools, acceleration, and the configured AVD |
| `cuttlefish` | AOSP/Cuttlefish phone images and offline Android jobs | Linux with KVM and vhost-vsock | Verifies host devices, tools, and artifacts |
| `qemu` | Boot disks, custom kernels, other architectures, serial/QMP/GDB | macOS, Linux, Windows; TCG is available for cross-architecture guests | Can install QEMU through supported macOS/Linux package managers |

Microsandbox is the default for ordinary coding-agent work. Android Emulator is
the portable Android choice. Cuttlefish is the stronger choice for offline
Android isolation when a compatible Linux host is available. QEMU is for
full-machine jobs rather than normal OCI project execution.

`asbx` never falls back to running guest commands directly on the host when a
backend is unavailable.

## Prepare Microsandbox

On a supported host, setup can provision Microsandbox without a separate manual
installation:

```bash
asbx setup --default-backend microsandbox
asbx doctor --backend microsandbox
```

Setup resolves the latest stable runtime bundle and verifies its published
SHA-256 before installation. The Rust build embeds the matching guest agent but
does not install the host runtime by itself.

Use Microsandbox for the default Agent Skill workflow: copied projects, OCI
images, reusable language environments, filtered networking, services, and
artifacts.

## Prepare Android Emulator

Android Emulator is the cross-platform Android backend. First install these
components with Android Studio or the Android SDK command-line tools:

- Android SDK Emulator
- Android SDK Platform-Tools (`adb`)
- a system image compatible with the host architecture
- an Android Virtual Device created from that image
- working host acceleration: Hypervisor.Framework, KVM, or WHPX

Check the Android installation before configuring `asbx`:

```bash
emulator -accel-check
emulator -list-avds
adb version
```

Add the AVD to `~/.agent-sandbox/config.toml`:

```toml
[android_emulator]
avd = "TestPhone"
boot_timeout = "5m"
shutdown_timeout = "30s"
gpu = "auto"

# Usually discovered from ANDROID_SDK_ROOT or standard SDK locations.
# sdk_root = "/path/to/Android/sdk"
# emulator = "/path/to/Android/sdk/emulator/emulator"
# adb = "/path/to/Android/sdk/platform-tools/adb"

[network]
allow_all_mode = true
```

Then select and verify it:

```bash
asbx setup --default-backend android-emulator
asbx doctor --backend android-emulator

# Optional end-to-end smoke test
asbx run --android-avd TestPhone \
  --project-mode none \
  --network all \
  -- getprop ro.build.version.release
```

Each sandbox cold-boots a private copy of the source AVD configuration with
fresh data state. The source AVD is not started or modified.

Android Emulator requires explicit `--network all` and the host-side
`network.allow_all_mode = true` gate. The SDK Emulator has no portable
interface through which `asbx` can enforce complete offline or filtered egress.
Use Cuttlefish on Linux if unrestricted Android networking is unacceptable.

## Prepare Cuttlefish

Cuttlefish requires a Linux host with read/write access to both `/dev/kvm` and
`/dev/vhost-vsock`. Install the Cuttlefish host packages appropriate for the
host, then extract these two matching Android build artifacts into one
directory:

- `cvd-host_package.tar.gz`
- the Cuttlefish device-image archive

Configure that directory:

```toml
[cuttlefish]
artifacts = "/opt/android/cuttlefish"
boot_timeout = "5m"
shutdown_timeout = "30s"
```

Select and verify the backend:

```bash
asbx setup --default-backend cuttlefish
asbx doctor --backend cuttlefish

# Optional end-to-end smoke test
asbx run --backend cuttlefish \
  --project-mode none \
  --network off \
  -- getprop ro.build.version.release
```

`asbx setup` does not download Android images or install Cuttlefish host
packages; it verifies the artifacts and host capabilities already provided.
Recent host tools with `--enable_tap_devices` support are required for the
backend's offline mode.

## Prepare QEMU

On macOS or Linux, setup can invoke a detected package manager after showing
the exact command:

```bash
asbx setup --install-backend qemu
asbx doctor --backend qemu
```

On Windows, or for a custom installation, install QEMU separately and point
`asbx` at the system binary when it is not on `PATH`:

```toml
[qemu]
binary = "/path/to/qemu-system-aarch64"
boot_timeout = "2m"
shutdown_timeout = "10s"
```

Lifecycle, serial output, QMP, and a loopback GDB stub work without software in
the guest. Project copy, agent commands, shell access, and artifact transfer
require SSH inside the guest:

```toml
[qemu]
ssh_user = "root"
ssh_key = "/path/to/qemu_guest_key"
```

The caller supplies a boot disk or kernel for each job. Writable root disks use
QEMU snapshot mode, so the base image is not modified.

## Set host policy

The machine owner controls the hard limits in
`~/.agent-sandbox/config.toml`. Start from
[`config.example.toml`](config.example.toml), then review at least:

- authorized workspace roots and whether read-write mounts are allowed
- default network mode and the high-risk `allow_all_mode` gate
- CPU, memory, disk, output, transfer, and cache ceilings
- backend-specific paths, timeouts, and credentials

Agent requests may narrow these limits but cannot silently widen them. Host
environment variables and credentials are not inherited by guests unless the
caller passes specific values.

Verify the completed handoff with:

```bash
asbx setup --check --json
asbx backend list --json
asbx doctor --backend microsandbox
```

Replace the last backend name with the backend selected for the machine. Once
these checks pass and the Skill is installed, the agent has the instructions it
needs to choose `run`, `open`/`exec`/`close`, networking, project exposure, and
artifact handling.

## Adapt another backend

Backend adapters implement a small lifecycle contract and opt into only the
operations they actually support:

1. Add a runtime crate that implements
   [`SandboxRuntime`](crates/runtime/lib/lib.rs) and its readiness checks.
2. Implement only the applicable optional traits, such as `CommandRuntime`,
   `TerminalRuntime`, `FileTransferRuntime`, `SnapshotRuntime`, `ImageRuntime`,
   or `DebugRuntime`.
3. Declare matching `BackendCapabilities`. The registry rejects mismatches
   between declared features and implemented capability accessors.
4. Register and configure the adapter in
   [`app/bootstrap.rs`](crates/cli/bin/app/bootstrap.rs).
5. Extend [`app/setup.rs`](crates/cli/bin/app/setup.rs) if the backend needs
   host installation or verification, and add contract and lifecycle tests.

The backend-neutral core does not require placeholder implementations for
unsupported features. See the
[`RuntimeRegistry`](crates/runtime/lib/registry.rs), existing
[`QEMU`](crates/runtime-qemu/lib/lib.rs) and
[`Android Emulator`](crates/runtime-android-emulator/lib/lib.rs) adapters, and
the [design document](agent-sandbox.md) for the complete contract.

## Reference

- [Agent instructions](skill/agent-sandbox/SKILL.md)
- [CLI reference](skill/agent-sandbox/references/cli.md)
- [Environment selection](skill/agent-sandbox/references/environments.md)
- [Troubleshooting](skill/agent-sandbox/references/troubleshooting.md)
- [Architecture and security model](agent-sandbox.md)
