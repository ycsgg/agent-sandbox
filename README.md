# Agent Sandbox

`asbx` runs isolated workloads through pluggable local VM backends.
Microsandbox handles OCI-based project commands; QEMU handles bootable disks,
direct kernel boot, multiple guest architectures, serial logs, QMP, and an
optional loopback GDB stub; Cuttlefish handles Android phone images on Linux
KVM hosts through ADB. Project code is copied into the guest by default, host
environment variables are not inherited, public networking excludes
host/private/link-local ranges, and one-shot VMs are removed after execution.
Guest output is streamed through bounded queues; retained JSON tails and
artifacts are capped by host configuration. Cross-process SQLite reservations
enforce both global VM count and reserved-memory ceilings.

Backends implement a small lifecycle contract and opt into independent command,
terminal, file-transfer, snapshot, image-cache, and remote-debug capabilities.
Registry validation rejects a backend whose declared features do not match its
implemented capabilities, so adding an unrelated feature does not require
placeholder changes in every adapter.

Copy mode respects project `.gitignore` and `.agent-sandbox-ignore` files,
rejects escaping symlinks, and constructs guest paths with POSIX semantics on
Linux, macOS, and Windows hosts.

Authorized projects can instead be mounted read-only or, behind an explicit
host gate and write quota, read-write. Network policies support offline,
public-only, statically inferred dependency registries, and deny-by-default
domain/CIDR/port rules.

## Build

The repository pins the published Microsandbox Rust SDK at v0.6.7. A local
`microsandbox/` checkout may be kept beside the wrapper for source inspection,
but it is intentionally ignored by Git.

```bash
cargo build --release -p agent-sandbox-cli
cargo install --path crates/cli
asbx setup
```

Rust 1.94 or newer is required. Microsandbox v0.6.7 uses KVM on Linux,
Hypervisor.framework on Apple Silicon macOS, and Windows Hypervisor Platform
on Windows. The QEMU backend selects KVM, HVF, or WHPX for same-architecture
guests and falls back to TCG for cross-architecture guests. QEMU is optional
unless that backend is selected. Cuttlefish is optional and requires Linux,
read/write access to KVM and vhost-vsock, the Cuttlefish host packages, and
matching host-tool/device-image artifacts.

This repository does not yet publish prebuilt `asbx` binaries or a package
manager formula, so end users currently install from a checkout. Building
downloads the pinned Microsandbox guest agent into Cargo's build output, but
does not provision `msb` or `libkrunfw` into the user's home. `asbx setup` is
the target-machine installation, verification, and repair entry point.

## Setup

Run the setup wizard after installation and whenever the selected backend or
agent CLI changes:

```bash
asbx setup
asbx setup --check
asbx setup --check --json
```

The wizard diagnoses Microsandbox, QEMU, configured Cuttlefish artifacts, and
local Codex, Claude Code, Cursor, Gemini CLI, and OpenCode installations. It
prints one plan and asks for confirmation before downloading a runtime,
invoking a system package manager, creating the host config, or installing the
Agent Skill.
When Microsandbox runtime files are missing, setup resolves GitHub's latest
stable release at runtime and verifies the selected platform bundle against
the release asset's published SHA-256. It never silently changes backends or
falls back to host execution.

Codex, Cursor, Gemini CLI, and OpenCode share the open Agent Skills location
`~/.agents/skills/agent-sandbox`. Claude Code uses
`~/.claude/skills/agent-sandbox`. Re-running setup is idempotent; an existing
unmanaged skill is not changed without `--force`.

Explicit reconfiguration is available for scripts and less common layouts:

```bash
asbx setup --default-backend microsandbox
asbx setup --install-backend qemu
asbx setup --install-backend cuttlefish
asbx setup --harness codex,claude-code
asbx setup --no-harness
asbx setup --yes
```

`--yes` applies the displayed deterministic plan without prompting and is
required for non-interactive mutation. `--check` never writes. QEMU is
installed only when selected, using a detected system package manager after
confirmation. Cuttlefish setup is verification-only: install its Linux host
packages separately, extract a matching `cvd-host_package.tar.gz` and Android
device-image archive into one directory, and set `cuttlefish.artifacts`.

## Usage

```bash
asbx setup --check --no-harness
asbx env detect --project . --json
asbx run --project . --env auto -- cargo test --workspace
asbx run --project . --project-mode mount-ro --network dependencies -- cargo fetch

asbx env create audit-full --base ubuntu:24.04 \
  --toolchain go@1.24 --toolchain rust@1.88 --toolchain node@22
asbx run --project . --env audit-full -- ./scripts/verify.sh

id="$(asbx open --project . --env node@22)"
asbx exec "$id" -- npm ci
asbx exec "$id" -- npm test
asbx close "$id"

# Android Cuttlefish; --android-artifacts also implies --backend cuttlefish.
asbx doctor --backend cuttlefish
asbx run --android-artifacts /opt/android/cuttlefish \
  --project-mode none --network off -- getprop ro.build.version.release

id="$(asbx open --backend cuttlefish --project . --network off)"
asbx exec "$id" -- ls /data/local/tmp/asbx/workspace
asbx exec "$id" -- sh -c \
  'getprop > /data/local/tmp/asbx/out/properties.txt'
asbx artifact get "$id" /data/local/tmp/asbx/out/properties.txt \
  --to ./properties.txt
asbx close "$id"

asbx cache status --json
asbx cache prune --max-size 20G --dry-run --json

asbx backend list --json
id="$(asbx open --backend qemu --root-disk ./guest.qcow2 \
  --firmware ./QEMU_EFI.fd --project-mode none --network off)"
asbx inspect "$id" --json
asbx close "$id"

# Direct kernel boot with an automatically allocated loopback GDB port.
id="$(asbx open --backend qemu --kernel ./Image --initrd ./initramfs.cpio.gz \
  --kernel-append 'console=ttyAMA0' --gdb --pause-at-boot \
  --project-mode none --network off)"
asbx debug "$id" --print-command --json
asbx debug "$id" --symbols ./vmlinux
asbx close "$id"
```

## Proxy and registry access

`asbx` inherits `HTTP_PROXY`, `HTTPS_PROXY`, `ALL_PROXY`, and `NO_PROXY` for
host-side OCI image pulls. Persistent settings can be placed in
`~/.agent-sandbox/config.toml` (or the file passed with `--config`):

```toml
[proxy]
inherit_env = false
http = "http://127.0.0.1:7890"
https = "http://127.0.0.1:7890"
# `all` is also supported when one proxy handles both schemes.
no_proxy = ["localhost", "127.0.0.1", "::1"]
inject_guest = false
```

File-backed settings are applied by a one-time self re-exec before registry
clients are constructed; no proxy helper or resident `asbx` daemon is started.
File-backed proxy URLs must use HTTP(S). Docker Hub shorthand such as
`alpine:3.20`, `library/alpine`, and `docker.io/library/alpine` is normalized
to `registry-1.docker.io`, avoiding the legacy `index.docker.io` endpoint.

`inject_guest` is intentionally off by default. Enable it only when the proxy
address and network policy are reachable from inside the VM; `127.0.0.1` in a
guest is not the host and therefore is not a usable guest proxy endpoint.

QEMU machine mode defaults to no workspace and offline networking. A writable
root disk uses QEMU temporary snapshot mode, so the caller-owned base image is
not modified. Configure `qemu.ssh_user` (and usually `qemu.ssh_key`) to enable
`copy`, `exec`, `shell`, and artifact transfer for guests that run SSH.
Filtered `public`, `dependencies`, and `rules` networking remains a
Microsandbox capability; QEMU currently accepts only `off` and host-gated
`all`. QEMU lease expiry is enforced on the next `asbx` invocation; unlike
Microsandbox, the QEMU adapter does not install an always-running TTL helper.

Cuttlefish accepts project modes `none` and `copy`. Its workspace is
`/data/local/tmp/asbx/workspace`, its downloadable artifact directory is
`/data/local/tmp/asbx/out`, and its default shell is `/system/bin/sh`.
Networking defaults to `off` by launching recent Cuttlefish tools without TAP
devices. Host-gated `all` is also available; filtered modes, host mounts,
published guest ports, and the wrapper restricted profile are rejected until
they can be enforced honestly. Like QEMU, Cuttlefish lease expiry is reclaimed
on the next `asbx` invocation rather than by a resident helper.

`asbx debug` validates the session, loopback endpoint, symbol architecture,
and debugger executable before attaching. It automatically selects LLDB on
macOS and GDB on other hosts. Without `--symbols`, a direct-boot kernel is
reported as context but is not loaded into the host debugger; remote
registers, memory, and disassembly remain available. Debugger init files and
symbol-script auto-loading are disabled by default.

See [`skill/agent-sandbox/SKILL.md`](skill/agent-sandbox/SKILL.md) and
[`agent-sandbox.md`](agent-sandbox.md) for workflows and design rationale.

## Safety notes

`mount-rw` lets guest code modify the authorized host project and is disabled
unless `workspace.allow_rw_mount` is enabled. Named environments contain only
trusted wrapper provisioning, never project install hooks. Cache pruning keeps
named environments by default; use `--include-environments` explicitly and
review `--dry-run` output before removing them.

`asbx debug --symbols` causes a trusted host debugger to parse that file.
Supply only a symbol artifact you intend to expose to a host process; the
guest boot image is never loaded implicitly.
