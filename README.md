# Agent Sandbox

`asbx` runs isolated workloads through pluggable local VM backends.
Microsandbox handles OCI-based project commands; QEMU handles bootable disks,
direct kernel boot, multiple guest architectures, serial logs, QMP, and an
optional loopback GDB stub. Project code is copied into the guest by default,
host environment variables are not inherited, public networking excludes
host/private/link-local ranges, and one-shot VMs are removed after execution.
Guest output is streamed through bounded queues; retained JSON tails and
artifacts are capped by host configuration. Cross-process SQLite reservations
enforce both global VM count and reserved-memory ceilings.

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
```

Rust 1.94 or newer is required. Microsandbox v0.6.7 uses KVM on Linux,
Hypervisor.framework on Apple Silicon macOS, and Windows Hypervisor Platform
on Windows. The QEMU backend selects KVM, HVF, or WHPX for same-architecture
guests and falls back to TCG for cross-architecture guests. QEMU is optional
unless that backend is selected.

On Apple Silicon, use the Microsandbox setup checks before the first VM:

```bash
cargo run -p agent-sandbox-cli -- doctor
cargo run -p agent-sandbox-cli -- doctor --backend qemu
```

## Usage

```bash
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

QEMU machine mode defaults to no workspace and offline networking. A writable
root disk uses QEMU temporary snapshot mode, so the caller-owned base image is
not modified. Configure `qemu.ssh_user` (and usually `qemu.ssh_key`) to enable
`copy`, `exec`, `shell`, and artifact transfer for guests that run SSH.
Filtered `public`, `dependencies`, and `rules` networking remains a
Microsandbox capability; QEMU currently accepts only `off` and host-gated
`all`. QEMU lease expiry is enforced on the next `asbx` invocation; unlike
Microsandbox, the QEMU adapter does not install an always-running TTL helper.

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
