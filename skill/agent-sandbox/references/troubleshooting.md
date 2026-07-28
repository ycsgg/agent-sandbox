# Troubleshooting

## Runtime is unavailable

Run:

```bash
asbx doctor
asbx doctor --backend qemu
```

Resolve failed virtualization, `msb`, or `libkrunfw` checks. Do not run the
project command on the host as a fallback.

For QEMU, install the matching `qemu-system-ARCH` binary. Hardware
acceleration is KVM on Linux, HVF on macOS, and WHPX on Windows; TCG is the
portable fallback and is selected automatically for cross-architecture
guests.

## QEMU starts but guest commands are unavailable

Lifecycle, serial logging, QMP, and GDB do not require a guest transport. For
`copy`, `exec`, `shell`, or artifacts, the guest must run SSH and the host
configuration must set `qemu.ssh_user` (and normally `qemu.ssh_key`), or the
machine command must pass `--user`.

Use `asbx inspect ID --json` to locate the serial log and active QMP, SSH, and
GDB loopback endpoints. Use `--project-mode none` for machines without SSH.

## Auto detection fails

Inspect:

```bash
asbx env detect --project . --json
```

For no runtime or multiple runtimes, pass `--image`. For a version mismatch,
pass an explicit `--env LANG@VERSION`.

## Dependency download fails

Confirm that the sandbox uses `--network public`, or `dependencies` for
detected Go/Cargo/npm registries. Custom `rules` mode is deny-by-default, so
add each required domain or public port. These modes intentionally block
private registries and host services. Do not switch to `all` unless the host
permits it and the task requires private access.

## Managed environment build fails

Use a glibc base such as `ubuntu:24.04` or Debian when installing exact Node.js
toolchains. Registry and toolchain downloads require public network access.
Failed builders are removed and are not registered; rerun the same
`asbx env create` after fixing the base or connectivity.

## Command times out or floods output

Increase `--timeout` only when the task is expected to run longer. JSON and
JSONL modes retain bounded tails; text mode streams without collecting the
full output in wrapper memory. Under sustained host-output backpressure,
`asbx` reports an `exec.output_truncated` event and discards excess chunks
rather than allowing wrapper memory to grow without bound.

## Session appears stale

Inspect and close it:

```bash
asbx inspect ID --json
asbx close ID
```

Every `asbx` invocation also reconciles expired wrapper leases. Microsandbox's
runtime maximum duration is a second cleanup backstop. QEMU does not install a
persistent TTL helper, so an expired QEMU machine is reclaimed by the next
`asbx` invocation.

## Artifact download is rejected

Ensure the source is a regular file below `/out` and the destination is inside
an authorized workspace root:

```bash
asbx artifact list ID
asbx artifact get ID /out/report.json --to ./report.json
```
