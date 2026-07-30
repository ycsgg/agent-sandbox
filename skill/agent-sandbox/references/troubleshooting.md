# Troubleshooting

## Runtime is unavailable

Run:

```bash
asbx setup --check --no-harness
asbx setup
```

The first command is read-only and reports the exact repair plan. The second
asks for confirmation before installing or changing anything. For detailed
backend diagnostics, run `asbx doctor` or select one backend with
`--backend qemu`, `--backend cuttlefish`, or `--backend android-emulator`.
Resolve failed virtualization, `msb`, or `libkrunfw` checks. Do not run the
project command on the host as a fallback.

For QEMU, `asbx setup --install-backend qemu` proposes the matching system
package-manager command. Hardware acceleration is KVM on Linux, HVF on macOS,
and WHPX on Windows; TCG is the portable fallback and is selected
automatically for cross-architecture guests.

For Cuttlefish, install the official Linux host packages, verify that
`/dev/kvm` and `/dev/vhost-vsock` are accessible, and combine a matching
`cvd-host_package.tar.gz` plus Android device-image archive in the directory
configured as `cuttlefish.artifacts`. Offline mode additionally needs host
tools that expose `--enable_tap_devices`; use a 2025-03 or newer matching
build. `asbx setup` diagnoses these inputs but does not download Android
artifacts or install the privileged host packages.

For Android Emulator, install the SDK Emulator, platform-tools, and a system
image, then create an AVD with Android Studio or `avdmanager`. Set
`android_emulator.avd` or pass `--android-avd NAME`. Doctor reports the
resolved binaries, acceleration result, and available/configured AVDs.

## QEMU starts but guest commands are unavailable

Lifecycle, serial logging, QMP, and GDB do not require a guest transport. For
`copy`, `exec`, `shell`, or artifacts, the guest must run SSH and the host
configuration must set `qemu.ssh_user` (and normally `qemu.ssh_key`), or the
machine command must pass `--user`.

Use `asbx inspect ID --json` to locate the serial log and active QMP, SSH, and
GDB loopback endpoints. Use `--project-mode none` for machines without SSH.

## Cuttlefish starts but ADB commands are unavailable

Inspect the session and the wrapper-owned `launch.log` path:

```bash
asbx inspect ID --json
asbx doctor --backend cuttlefish --json
```

Host tools and phone images must come from the same Android build. Confirm that
no external Cuttlefish instance owns the reported ADB port, and that the Linux
user has the access installed by the Cuttlefish host packages. Android user
builds might not provide `su`; omit `--user root` or use a userdebug image.

## Android Emulator does not boot

Run:

```bash
asbx doctor --backend android-emulator --json
```

Confirm that the configured AVD exists, matches the host architecture, and
that Hypervisor.Framework (macOS), WHPX (Windows), or KVM (Linux) is usable.
Inspect `asbx inspect ID --json` for the private AVD name and console/ADB
ports, then inspect `emulator.log` below the backend state directory. A Google
Play/user image may not provide `su`; omit `--user root`. Stale sessions are
reclaimed by `asbx close ID` or the next lease reconciliation.

## QEMU debugger does not attach

Inspect a non-mutating, structured launch plan:

```bash
asbx debug ID --print-command --json
```

The session must be active and opened with `--gdb`. Use `--pause-at-boot` when
early startup matters. TCG provides the most consistent breakpoint and
watchpoint behavior; hardware accelerators may expose fewer debug features.
For Linux source-level debugging, pass a matching uncompressed `vmlinux` with
debug information through `--symbols` and boot with
`--kernel-append nokaslr`. Without symbols, `asbx debug` connects without
loading a host file and still supports register, memory, and remote
assembly-level inspection.

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

For an OCI image pull failure, run `asbx doctor` and distinguish the host-side
registry pull from networking inside the guest. `asbx` inherits
`HTTP_PROXY`/`HTTPS_PROXY`/`ALL_PROXY`/`NO_PROXY`; persistent host proxy values
belong in the `[proxy]` configuration section. Docker Hub shorthand is resolved through
`registry-1.docker.io`, not the legacy `index.docker.io` hostname. Layer blobs
also require access to `production.cloudfront.docker.com`.

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
runtime maximum duration is a second cleanup backstop. QEMU, Cuttlefish, and
Android Emulator do not install a persistent TTL helper, so an expired
full-system VM is reclaimed by the next `asbx` invocation.

## Artifact download is rejected

Ensure the source is a regular file below the backend artifact directory and
the destination is inside an authorized workspace root:

```bash
asbx artifact list ID
asbx artifact get ID /out/report.json --to ./report.json
# Either Android backend:
asbx artifact get ID /data/local/tmp/asbx/out/report.json --to ./report.json
```
