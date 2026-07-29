# CLI reference

## One-shot execution

```bash
asbx run [sandbox options] -- PROGRAM [ARG...]
```

Important options:

- `--project PATH`
- `--env auto|go@VERSION|rust@VERSION|node@VERSION`
- `--image OCI_REF` or `--snapshot NAME`
- `--backend microsandbox|qemu`
- `--cpus N`, `--memory SIZE`, `--disk SIZE`
- `--user USER`, `--security default|restricted`
- `--project-mode none|copy|mount-ro|mount-rw`
- `--network off|public|dependencies|rules|all`
- custom rules: `--allow-domain`, `--deny-domain`,
  `--allow-domain-suffix`, `--deny-domain-suffix`, `--allow-cidr`,
  `--deny-cidr`, `--allow-port`, and `--deny-port`; protected destinations
  additionally use host-gated `--allow-private`, `--allow-host`, or
  `--allow-metadata`
- `--timeout DURATION`, `--ttl DURATION`
- `--publish GUEST_PORT[:HOST_PORT]`
- `--env-var KEY=VALUE`
- `--output text|json|jsonl`

`--image` takes precedence over `--snapshot`, which takes precedence over
`--env`. Text output preserves guest stdout/stderr. JSON contains bounded
tails. JSONL emits streaming control and output events.

## QEMU machine boot

```bash
asbx backend list --json
asbx doctor --backend qemu

id="$(asbx open --backend qemu --root-disk ./guest.qcow2 \
  --firmware ./QEMU_EFI.fd --project-mode none --network off)"
asbx inspect "$id" --json
asbx close "$id"
```

Machine inputs are `--root-disk`, `--disk-format raw|qcow2`, `--kernel`,
`--initrd`, `--dtb`, `--firmware`, `--arch`, `--machine`, `--cpu`,
`--accelerator`, and repeatable `--kernel-append`. `--gdb [PORT]` exposes a
loopback GDB stub; `--pause-at-boot` starts CPUs paused. An omitted GDB port is
allocated automatically and reported by `inspect`.

Attach a host debugger without manually parsing runtime metadata:

```bash
asbx debug ID --print-command --json
asbx debug ID --symbols ./vmlinux
asbx debug ID --debugger lldb --command 'register read pc'
```

`--debugger auto|gdb|lldb` controls discovery; `--debugger-binary` selects an
explicit executable. Repeat `--debugger-arg` for native debugger options and
`--command` for commands that must run after the remote connection is
established. The structured plan contains `ready`, `endpoint`, `architecture`,
`accelerator`, `symbol_mode`, the exact program/argument array, and warnings.
Endpoints must be loopback. An explicit symbol file must be a regular file and
its recognized ELF/PE architecture must match the guest. Guest boot images are
reported but never loaded implicitly into the host debugger. GDB/LLDB init
files and symbol-script auto-loading are disabled by default.

QEMU machine mode defaults to `--project-mode none` and `--network off`.
Writable disks use a temporary snapshot and do not mutate the base image.
Guests need an SSH service plus `qemu.ssh_user`/`qemu.ssh_key` (or `--user`)
for copy mode, command execution, shell access, and file transfer. QEMU
currently supports only `off` and host-gated `all`; filtered egress modes stay
on Microsandbox.

Copy mode honors `.gitignore` and `.agent-sandbox-ignore`. Keep generated,
vendored, or local runtime source trees out of the guest through those files;
the wrapper also applies entry-count, per-file, and total-byte caps.

Mounts expose only the canonical authorized project. `mount-ro` prevents guest
writes. `mount-rw` is host-policy gated, quota-limited, and intentionally lets
guest code change host project files.

## Persistent sessions

```bash
asbx open [sandbox options]
asbx exec ID [--cwd /workspace] [--timeout 10m] -- PROGRAM [ARG...]
asbx shell ID
asbx touch ID --ttl 2h
asbx inspect ID --json
asbx list
asbx close ID
```

`open` prints only the session ID on stdout in text mode, so command
substitution is safe. Port information is printed on stderr.

## Ports and artifacts

```bash
asbx ports ID [--json]
asbx artifact list ID [--json]
asbx artifact get ID /out/report.json --to ./report.json
```

Only regular files below `/out` can be downloaded. The host destination must
remain inside an authorized workspace root.

## Environment and diagnostics

```bash
asbx env detect --project . --json
asbx env create NAME --base ubuntu:24.04 \
  --toolchain go@1.24 --toolchain rust@1.88 --toolchain node@22
asbx env list [--json]
asbx env inspect NAME [--json]
asbx env remove NAME
asbx doctor [--backend microsandbox|qemu] [--json]
asbx backend list [--json]
asbx cache status [--json]
asbx cache prune [--max-size SIZE] [--older-than DURATION] \
  [--include-environments] [--dry-run] [--json]
```

Managed environment cache keys include the resolved base-image manifest
digest, host architecture, normalized toolchain versions, and provisioning
manifest version. Cache pruning protects named environments by default.
