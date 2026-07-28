# CLI reference

## One-shot execution

```bash
asbx run [sandbox options] -- PROGRAM [ARG...]
```

Important options:

- `--project PATH`
- `--env auto|go@VERSION|rust@VERSION|node@VERSION`
- `--image OCI_REF` or `--snapshot NAME`
- `--cpus N`, `--memory SIZE`, `--disk SIZE`
- `--user USER`, `--security default|restricted`
- `--project-mode copy|mount-ro|mount-rw`
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
asbx doctor [--json]
asbx cache status [--json]
asbx cache prune [--max-size SIZE] [--older-than DURATION] \
  [--include-environments] [--dry-run] [--json]
```

Managed environment cache keys include the resolved base-image manifest
digest, host architecture, normalized toolchain versions, and provisioning
manifest version. Cache pruning protects named environments by default.
