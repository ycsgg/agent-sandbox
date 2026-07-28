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
- `--network off|public|all`
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
asbx doctor [--json]
asbx cache status [--json]
```
