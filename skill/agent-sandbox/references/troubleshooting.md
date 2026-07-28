# Troubleshooting

## Runtime is unavailable

Run:

```bash
asbx doctor
```

Resolve failed virtualization, `msb`, or `libkrunfw` checks. Do not run the
project command on the host as a fallback.

## Auto detection fails

Inspect:

```bash
asbx env detect --project . --json
```

For no runtime or multiple runtimes, pass `--image`. For a version mismatch,
pass an explicit `--env LANG@VERSION`.

## Dependency download fails

Confirm that the sandbox uses `--network public`. Public mode intentionally
blocks private registries and host services. Do not switch to `all` unless the
host permits it and the task requires private access.

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
runtime maximum duration is a second cleanup backstop.

## Artifact download is rejected

Ensure the source is a regular file below `/out` and the destination is inside
an authorized workspace root:

```bash
asbx artifact list ID
asbx artifact get ID /out/report.json --to ./report.json
```
