# Agent Sandbox

`asbx` runs project build, test, and audit commands inside disposable
Microsandbox microVMs. Project code is copied into the guest by default,
host environment variables are not inherited, public networking excludes
host/private/link-local ranges, and one-shot VMs are removed after execution.
Guest output is streamed through bounded queues; retained JSON tails and
artifacts are capped by host configuration. Cross-process SQLite reservations
enforce both global VM count and reserved-memory ceilings.

Copy mode respects project `.gitignore` and `.agent-sandbox-ignore` files,
rejects escaping symlinks, and constructs guest paths with POSIX semantics on
Linux, macOS, and Windows hosts.

## Build

The repository pins the published Microsandbox Rust SDK at v0.6.7. A local
`microsandbox/` checkout may be kept beside the wrapper for source inspection,
but it is intentionally ignored by Git.

```bash
cargo build --release -p agent-sandbox-cli
cargo install --path crates/cli
```

Rust 1.94 or newer is required. Runtime support follows Microsandbox v0.6.7:
Linux with KVM, Apple Silicon macOS with Hypervisor.framework, and Windows with
Windows Hypervisor Platform.

On Apple Silicon, use the Microsandbox setup checks before the first VM:

```bash
cargo run -p agent-sandbox-cli -- doctor
```

## Usage

```bash
asbx env detect --project . --json
asbx run --project . --env auto -- cargo test --workspace

id="$(asbx open --project . --env node@22)"
asbx exec "$id" -- npm ci
asbx exec "$id" -- npm test
asbx close "$id"
```

See [`skill/agent-sandbox/SKILL.md`](skill/agent-sandbox/SKILL.md) and
[`agent-sandbox.md`](agent-sandbox.md) for workflows and design rationale.

## Current scope

The implemented CLI covers the Phase 1 execution loop plus environment
detection, JSON/JSONL output, loopback publishing, artifacts, and lease
reconciliation. Workspace mounts, custom network rules, multi-toolchain
environment building, and cache pruning remain later-phase features and are
not exposed as working commands.
