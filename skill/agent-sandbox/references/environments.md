# Environment selection

`asbx env detect` statically reads bounded declaration files; it never executes
project code.

Supported fast paths:

| Project declaration | Environment | OCI image |
|---|---|---|
| `go.mod`, `go.work` | `go@VERSION` | official `golang` Bookworm image |
| `rust-toolchain*`, `Cargo.toml` | `rust@VERSION` | official `rust` Bookworm image |
| `.nvmrc`, `.node-version`, `package.json`, `tsconfig*.json` | `node@VERSION` | official `node` Bookworm image |

Use `--env auto` for a single supported runtime. Build a named environment for
multiple toolchains:

```bash
asbx env create audit-full --base ubuntu:24.04 \
  --toolchain go@1.24 \
  --toolchain rust@1.88 \
  --toolchain node@22
asbx run --project . --env audit-full -- ./scripts/verify.sh
```

Builder snapshots contain wrapper-managed toolchains but no project files or
install hooks. Exact Node.js builders require a glibc base such as Ubuntu or
Debian. Builder architecture is derived from the host, so the same CLI works
on supported x86_64 and arm64 hosts.

Use an explicit `--image` for:

- Python, Java, or other ecosystems;
- native system dependencies not present in the fast-path image;
- a fully reproducible image digest;
- private registry or organization-specific images.

Examples:

```bash
asbx run --project . --env go@1.24 -- go test ./...
asbx run --project . --env rust@1.88 -- cargo test --workspace
asbx run --project . --env node@22 -- npm test
asbx run --project . --image ghcr.io/acme/audit@sha256:DIGEST -- ./verify.sh
```

Dependency installation belongs inside the project sandbox. Do not turn a
snapshot containing untrusted project install hooks into a shared trusted
environment.
