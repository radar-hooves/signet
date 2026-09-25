# signet

Machine-identity attest client for Portcullis, the household secrets broker: one self-contained Go binary that holds a P-256 key in a file and proves _which machine_ you are. It signs the broker's `/v1/attest` challenge and trades the proof for a short-lived bearer. Broker-agnostic: any service implementing the attest contract can consume it.

## Scope

These are deliberate boundaries, not gaps — the code shows what is present, never what is deliberately absent and why.

- **Vendors no broker code and makes no authorisation decision.** signet proves possession of a key; the broker alone issues challenges, verifies signatures, mints bearers, and fixes vend scope. It speaks the `/v1/attest/*` HTTP contract (plus the public `/v1/credentials/{name}` vend door) and nothing more. Detail: `.claude/rules/attest-boundary.md`.
- **One key, one file.** The signing key is a P-256 private key in a PKCS8 PEM file, mode `0600`, at `$XDG_CONFIG_HOME/portcullis/<identity>.key` — the same path and format the household's `vend-token.py` already uses. Detail: `.claude/rules/key-custody.md`.
- **A thin credential helper, not a framework.** The protocol half (challenge → sign → token → renew) is deliberately small and specific to one broker's contract. SPIRE, mTLS meshes, and full PKI are heavier answers to a problem a single broker does not have — do not grow it into one.
- **Single-shot, not resident.** Every subcommand runs once and exits, like `git credential` / `docker-credential-*` / AWS `credential_process`. No daemon, no socket, no agent mode.

## Building

```bash
make build   # CGO_ENABLED=0 go build -o signet ./cmd/signet
make test    # CGO_ENABLED=0 go test ./...
```

Plain Go, no cgo: cross-compiles freely with `GOOS`/`GOARCH`.

## Sources of truth

- **Broker contract**: the `/v1/attest` HTTP API (any broker implementing it). Household attestation architecture: `docs/master/governance/secrets/`.
- **Config, usage**: `docs/configuration.md`, `docs/usage.md`.

## CI deviations from the household standard

- **No `auto-label-issues` caller.** `rules-library/core/ci-workflow-standard.md` permits a public repo that cannot resolve the private master-project reusable to omit the caller provided the omission is recorded. signet is public and `radar-hooves/master-project` is private, so labels are applied at creation time by the `/git-issue` skill instead.
