# signet

Hardware-rooted signing CLI: one self-contained Go binary that proves _which machine_ you are, using a non-exportable P-256 key sealed in whatever secure hardware the host has (Apple Secure Enclave, TPM 2.0, or YubiKey/PIV). It is a machine-identity credential helper for a secrets broker — it signs the broker's `/v1/attest` challenge in hardware and trades the proof for a short-lived bearer. Broker-agnostic: any service implementing the attest contract can consume it. The shape is AWS IAM Roles Anywhere, generalised across the three secure-hardware substrates a real fleet has.

## Scope

These are deliberate boundaries, not gaps — the code shows what is present, never what is deliberately absent and why.

- **Vendors no broker code and makes no authorisation decision.** signet proves possession of a hardware key; the broker alone issues challenges, verifies signatures, mints bearers, and fixes vend scope. It speaks the `/v1/attest/*` HTTP contract (plus the public `/v1/credentials/{name}` vend door) and nothing more — no sidecar, no PKCS#11 module. Detail: `.claude/rules/attest-boundary.md`.
- **Never falls back to a software key.** A host without secure hardware fails loudly rather than degrading to a key on disk, so "hardware-rooted" is never a claim that is sometimes false. No key at rest: the only on-disk state is a short-lived bearer cache and, per named `--identity`, an opaque hardware-wrapped blob (Secure Enclave on macOS; TPM, for any identity but the original unnamed one). Detail: `.claude/rules/key-custody.md`.
- **A thin credential helper, not a framework.** The protocol half (challenge → sign → token → renew) is deliberately small and specific to one broker's contract. SPIRE, mTLS meshes, and full PKI are heavier answers to a problem a single broker does not have — do not grow it into one.
- **Single-shot, not resident.** Every subcommand runs once and exits, like `git credential` / `docker-credential-*` / AWS `credential_process`. The lone long-lived mode is `agent`, which owns the hardware for socket clients and serves pubkey/sign only, never touching the broker.

## Building

```bash
make build   # macOS: xcrun swiftc compiles internal/signer/enclave.swift into libsignet_se.a, then CGO_ENABLED=1 go build links it; other platforms: just the cgo go build
make test    # CGO_ENABLED=1 go test ./...
```

- cgo means **per-platform native builds**: the SE and PIV backends cannot be cross-compiled. Plain `go build` on macOS fails to link unless `internal/signer/libsignet_se.a` exists — always `make build`.
- Only the Secure Enclave backend sits behind a build tag (it links a macOS-only Swift shim). TPM and PIV must compile on every platform; do NOT add a build tag that drops a backend from the default build.
- The go-tpm software simulator (test-only) is behind the `tpmsimulator` build tag so its OpenSSL dependency stays out of normal builds.

## Sources of truth

- **Broker contract**: the `/v1/attest` HTTP API (any broker implementing it). Household attestation architecture: `docs/master/governance/secrets/`.
- **Architecture, backends, config, usage**: `docs/backends.md`, `docs/configuration.md`, `docs/usage.md`. Product intent (gitignored): `docs/product/`.

## CI deviations from the household standard

- **No `auto-label-issues` caller.** `rules-library/core/ci-workflow-standard.md` permits a public repo that cannot resolve the private master-project reusable to omit the caller provided the omission is recorded. signet is public and `radar-hooves/master-project` is private, so labels are applied at creation time by the `/git-issue` skill instead.
