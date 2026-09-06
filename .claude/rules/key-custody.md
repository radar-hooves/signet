---
paths:
  - '**/internal/signer/**'
  - '**/internal/agent/**'
  - '**/internal/datadir/**'
  - '**/internal/attest/cache.go'
  - '**/cmd/signet/**'
---

# Key Custody

A non-exportable signing key sealed in secure hardware is signet's entire reason to exist. These invariants govern how it is born, held and never degraded.

- Must NOT export, serialise, copy or log the private key: only the public half (SPKI DER, base64, via `marshalSPKI`) and signatures leave a backend, and the agent serves pubkey and sign operations only (`internal/agent/server.go`).
- Must NOT add a software, file or in-memory key backend, or a degraded mode that signs without secure hardware. `New` and `autoDetect` (`internal/signer/signer.go`) resolve to exactly one hardware backend or return an error.
- Must keep on-disk state to exactly two files: the bearer cache under `~/.signet/cache/` (mode 0600, atomic write, keyed by broker URL AND the enrolled key's fingerprint, 16 hex of SHA-256(SPKI DER), so a re-enrolled key never serves a bearer minted for the old one; `internal/attest/cache.go`) and, on macOS, the opaque machine-bound Secure Enclave blob at `~/.signet/se-<identity>.key` (0600 under a 0700 dir). TPM and PIV write no key file.
- Must keep the Secure Enclave backend keychain-free, on the self-stored blob: keychain persistence needs the `com.apple.application-identifier` entitlement and fails on the unsigned binaries `make build` produces (`errSecMissingEntitlement`).
- Must keep `enrol` print-only, idempotent and non-destructive: it prints the public key for the operator to paste into the broker, returns an existing key rather than clobbering it, and never auto-registers or trusts on first use. The agent has no enrol op; `enrol --agent` only reads the slot's existing public key.
