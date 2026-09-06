---
paths:
  - '**/internal/attest/**'
  - '**/cmd/signet/**'
---

# Attest Boundary

signet is the machine-identity client of one broker's attestation contract: it proves possession of a hardware key, and every authorisation decision stays on the broker. This is signet's corollary of the broker-black-box invariant in `rules-library/sidekick/sidekick-tooling.md`; the broker repo carries the verification side, and an invariant it depends on is never weakened here unilaterally.

- Must speak only `POST /v1/attest/{challenge,token,renew}` (`attestFresh`, `renewBearer` in `internal/attest/attest.go`) plus the public consumer vend door `GET /v1/credentials/{name}` used by `verify`, `headers`, `vend-to-file` and `exec`; no other broker endpoint, sidecar, helper process or PKCS#11 module.
- Must NOT depend on a broker module, copy broker code, or reimplement any broker-side step (challenge issuance, signature verification, bearer minting, scope evaluation); the broker is a black-box HTTP service.
- Must NOT add allow/deny, scope-checking or entitlement logic. A 401 is the broker exercising its authority; the only response is to re-attest (`Auth`, `internal/attest/auth.go`), never to widen access.
- Must keep `canonicalMessage` (`"{challenge_id}.{nonce}"`) byte-for-byte aligned with the broker's `canonical_message()`; a change on either side is coordinated and cross-repo. Sign through the backend-agnostic `Signer` interface, never a specific backend.
- Must NOT reintroduce a broker-brand prefix for any flag, env var or path, nor an ambient environment variable; configuration is per-subcommand flags and the data dir is `~/.signet`.
- Must keep `auth` single-shot: emit one `{"Authorization":"Bearer <key>"}` line to stdout and exit, diagnostics on stderr, no daemon, socket, background refresher or keepalive. A near-expiry bearer is renewed within 30 minutes of expiry; a 401 or a past-max-lifetime bearer triggers a fresh attest. `auth --agent` still emits once; only the signing hop goes via the agent, which never speaks to the broker.
