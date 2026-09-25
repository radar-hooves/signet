# Usage

signet is a machine-identity attest client. It holds a P-256 key in a PKCS8 PEM file, signs a broker's attestation challenge with it, and exchanges that proof for a short-lived bearer token it caches and hands to consumers.

For per-subcommand flags, on-disk paths, and identity selection see [configuration.md](configuration.md).

## How it works

```text
  enrol   ──▶  signet mints the key (if absent) and prints its PUBLIC half (SPKI DER, base64).
               You paste it into the broker once. The private half never leaves the key file.

  auth    ──▶  signet asks the broker for a challenge, signs it, exchanges the signature
               for a short-lived bearer, caches it, and prints an
               {"Authorization":"Bearer …"} header. Re-runs reuse the cache and renew
               as the token ages.
```

`auth` is a credential helper, the same shape as `git credential`, `docker-credential-*`, and AWS's `credential_process`. A consumer (an MCP client, a script, a service) calls it on demand to get a fresh auth header; it never holds a standing secret of its own. signet makes no authorisation decision; every challenge issuance, signature verification, and bearer minting is the broker's.

## Commands

```text
signet enrol   [--identity <name>] [--key <path>]
signet sign    [--identity <name>] [--key <path>] <message>
signet auth    [--identity <name>] [--key <path>] <broker-url>
signet verify  --broker <url> [--credential <name>] [--identity <name>] [--key <path>]
signet headers --broker <url> --credential <name> [--header <name>] [--format bearer|raw] [--identity <name>] [--key <path>]
signet vend-to-file --broker <url> [--field <name>] [--mode <octal>] [--print-shape] [--identity <name>] [--key <path>] <name> <dest>
signet exec    --broker <url> --credential <name> --env-var <NAME> [--field <name>] [--identity <name>] [--key <path>] -- <command> [args...]
signet doctor  [--identity <name>] [--key <path>]
signet version
```

### enrol

```text
signet enrol
```

Mints the key file if absent and prints its public half (SPKI DER, base64) to stdout for one-time enrolment with the broker. You paste that value into the broker once; the private half never leaves the file.

`enrol` is non-destructive and idempotent: it reads an existing key rather than overwriting it, so running it again prints the same public key.

### sign

```text
signet sign <message>
```

Signs `<message>` and prints a base64 IEEE P1363 (`r||s`) ECDSA P-256 signature over SHA-256 of the message to stdout. This is for testing or bespoke flows; the routine path is `auth`, which signs the broker's challenge for you.

### auth

```text
signet auth [--identity <name>] [--key <path>] <broker-url>
```

Runs the full attestation flow against the broker at `<broker-url>`: requests a challenge, signs it with the selected key, exchanges the signature for a short-lived bearer, caches that bearer, and prints a compact `{"Authorization":"Bearer <token>"}` header to stdout.

The broker resolves the calling consumer by its enrolled public key (the SSH `authorized_keys` model); no identity id is presented or required. `--identity` selects which local key signs the challenge (defaults to `consumer`); `--key` overrides the file path directly.

The canonical message signed is `{challenge_id}.{nonce}`; signet speaks only the `/v1/attest/{challenge,token,renew}` HTTP contract.

Re-runs reuse the cache and renew the bearer as it ages: a cached token still more than 30 minutes from expiry is reused as-is; within 30 minutes of expiry signet renews it; a `401` on renew (or a token past its maximum lifetime) triggers a fresh attestation. A cached bearer the broker refuses at the vend door (`401`) is likewise discarded, re-attested once, and the vend retried. `403`, `404` and `429` are the broker's settled answers and are never retried. The cache is keyed by broker URL and the enrolled public key's fingerprint (the first 16 hex characters of SHA-256 over the SPKI DER public key), so re-enrolling a new key for the same broker never serves a stale bearer minted for the old key.

Concurrent processes finding a cold cache single-flight through an advisory lock on the cache file: one mints, the rest wait and then read what it wrote, so a session's worth of processes needing the same bearer cost one attestation between them. A waiter gives up after 30 seconds — long enough for one real mint, so a wait still inside it is ordinary contention — and proceeds to mint its own rather than block forever; that case is reported on stderr rather than swallowed, since the lock being held that long means the holder is stuck, not merely slow.

## Wiring signet as a credential helper

A credential helper is a small program a consumer shells out to whenever it needs a fresh credential, instead of the consumer holding a standing secret of its own. `auth` fits that contract exactly: it prints an `Authorization` header on stdout and exits, and the consumer captures that output. There is no daemon, socket, or keepalive; signet runs once per request and exits, like `git credential` or AWS's `credential_process`.

For a Claude Code MCP `http` server, wire `auth` as the `headersHelper`:

```json
{
  "mcpServers": {
    "broker": {
      "type": "http",
      "url": "https://broker.example.internal/mcp",
      "headersHelper": "signet auth https://broker.example.internal"
    }
  }
}
```

The bearer refreshes at each (re)connect: Claude Code re-runs the helper, and signet serves the cached bearer (renewing or re-attesting as needed). The same pattern works for any consumer that can shell out for an `Authorization` header; the MCP `headersHelper` is one instance of the general credential-helper contract, not a signet-specific feature.

### verify

```text
signet verify --broker <url> [--credential <name>] [--identity <name>] [--key <path>]
```

`verify` is the consumer pre-flight command. It runs the full attestation round-trip against the broker and, if `--credential` is supplied, probes whether the enrolled identity has vend scope for that credential. It is designed to be called from a health check, a CI gate, or a deployment script to confirm the machine is correctly enrolled before doing real work.

`verify` prints a short diagnostic table to stdout and exits with a typed exit code:

| Code | Meaning |
| --- | --- |
| `0` | Success: attestation accepted; credential resolvable (if `--credential` given). |
| `1` | Unexpected transport or argument error. |
| `2` | Key missing: no key enrolled for this identity. |
| `3` | Attestation rejected: the broker answered and refused this key (4xx) — not enrolled for this identity, or too many challenges pending for this key: retry in a moment (today's broker body cannot distinguish the two). |
| `4` | Credential out of scope: the identity is attested but the credential is not in its vend scope (403). |
| `5` | Credential not found: the credential name is absent from the broker's catalogue (404). |

Example output (successful attestation, credential probed):

```text
signet verify — broker: https://broker.example.internal

  key              OK             key present
  attest           OK             bearer minted
  credential my-cred      OK             resolvable

result: OK
```

Example for a machine not yet enrolled:

```text
signet verify — broker: https://broker.example.internal

  key              FAIL           no key enrolled: software: no enrolled key at ~/.config/portcullis/consumer.key; run 'signet enrol' first
```

### headers

```text
signet headers --broker <url> --credential <name> [--header <name>] [--format bearer|raw] [--bare] [--identity <name>] [--key <path>]
```

`headers` is the vend-to-headers credential helper: it runs the same attestation round-trip as `verify`, then vends `--credential` from the broker and prints it — by default as a compact JSON HTTP header line, the shape a `.mcp.json` `headersHelper` (or any `credential_process`-style consumer) captures directly. Unlike `verify`, which only probes whether a credential _would_ resolve, `headers` returns the credential's actual value, so it is not a diagnostic; it is the header-producing call itself.

The vended credential must resolve to a single-field static value: `material.kind` must be `static`, and `material.fields` must hold exactly one field. A `session` credential, or a static credential with zero or more than one field, is a typed refusal rather than a guess at which field to print — `headers` never chooses on the caller's behalf.

Two independent flags shape the output. `--format` shapes the **value**: `bearer` (default) emits `Bearer <value>`, `raw` emits `<value>` alone. `--bare` shapes the **framing**: without it (default) the value is wrapped in a compact-JSON object keyed by `--header` (default `Authorization`); with it, the value is printed alone. They compose:

| Flags                 | stdout                              |
| --------------------- | ------------------------------------ |
| _(default)_           | `{"Authorization":"Bearer s3cr3t"}` |
| `--format raw`        | `{"Authorization":"s3cr3t"}`        |
| `--bare`              | `Bearer s3cr3t`                     |
| `--bare --format raw` | `s3cr3t`                            |

The JSON framings are the `headersHelper` contract and remain the default. Reach for `--bare` when interpolating into a shell command: a JSON-wrapped value substituted into `curl -H "Authorization: Bearer $v"` builds a **malformed header**, and the server rejects it with a 401 or 403 that is indistinguishable from a stale or revoked credential. Note that `--format raw` alone does _not_ do this — it removes the `Bearer ` prefix but keeps the JSON object; `--bare` is the flag that removes the framing.

`--header` names the JSON key, so it has no meaning under `--bare` (which prints no key). Combining them is refused rather than silently ignored.

Under `--bare` only, a credential whose value contains a carriage return, newline, or NUL byte is refused as unusable material (exit `6`) rather than printed. The default JSON framing escapes such a value instead, and is unchanged.

The credential value only ever lands on stdout, as the one line `headers` prints on success. Every diagnostic and every failure message goes to stderr instead, and never contains the credential value or the minted attestation bearer.

A locked vault (423) is its own class, distinct from "not found": nothing about the credential's existence is known while the vault is locked, so reporting it as a 404 sends the reader hunting a catalogue the broker never even consulted (radar-hooves/mcp-servers#868). Any other non-2xx status prints the raw status and the broker's own `error`/`detail` fields.

`headers` exits with a typed code:

| Code | Meaning                                                                                              |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0`  | Success: the header line was printed to stdout.                                                      |
| `1`  | Unexpected transport or argument error.                                                              |
| `2`  | Key missing: no key enrolled for this identity.                                          |
| `3`  | Attestation rejected: the broker refused the attestation (4xx).                                      |
| `4`  | Credential out of scope: the identity is attested but the credential is not in its vend scope (403). |
| `5`  | Credential not found: the credential name is absent from the broker's catalogue (404).               |
| `6`  | Unusable material: the credential is not a single-field static value.                                |
| `7`  | Vault locked: the broker's vault is locked (423) — catalogue membership is unknown.                  |
| `8`  | Broker error: the broker answered the vend with an unexpected non-2xx status.                        |

Example (a static, single-field credential named `example-api`):

```text
$ signet headers --broker https://broker.example.internal --credential example-api
{"Authorization":"Bearer sk_live_abc123..."}
```

With `--header` and `--format raw` — note the JSON object remains:

```text
$ signet headers --broker https://broker.example.internal --credential example-api --header X-Api-Key --format raw
{"X-Api-Key":"sk_live_abc123..."}
```

With `--bare`, for interpolating into a shell command:

```text
$ signet headers --broker https://broker.example.internal --credential example-api --bare
Bearer sk_live_abc123...

$ signet headers --broker https://broker.example.internal --credential example-api --bare --format raw
sk_live_abc123...

$ v=$(signet headers --broker https://broker.example.internal --credential example-api --bare --format raw)
$ curl -H "Authorization: Bearer $v" https://api.example.internal/v1/thing
```

### vend-to-file

```text
signet vend-to-file --broker <url> [--field <name>] [--mode <octal>] [--print-shape] [--identity <name>] [--key <path>] <name> <dest>
```

`vend-to-file` runs the same attestation round-trip as `verify` and `headers`, then vends `<name>` from the broker and writes one field's value straight to `<dest>` — atomically, at mode `0600` by default — instead of printing it. It exists for consumers that need a credential placed at a file (a `.env`, an `.envrc.local`, a stack secret sink) without the value ever passing through a shell pipeline, a log, or an LLM transcript.

Unlike `headers`, which only understands a single-field `static` credential, `vend-to-file` also understands `session` material:

- **`static`** — the sole field's value if the credential has exactly one field; `--field <name>` selects among two or more (or overrides a single field) by exact name match. A name that does not exist, or an ambiguous multi-field credential with no `--field`, is a typed refusal that names the available field _names_ — never a value.
- **`session`** — always the `access_token` field; `--field` is not consulted. A cookie-only session with no `access_token` is a typed refusal naming the gap, never a guess at which cookie to write.

`--mode` sets the destination's file mode as an octal string (default `0600`). `--print-shape` prints only the credential's `kind` and field names — never a value — and writes no file; use it to see what a credential offers before choosing `--field`. `--field` is ignored when `--print-shape` is set: the shape is printed before any field is resolved, so no file is written either way.

The write is atomic: a temp file is created in `<dest>`'s own directory, written, fsynced, and chmoded, then renamed over `<dest>` only once every prior step has succeeded. On any failure `<dest>` is left exactly as it was — never created, never partially written — and no temp file is left behind.

The only line `vend-to-file` prints on success is a non-secret confirmation, e.g. `wrote 42 bytes to /etc/myapp/token (mode 0600)`. Every diagnostic and every failure message goes to stderr instead, and never contains the credential value or the minted attestation bearer.

A locked vault (423) is its own class, distinct from "not found" (radar-hooves/mcp-servers#868); any other non-2xx status prints the raw status and the broker's own `error`/`detail` fields. `<dest>` stays untouched on every one of these, exactly as on the pre-existing failure classes.

`vend-to-file` exits with a typed code:

| Code | Meaning                                                                                              |
| ---- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `0`  | Success: `<dest>` was written (or, with `--print-shape`, the shape was printed).                     |
| `1`  | Unexpected transport, argument, or filesystem error.                                                 |
| `2`  | Key missing: no key enrolled for this identity.                                          |
| `3`  | Attestation rejected: the broker refused the attestation (4xx).                                      |
| `4`  | Credential out of scope: the identity is attested but the credential is not in its vend scope (403). |
| `5`  | Credential not found: the credential name is absent from the broker's catalogue (404).               |
| `6`  | Unusable material: the credential cannot be resolved to a single field's value.                      |
| `7`  | Vault locked: the broker's vault is locked (423) — catalogue membership is unknown.                  |
| `8`  | Broker error: the broker answered the vend with an unexpected non-2xx status.                        |

Example (a static, single-field credential named `example-api`, default mode):

```text
$ signet vend-to-file --broker https://broker.example.internal example-api /etc/myapp/token
wrote 42 bytes to /etc/myapp/token (mode 0600)
```

Selecting one field of a multi-field static credential, and a stricter mode:

```text
$ signet vend-to-file --broker https://broker.example.internal --field password --mode 0640 db-creds /etc/myapp/db.pass
wrote 18 bytes to /etc/myapp/db.pass (mode 0640)
```

Inspecting a credential's shape before choosing `--field`:

```text
$ signet vend-to-file --broker https://broker.example.internal --print-shape db-creds /etc/myapp/db.pass
kind: static
fields: username, password
```

### exec

```text
signet exec --broker <url> --credential <name> --env-var <NAME> [--field <name>] [--identity <name>] [--key <path>] -- <command> [args...]
```

`exec` runs the same attestation round-trip as `verify`, `headers`, and `vend-to-file`, then vends `--credential` from the broker, resolves one value out of it exactly the way `vend-to-file` does (see the field-resolution rules under [vend-to-file](#vend-to-file)), sets `--env-var` to that value in a **child process's** environment, and replaces the current process with `<command>` — so the value goes straight from the broker into the child's environment and never touches signet's own shell, an env var in the calling session, a file, or an LLM transcript.

It exists for **stdio MCP servers** and any other child that reads a credential from its environment at start-up. `headers` solves the equivalent problem for an `http` MCP server's `headersHelper`; `vend-to-file` solves it for a consumer that reads a file; neither helps a stdio server, because Claude Code's `.mcp.json` has no `envHelper` equivalent — the credential has to be in the environment _before_ the process is spawned.

The `--` terminator is required and separates signet's own flags from the child's: everything after it is `<command>`'s argv, untouched by signet's flag parser. Omitting `--`, or leaving nothing after it, is a usage error.

`exec` replaces the current process with `<command>` via `syscall.Exec` (the `execve(2)` system call) rather than spawning a subprocess signet then waits on: no signet process is left holding the value in memory, and the child's stdio and signal handling are exactly what they would have been had it been launched directly. **`exec` prints nothing to stdout on success** — stdout belongs to `<command>`'s own protocol from the moment it starts. The vended value is never placed in argv either, so it never appears in `ps` output.

`syscall.Exec` has no equivalent on Windows (there is no `execve()`); `exec` still builds there, but the launch step itself fails at runtime with an ordinary transport-style error. `exec` is unix-only in practice today.

Every diagnostic and every failure message goes to stderr, and never contains the credential value or the minted attestation bearer. A locked vault (423) is its own class, distinct from "not found" (radar-hooves/mcp-servers#868); any other non-2xx status prints the raw status and the broker's own `error`/`detail` fields — the child is never launched on either.

`exec` exits with a typed code:

| Code | Meaning                                                                                                       |
| ---- | ------------------------------------------------------------------------------------------------------------- |
| `0`  | Success — never actually observed: `syscall.Exec` replaces this process, so nothing is left to return a code. |
| `1`  | Unexpected transport, argument, or exec failure.                                                              |
| `2`  | Key missing — no key enrolled for this identity.                                                  |
| `3`  | Attestation rejected — the broker refused the attestation (4xx).                                              |
| `4`  | Credential out of scope — the identity is attested but the credential is not in its vend scope (403).         |
| `5`  | Credential not found — the credential name is absent from the broker's catalogue (404).                       |
| `6`  | Unusable material — the credential cannot be resolved to a single field's value.                              |
| `7`  | Command not found — `<command>` could not be resolved to an executable via `PATH`.                            |
| `8`  | Vault locked — the broker's vault is locked (423); catalogue membership is unknown.                           |
| `9`  | Broker error — the broker answered the vend with an unexpected non-2xx status.                                |

Example — launch a stdio MCP server with a broker-vended token in its environment, without the token ever touching the calling shell:

```text
$ signet exec --broker https://broker.example.internal --credential github-pat \
    --env-var GITHUB_PERSONAL_ACCESS_TOKEN -- github-mcp-server stdio
```

The `github-mcp-server` process starts with `GITHUB_PERSONAL_ACCESS_TOKEN` set in its own environment; nothing was printed and no `signet` process remains.

### doctor

```text
signet doctor [--identity <name>] [--key <path>]
```

`doctor` probes the key file at the identity/key selection and reports whether it is present and readable. It is the first thing to run when setting up a new machine or diagnosing a failure.

Example output:

```text
signet doctor — platform: darwin/arm64

  software   OK             key present, mode -rw-------, fingerprint a1b2c3d4e5f60718
```

Example when no key has been enrolled:

```text
signet doctor — platform: darwin/arm64

  software   UNAVAILABLE    no key at /Users/paul/.config/portcullis/consumer.key; run 'signet enrol' first
```

`doctor` exits `0` if the key is present and readable, and `1` otherwise.

### version

```text
signet version
```

Prints the signet version, platform, and Go runtime. The format is:

```text
signet v2026.9.6 darwin/arm64 (go1.25.10)
```
