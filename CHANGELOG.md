# Changelog

All notable changes to signet will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/), and this project adheres to calendar-based versioning (YYYY.M.x).

## [Unreleased]

## [2026.9.5] - 2026-09-25

### Changed

- **signet is now a single software backend.** The Secure Enclave, TPM 2.0 and PIV backends, and the `agent` socket daemon that served them, are removed; every consumer identity is now a P-256 private key in a PKCS8 PEM file, mode `0600`. `--backend`, `--slot`, `--agent` and every hardware-specific flag are removed — an invocation still passing one now fails fast, naming the flag, rather than being silently ignored. `--identity` stays: it names the key file, defaulting to `$XDG_CONFIG_HOME/portcullis/<identity>.key` (`~/.config/portcullis/consumer.key` by default), the same path and format the household's `vend-token.py` already reads and writes, so a key enrolled by either tool is usable by the other. A new `--key` flag overrides the path directly. `enrol` mints the key file when absent (never overwriting an existing one) and prints the same SPKI DER base64 public key shape as before, so the broker enrolment contract is unchanged; `sign`, `auth`, `verify`, `headers`, `vend-to-file`, `exec` and their output contracts and exit codes are unchanged; `doctor` now reports the key file's presence, mode and public-key fingerprint instead of hardware availability. The bearer cache, the cross-process lock, `vend-to-file` and the vend-failure classification are unchanged. This is the household's move away from hardware-rooted machine identity (operator ruling, 25/09/2026): signet is now a plain Go binary — no cgo, no per-platform native build, cross-compiles freely — and both release targets (`linux/amd64`, `darwin/arm64`) build from one runner.

## [2026.9.4] - 2026-09-24

### Fixed

- A transient PC/SC sharing violation on the PIV backend is now retried instead of failing outright.

## [2026.9.3] - 2026-09-24

### Added

- `--backend`, `--slot` and `--identity` now default to `SIGNET_BACKEND`, `SIGNET_SLOT` and `SIGNET_IDENTITY` when the flag is absent, on every subcommand that accepts them; a passed flag always wins, and an unset (or explicitly-empty) env var leaves the built-in default (auto-detect / `9c` / `consumer`) unchanged. A Claude Code stdio MCP server's `args` are a literal array, not a shell command line: it can substitute one whole token from one env var, as `--identity ${SIGNET_EXEC_IDENTITY:-github-mcp}` already does for backend/identity, but it cannot splat a host-only, PIV-only `--slot <n>` pair into an array shared by every host, some of which (the Macs) have no slot to name — and an empty per-token `--slot ${SIGNET_SLOT:-}` breaks argument parsing there. Measured 24/09/2026 on atlas: the shared `.mcp.json`'s `github` and `aws` stdio entries had no way to carry atlas's PIV slot at all, so both landed on the wrong enrolled identity and the broker refused them. A host now names its backend/slot/identity once, in its own declared environment (a fleet-provisioned Claude Code `env` block, not a shell profile).

### Fixed

- The broker-rejected-attestation hint (`verify`, `headers`, `vend-to-file`, `exec`) no longer names "this key is not enrolled" as the cause of a 401 with confidence it does not have. Portcullis caps pending challenges at ten per key and mints a throwaway challenge past the cap so the token leg answers the SAME body (`{"error":"unauthenticated","detail":"attestation failed"}`) whether the key genuinely is not enrolled or the cap was hit — deliberate, to preserve the no-enumeration-oracle property, but it makes the two causes indistinguishable from the response alone today. Measured 2026-09-14 on atlas: one `nixos-rebuild switch` started 17 concurrent `signet vend-to-file` processes against one key, the cap refused the other seven, every key was enrolled, and a one-second wait would have cleared it — but the hint sent the reader hunting an enrolment problem that did not exist. The hint now quotes the broker's own `error`/`detail` fields and names both live causes ("not enrolled for this identity, or too many challenges pending for this key: retry in a moment") instead of picking one. `docs/usage.md`'s exit-3 row is reworded to match.

## [2026.9.2] - 2026-09-13

### Added

- The TPM backend now holds more than one identity per machine, closing the gap that had the fleet's first TPM-rooted host (mimir) take a YubiKey instead ([#12](https://github.com/radar-hooves/signet/issues/12)). `--identity` now behaves identically across the Secure Enclave and TPM backends: an omitted value or an explicit `consumer` keeps the TPM's original behaviour unchanged (a key at the fixed persistent handle `0x81010001`, nothing on disk), so an already-enrolled host is not broken by upgrading. Any other name gets its own key, born under a deterministic ECC storage primary (`tpm2.ECCSRKTemplate`, reproduced bit-for-bit on the same TPM every time so it is never itself persisted) and wrapped by `TPM2_Create` into an opaque blob at `~/.signet/tpm-<identity>.key` — the same on-disk file model Secure Enclave already uses, chosen over spending one of a real TPM's scarce persistent-object slots per identity. `signet agent --bind <socket>=<key>` now routes `<key>` as a PIV slot under `--backend piv` or a named identity under `--backend tpm`/`secure-enclave`, so one TPM host can serve one socket per broker consumer, each bound to its own identity, exactly as the fleet's `signet-agent` NixOS module already binds one socket per consumer on a YubiKey. Proven end to end against the go-tpm software simulator: two named identities enrol to distinct keys, each signs, and each signature verifies only against its own public key.

## [2026.9.1] - 2026-09-10

### Fixed

- `headers`, `exec`, and `vend-to-file` no longer report a locked broker vault (423) as `credential "<name>" not found in catalogue (404)`. All three folded every credential-vend status that was not 403 or 404 into a bare `unexpected broker %d`, but the 404 branch above it had no default guard, so a 423 read as "credential not found" whenever its numeric value happened to satisfy neither dedicated case first — sending the reader hunting a catalogue the broker had never even consulted, since the vault being locked means catalogue membership is unknown, not absent. `verify`, hitting the same locked broker, already reported it correctly (`unexpected broker 423: ...`) because its fallback branch prints the status and body for anything it has no dedicated wording for; the three helpers now share that shape through one classifier (`classifyVend`/`vendBrokerDetail` in the new `internal/attest/vendfailure.go`) instead of three hand-maintained copies. A locked vault is now its own typed exit (`7` for `headers`/`vend-to-file`, `8` for `exec` — `7` there is already `ExitExecCommandNotFound`), and any other non-2xx status gets a further distinct exit (`8`/`9` respectively) printing the raw status and the broker's own `error`/`detail` JSON fields rather than folding into the generic transport-error exit `1`, so a caller can branch on "the vault is locked" without parsing text. `docs/usage.md`'s exit-code tables are extended to match. Found via a foreman lane on radar-hooves/mcp-servers#868, which had gone credential-catalogue hunting on the strength of the wrong message.
- `headers`, `vend-to-file`, and `exec` now carry the same local-not-an-outage hint `verify` already printed on a broker-rejected attestation (401): a bare `broker rejected attestation: ... 401` read exactly like a broker fault and sent the reader diagnosing the wrong system, when the usual cause is local — the default identity's key not enrolled for the broker in use. One shared `attestRejectedHint()` is now printed by all four commands after their own failure line, naming both key-selection flags (`--identity` for the Secure Enclave key, `--slot` for PIV) instead of `--identity` alone, so the wording is accurate on every backend. Regression tests pin the hint's presence on each command's attest-rejected output.

## [2026.9.0] - 2026-09-01

### Fixed

- `golang.org/x/crypto` is bumped v0.52.0 → v0.55.0, clearing CVE-2026-56854 (GO-2026-6303, CRITICAL) from the released binary. The advisory is against `golang.org/x/crypto/ssh`: the `source-address` critical option in the `Permissions` an authentication callback returns was enforced only on the `PublicKeyCallback` and `VerifiedPublicKeyCallback` paths, so a source-address restriction set by `PasswordCallback`, `KeyboardInteractiveCallback`, `NoClientAuthCallback` or `GSSAPIWithMICConfig.AllowLogin` was silently ignored — an authentication bypass, and a widening of CVE-2026-46595. signet does not import `x/crypto/ssh` and never has: `x/crypto` is an indirect dependency reached only through `go-piv`'s use of `x/crypto/cryptobyte`, so the vulnerable symbols are not in the call graph and no signet behaviour changes. That unreachability is not the point. Trivy's `gobinary` scanner reports at MODULE granularity off the linked module list a Go binary carries in its own metadata, so the module's presence is the finding regardless of which packages were linked, and because the advisory has a fixed version, `ignore-unfixed: true` does not drop it. The consumer-visible effect is that `poodle64/godswood`'s `Build and Push Docker Image` workflow failed on every commit to `main` on 2026-09-01 (runs 33461462885, 33462036999, 33462598760): its Trivy `CRITICAL` gate correctly refused the signet binary baked into the production image, so the app could not build and therefore could not reach the broker at all.
- This is the same shape as #11 one release ago and is closed the same way — by fixing the artefact, never by waiving the scanner. No `.trivyignore`, no severity waiver, no `--exit-code 0`: a gate that is taught to ignore this class stops being able to report the next one. Verified before tagging rather than after: the PUBLISHED v2026.8.4 `linux-amd64` binary was downloaded and scanned (`trivy rootfs --scanners vuln --severity CRITICAL,HIGH --ignore-unfixed`), reproducing exactly one finding — CVE-2026-56854, CRITICAL, `v0.52.0`, fixed in `0.55.0` — and confirming that #11's seven HIGH stdlib advisories are genuinely gone, so v2026.8.4's `check-latest` fix worked and the toolchain is not implicated this time. The same source tree with the bump, built `linux/amd64` under cgo on Go 1.25.14 exactly as the release workflow builds it, scans to zero findings and gates green. Runtime linkage (`libc`, `libpcsclite.so.1`) and the CLI surface are byte-for-byte what v2026.8.4 shipped. Bump only; no source change to the tool itself.

## [2026.8.4] - 2026-08-27

### Fixed

- The release and CI workflows now set `check-latest: true` on `actions/setup-go`, so a build actually picks up Go security patches. Without it setup-go keeps the runner image's preinstalled toolchain whenever it satisfies the spec, so the floating `go-version: '1.25'` silently stopped floating and pinned itself to whatever the image shipped. This is why v2026.8.2 — cut for no reason other than to rebuild v2026.8.1 on a patched toolchain, and whose release notes say exactly that — produced another Go 1.25.12 binary and left #11's seven HIGH stdlib advisories precisely where they were; v2026.8.3 then did the same. Go 1.25.13 (the fix release) and 1.25.14 had both been available for some time. The consumer-visible effect is unchanged behaviour and a binary that passes a Trivy `CRITICAL,HIGH` scan with `ignore-unfixed: true` again, which is what `poodle64/godswood` needs to keep signet in its production image and reach the broker at all. No source change to the tool itself. (#11)

## [2026.8.3] - 2026-08-27

### Fixed

- A bearer the broker refuses at the credential-vend door is now discarded and re-attested once, and the vend retried, instead of being handed back as `unexpected broker 401`. A cached bearer can be dead well before its local expiry: the broker deletes the old key when a renew rotates it (`rotate_key` inserts the new and deletes the old in one transaction), so a process that read the cache moments before another renewed it holds a key the broker no longer knows. Nothing local said so — the cached copy still looked fresh, so it was handed out until it entered the 30-minute renew window, and the SAME dead key was presented on every invocation until then. Five refusals inside fifteen minutes trip the broker's per-key auth-failure lock, at which point EVERY credential that identity vends answers `429` until the window rolls: one stale bearer takes out the whole identity. Measured 2026-08-27 on a live fleet — two unrelated credentials locked out together, neither of them the one whose renew had rotated the key, and the broker's own logs showed 92 rotations in six hours against nine `unknown consumer key` refusals. The broker's lock is documented against a consumer that "occasionally presents an old key before rotating", which is exactly what signet was not doing; this makes that assumption true. `15-attest-boundary.md` §3 already held that a 401 is the broker exercising its authority and the only response is to re-attest — that was implemented on the renew leg and in `auth`, but the vend door (§1's one bounded exception) never got it. The recovery is bounded to a single retry, is single-flighted through the same cache lock so a session's worth of processes recovering from one rotation costs one attestation between them, and takes the replacement another process has already minted where there is one. `403`, `404` and `429` are passed through untouched — they are the broker's settled answers about scope, catalogue membership and load, and a retry on `429` would compound the very lock this closes. Adds no flag, config surface or on-disk artefact: overwriting the cache IS the invalidation.
- `verify` no longer reports a purely local invocation problem as a broker fault. `--identity` resolves to the backend's own default key when unset (`consumer` on the Secure Enclave), so a bare `signet verify --broker <url>` on a host whose enrolled identities are each named for their consumer attests with a key the broker has never seen, and the broker correctly answers 401. The line printed for that read `broker rejected attestation: … broker 401 …` — naming the broker three times for a local enrolment problem — and it was twice escalated as a broker outage in one night, once with a warning that other consumers might be affected. It is the third instance of this message class in the estate; `poodle64/master-project#184` records the YubiKey-absent case with the same diagnosis, that the error "names the broker for what is entirely a local backend problem". The line now leads with the fact that settles it (the broker ANSWERED and refused this key), and two lines under it classify the cause as local and name the lever, `--identity`. Wording only: the classification itself was already in the code — a `*BrokerError` in the wrap chain has always separated a refusal from a transport failure — so this adds no flag, config surface, subcommand, or broker lookup, and the success path is byte-identical. `docs/usage.md`'s exit-3 row for `verify` is reworded to match, and its key-missing example corrected: it showed a stale error string and a `result:` line `verify` has never printed.
- `enrol` on the PIV backend now writes a new key into a card whose management key has been rotated, not only a card still on the factory default. Key generation is gated by the management key (signing is not — every slot is `PIN required for use: NEVER`), and enrolment assumed the default key as a constant, so the moment the card's key was changed no new identity could ever be added. `enrol` now tries the factory default first — a card still on defaults works exactly as before, which is load-bearing because the change has to land before the card is rotated — and, if that write is refused with an authentication error (`security status not satisfied`, or a retry-counted `piv.AuthErr`), falls back to retrieving the card-held management key via `Metadata(pin)` and retrying with it. This is the household's chosen card shape: the management key held on-card under PIN protection (`ykman piv access change-management-key --protect`). The one operation that now needs the PIN — enrolment — is attended and rare, so the PIN is never stored: it is typed once, at an interactive terminal, with echo disabled, and is deliberately not accepted from a flag, environment variable, or file (which would reintroduce the standing credential the design avoids). If stdin is not a terminal — the unattended container case — enrolment fails fast with a distinct, diagnosable error naming the interactive flow, rather than blocking forever on a PIN read; a hang inside a container is the worst failure mode here. Only two cases are supported, factory default and PIN-protected-on-card, keeping the operator's rotation runbook to one command. No change to the signing path: `sign`, `auth`, `headers`, `verify`, `vend-to-file`, and `exec` continue to work with no PIN, preserving unattended container signing. The rotated-card path awaits a manual run against the live card before it is rotated — that run is the verification gate for poodle64/portcullis#155 step 1. (poodle64/signet#9)

## [2026.8.1] - 2026-08-14

### Fixed

- Every subcommand now resolves its bearer through the disk cache, single-flighted across processes. Only `auth` consulted the cache; `headers`, `exec`, `vend-to-file` and `verify` each called `attestFresh` directly, so every invocation cost a full three-leg attestation (challenge, hardware signature, token) no matter how recently one had been minted. That is invisible for a lone credential helper and severe for the shape signet is actually deployed in: a Claude Code session starts every gate-served MCP server at once, and each runs its own `headersHelper` process. Measured on a 26-server project — 26 concurrent attestations, a median 12s and a worst case of 29s to return one header, and the broker correctly shedding load with `429 rate_limited` on `attest/challenge` and 401s on `attest/token`. Claude Code reported the resulting failures as `Incompatible auth server: does not support dynamic client registration` against every server in the project, which points at OAuth discovery and not at the credential helper, so the real cause survived several sessions. A warm cache now costs zero broker round-trips, a bearer inside the 30-minute renew window takes the one-round-trip renew leg, and concurrent callers finding a cold cache produce ONE attestation between them (an advisory `flock` on the cache file itself — no third on-disk artefact, per key custody). Locking is an optimisation, never a correctness gate: a caller that cannot take the lock still proceeds, so a platform without `flock` degrades to the previous behaviour rather than blocking.

## [2026.8.0] - 2026-08-13

### Fixed

- `headers` accepts `session` material carrying an `access_token`, instead of refusing it with exit 6 (`unusable material (kind "session", want static)`). It already resolved a single `static` field and nothing else, while `vend-to-file` and `exec` had both been widened to the shared `resolveField` — whose own docstring names "headers.go's single-static-field assumption" as the thing it goes beyond. `headers` now uses that same resolution, so all three subcommands agree on what a credential resolves to. A cookie-only session (no `access_token`) is still exit 6, and multi-field or zero-field static material is unchanged: the refusal names the shape and never a value, as before. The practical effect is that Portcullis's whole `produced` credential class — an OAuth bearer the broker mints from a vaulted `client_id`/`client_secret` and renews behind its own vend door — was unreachable over a `.mcp.json` `headersHelper`, which is the one transport a hosted MCP server can use. A broker that had minted a perfectly good bearer answered "unusable material", which reads as a broken credential rather than a missing feature in the caller, so the gap cost real diagnosis time before it was recognised as one. Found while giving the household's MCP gate a machine-authentication path (poodle64/yggdrasil#208).

## [2026.7.3] - 2026-07-17

### Added

- `exec` subcommand — the vend-and-exec helper for consumers that need a broker-vended credential in an **environment variable before a child process starts**, which neither `headers` (an HTTP header) nor `vend-to-file` (a file) can provide: a stdio MCP server reads its credential from its own environment at start-up, and Claude Code's `.mcp.json` has no `envHelper` equivalent to `headersHelper`. Without `exec`, the only option was a secret-shaped environment variable sitting in the calling session — inherited by every child process and readable by anything that can read that process's environment (e.g. `printenv`), the exact leak shape `exec` exists to close (poodle64/master-project#184). Performs the same attestation and credential-vend legs as `headers` and `vend-to-file`, resolves one value out of the material with the same `resolveField` widening `vend-to-file` uses (a single or `--field`-selected static field, or a session's `access_token`), builds the child's environment as the current process environment with `--env-var` set to the vended value (replacing, never duplicating, any pre-existing entry of that name), and replaces the current process with `<command>` via `syscall.Exec` — true process-image replacement, not a forked subprocess: no signet parent is left holding the value in memory, no extra PID sits between Claude Code and the launched server, and the child's stdio and signals pass through untouched, which matters because a stdio MCP server speaks its protocol on file descriptors 0 and 1. Command form is `signet exec [flags] --broker <url> --credential <name> --env-var <NAME> [--field <name>] -- <command> [args...]`; the `--` terminator is required and everything after it is the child's argv, never parsed as a signet flag. Nothing is ever printed to stdout on success (stdout belongs to the child's own protocol from the moment it starts, unlike `headers` and `vend-to-file`, which each print one confirmation line), and the vended value is never placed in argv, so it is never visible to `ps`. Every diagnostic and failure message goes to stderr and never contains the credential value or the minted bearer. Exit codes extend the sibling vocabulary: 0 success (never actually observed — `syscall.Exec` replaces the process), 2 key missing, 3 attestation rejected, 4 credential out of scope, 5 credential not found, 6 unusable material, and a new 7 for command-not-found (`<command>` could not be resolved to an executable via `PATH`). `syscall.Exec` has no Windows equivalent (the standard library's own Windows implementation is a stub that always fails); `exec` still builds there but the launch step fails at runtime, so it is unix-only in practice today.
- `headers --bare` — prints the credential value alone instead of wrapping it in a compact-JSON object, for interpolating into a shell command. `--bare` and `--format` are independent axes and compose: `--format` shapes the VALUE (`bearer` prefixes `Bearer `, `raw` does not), `--bare` shapes the FRAMING (JSON object keyed by `--header`, or the value alone). The four shapes are `{"Authorization":"Bearer <v>"}` (default), `{"Authorization":"<v>"}` (`--format raw`), `Bearer <v>` (`--bare`), and `<v>` (`--bare --format raw`). The JSON default is unchanged and remains the `.mcp.json` `headersHelper` contract, so existing consumers are unaffected. This closes a silent trap: a JSON-wrapped value substituted into `curl -H "Authorization: Bearer $v"` builds a malformed header, and the server rejects it with a 401/403 that is indistinguishable from a stale or revoked credential — a failure that misdiagnosed two live credentials as stale across two sessions. `--header` names the JSON key and so has no meaning under `--bare`; combining them is refused rather than silently ignored. (poodle64/signet#5)
- `signet headers --help` (and `-h`) now prints the subcommand's own reference — usage line, flags, the output shape of every mode with a worked `curl` example, and the exit-code table — instead of only Go's bare auto-generated flag list. The shapes are rendered from the same single source the top-level `signet --help` embeds, so the two cannot drift. (poodle64/signet#5)

### Fixed

- `headers --format raw` was documented as printing "the bare value" in `--help`, in `docs/usage.md`, and in the flag's own description, but it has always emitted `{"Authorization":"<value>"}` — the JSON object, minus only the `Bearer ` prefix. The behaviour is unchanged (it is the pre-existing contract) and is now described accurately wherever it appeared; `--bare` is the flag that actually removes the framing. (poodle64/signet#5)
- `headers --bare` refuses a credential whose value carries a CR, LF, or NUL (exit 6, unusable material) rather than printing it. `--bare` is the only output path with no escaping — the JSON framing escapes such a value and stays on one line — and it exists to be interpolated into a header unquoted, so an embedded CRLF was a header-injection and request-splitting vector, and an embedded newline silently broke the single-line output `--bare` advertises. No HTTP field value may contain these (RFC 9110), so such material cannot become one header value. The refusal names the offending control character and never the value. The default JSON path is deliberately unchanged. (poodle64/signet#5)

## [2026.7.2] - 2026-07-16

### Added

- `vend-to-file` subcommand — the vend-to-file helper for consumers that need a broker-vended credential placed at a file (a `.env`, an `.envrc.local`, a stack secret sink) instead of an HTTP header, without the value ever passing through a shell pipeline, a log, or an LLM transcript. Performs a fresh attestation each run (matching `headers`) followed by the same credential-vend leg, then writes ONE field's value atomically to `<dest>` at mode `0600` by default (`--mode` overrides): a temp file is created in `<dest>`'s own directory, written, fsynced, and chmoded, then renamed over `<dest>` only once every prior step has succeeded — on any failure `<dest>` is left exactly as it was, never created and never partially written. Widens material handling beyond `headers`' single-static-field assumption: a `static` credential with more than one field requires `--field <name>` to disambiguate (an ambiguous credential with no `--field`, or a `--field` naming an absent field, is a typed refusal naming the available field _names_, never a value); a `session` credential always resolves its `access_token` field, and a cookie-only session with no `access_token` is a typed refusal naming the gap. `--print-shape` prints only the credential's `kind` and field names — never a value — and writes no file, for inspecting a credential's shape before choosing `--field`. The only line printed to stdout on success is a non-secret byte-count confirmation; every diagnostic and failure message goes to stderr and never contains the credential value or the minted bearer. Exit codes extend `headers`' vocabulary: 0 success, 2 key missing, 3 attestation rejected, 4 credential out of scope, 5 credential not found, 6 unusable material. (poodle64/portcullis#107)

## [2026.7.1] - 2026-07-10

### Added

- `headers` subcommand — the vend-to-headers helper for Claude Code's `.mcp.json` `headersHelper` contract. Performs a fresh attestation each run (deliberately no bearer-cache reuse: always-fresh proof of possession, matching `verify`) followed by `verify`'s credential-vend leg: it attests to a broker (`--broker`), vends a named credential (`--credential`), and prints ONE compact-JSON header line to stdout — `{"Authorization":"Bearer <value>"}` by default, or `{"<name>":"<value>"}` with `--header <name>` and `--format raw`. The credential must resolve to `static` material with exactly one field; anything else (a `session` credential, or zero/multiple static fields) is a typed refusal, never a partial print. Exit codes extend `verify`'s vocabulary: 0 success, 2 key missing, 3 attestation rejected, 4 credential out of scope, 5 credential not found, 6 unusable material. Like `verify`, its output never contains the minted bearer, and on failure it never contains the credential value.

## [2026.7.0] - 2026-07-04

### Added

- `verify` subcommand — consumer pre-flight with typed exit codes. Runs the attestation round-trip against a broker (`--broker`) and optionally probes a credential vend (`--credential`), then exits 0 (success), 2 (no key enrolled), 3 (attestation rejected), 4 (credential out of vend scope), or 5 (credential not in the catalogue), so callers branch on the exact failure mode instead of one opaque "unauthorised". Its output never contains the minted bearer or a credential value.
- `doctor --backend <name>` probes a single backend instead of all three, and an unknown backend name is now rejected instead of silently ignored.
- Branding: `docs/branding/` carries the monochrome signet-ring wordmark and monogram (single ink `#111111`, geometry-only marks, monospace wordmark) with a canonical-colour reference; the README header now uses the wordmark.
- CI test gate (`.github/workflows/ci.yaml`): gofmt, go vet, and the full test suite run on every pull request and push to main, natively on both release platforms.

### Changed

- **Repository layout**: the flat root package is now the standard Go CLI shape — `cmd/signet/` plus `internal/signer` (backends), `internal/attest` (broker client, bearer cache, auth/verify), `internal/agent` (daemon and socket client), and `internal/datadir`. The Swift Secure-Enclave shim lives at `internal/signer/enclave.swift` and its build products stay inside that package directory. Build and install interfaces are unchanged (`make build`, `make test`, same release artifacts).
- CLI polish: `version` no longer doubles the `go` prefix (`(go1.25.10)`, not `(go go1.25.10)`); `-h`/`--help` on a subcommand exits 0 after printing the flag list instead of exit 1 with `error: flag: help requested`; missing-argument errors share one shape (`signet <subcommand>: a <thing> argument is required`); `verify` transport errors are reported once, not twice; help-text columns align and the `82..95` slot range is labelled as hex.
- Broker rejections are classified by a typed error carrying the HTTP status instead of matching on message text (no wire or exit-code change).
- Release workflow: failure notifications post directly to ntfy (the private composite action can never resolve on this public repo), and `actions/checkout` is pinned at v7.0.0.
- Documentation truth-up: the bearer cache is keyed by broker URL plus the enrolled key's fingerprint (not an identity name); configuration is flags-only with no environment variables; the `agent` daemon is documented as the deliberate long-lived counterpart to the single-shot credential-helper flows; usage now covers all seven subcommands.

### Fixed

- Homebrew formula `test do` block asserted behaviour that no longer exists (no-argument invocation exiting 1 with lowercase `usage` on stderr); it now asserts the real contract — help on stdout exit 0, unknown subcommand exit 1.

## [2026.6.6] - 2026-06-29

### Added

- `agent` subcommand — an own-the-token, sign-on-request daemon for workloads that cannot reach the hardware directly (a container with no pcscd socket / no path to the YubiKey). One process owns the single-access token and serves a Unix socket per `--bind <socket>=<slot>`; each socket is pinned to one slot, so a client can only ever sign with that socket's key (the slot is never taken from a request). Hardware access is serialised across bindings; the agent answers only "return the public key" and "sign", and never generates or overwrites a key. The `ssh-agent` / SPIRE node-agent / HSM-proxy pattern.
- `--agent <socket>` flag on `sign`, `enrol`, and `auth` — forwards signing and public-key reads to a running agent instead of opening local hardware. Attestation is resolve-by-public-key, so the broker is unaffected by how the signature was produced. (poodle64/signet#3)

## [2026.6.5] - 2026-06-28

### Added

- `version` subcommand — prints the signet version, platform, and Go runtime.
- `doctor` subcommand — preflight check of the signing environment (backend availability and hardware reachability), with platform-specific probes.
- `help` subcommand and `-h` / `--help` — usage for every subcommand.

### Changed

- Documentation truthed-up to a finished-product state (README, usage, configuration, and backends guides); added CONTRIBUTING.md and SECURITY.md.

## [2026.6.4] - 2026-06-25

### Changed

- **The CLI is flag-driven; the `SIGNET_BACKEND`, `SIGNET_PIV_SLOT`, and `SIGNET_IDENTITY` environment variables are removed.** Backend, PIV slot, and Secure-Enclave identity are now selected by `--backend`, `--slot`, and `--identity`, accepted on every subcommand — e.g. `signet auth --backend piv --slot 9a <broker-url>`. **Breaking:** callers that configured signet through the environment must pass the equivalent flags (an embedding consumer passes them per invocation). `--backend` still falls back to platform auto-detect when omitted; `--slot` defaults to `9c`; `--identity` defaults to `consumer`. Explicit per-invocation selection is self-documenting and removes the ambient-environment footgun — a single exported `SIGNET_PIV_SLOT` would have forced every consumer on a host onto one slot, hence one identity.

## [2026.6.3] - 2026-06-25

### Added

- PIV (YubiKey) backend: `SIGNET_PIV_SLOT` selects the signing slot per identity — `9a`, `9c`, `9d`, `9e`, or a retired key-management slot `82`–`95`; unset defaults to `9c` (back-compat). Each PIV slot holds an independent keypair and the broker resolves identity by public key, so one YubiKey now roots **multiple distinct identities — one per slot, up to ~24** — instead of only the single slot-9c identity. This is what makes a single token viable for a multi-consumer host: e.g. an admin identity on `9a` enrolled alongside a warming identity on `9c`, each with its own scope. `enrol` provisions the chosen slot's key (default management key) on first use. Validated on a real YubiKey 5: `9c` and `9a` enrol independent, individually-stable keys; the unset default stays `9c`; an invalid slot is rejected. A gated hardware regression test (`TestPIV_HW_MultiSlot_DistinctStableKeys`) guards it.

## [2026.6.2] - 2026-06-25

### Fixed

- PIV (YubiKey) backend: `enrol` now persists and re-reads its slot-9c key correctly. `pivPublicKey` decided whether a key existed by probing the slot's X.509 **certificate** — which `GenerateKey` never writes — so every `enrol` regenerated a fresh key (a different public key each call) and `sign`/`PublicKeyDER` reported an empty slot. It now reads the key directly via go-piv `KeyInfo` (firmware ≥ 5.3.0), falling back to the attestation certificate's key for older firmware. First end-to-end enrol → attest → sign was validated against a real YubiKey 5; the PIV path had no hardware round-trip test before, only software backend-selection tests, which is why this shipped.

### Added

- Hardware round-trip regression test (`signer_piv_hw_test.go`, gated behind `SIGNET_PIV_HW_TEST=1`): asserts two consecutive `enrol` calls return the same SPKI and that a `sign` output verifies against the enrolled public key.

## [2026.6.1] - 2026-06-24

### Changed

- `signet auth` no longer takes an identity-id argument; the form is now `signet auth <broker-url>`. The broker resolves the calling consumer by its enrolled public key (resolve-by-key, the SSH `authorized_keys` model) rather than by a presented id, so a consumer holds no identity id at all. `SIGNET_IDENTITY` still selects which local hardware keypair signs the challenge. This is a breaking change to the `auth` invocation for any consumer that previously passed an id.

### Fixed

- Corrected stale `~/.signet` path references in a packaging comment and a test (the Secure-Enclave key blob lives under the platform data dir, not `~/.signet`).

### Documentation

- Rewrote the README to the household standard and added usage, configuration, backend, and building guides.
- Documented `SIGNET_IDENTITY` as the local keypair selector (the SSH-keyfile model).

## [2026.6.0] - 2026-06-22

First public release. signet was split out of the broker's repository into its own standalone repository and published. This is the first release installable without repository access.

### Added

- Cross-platform hardware-rooted signing CLI in a single self-contained Go binary, with three backends compiled in and selected at runtime — TPM 2.0 (pure Go, `go-tpm`), YubiKey/PIV slot 9c (`go-piv`, cgo/PC-SC), and Apple Secure Enclave (CryptoKit shim linked via cgo). The backend is chosen by `SIGNET_BACKEND` or auto-detected.
- `enrol`, `sign`, and `auth` subcommands. `auth` implements the credential-helper contract (attest → cache → emit an `Authorization` header), compatible with the Claude Code `headersHelper` and the same shape as `git`/`docker`/AWS `credential_process` helpers.
- Secure Enclave backend that works on an **unsigned** binary via CryptoKit's self-stored-key-blob model — the Enclave's wrapped key blob is stored in a file, the keychain is never touched, and no code-signing entitlement or notarisation is required.
- A bearer cache keyed by broker URL **and** identity, renewing as the token ages.
- Homebrew formula and a nix (`fetchurl` + SRI) derivation for installing the per-platform release binary.
- A per-platform release workflow (darwin/arm64, linux/amd64).
