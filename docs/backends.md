# Hardware backends

signet compiles in three backends and selects one at runtime: Apple Secure Enclave, a TPM 2.0, or a YubiKey/PIV token. The CLI and the attestation client are written against a small `Signer` interface (its two methods are `Enrol` and `Sign`) and never against a specific backend, so the identity model and the broker contract are identical across all three substrates. Switching hardware is a one-flag change: `--backend secure-enclave`, `--backend tpm`, or `--backend piv`.

For how a backend is chosen and the on-disk paths each writes, see [configuration.md](configuration.md); for the commands themselves see [usage.md](usage.md).

## Comparison

| Backend | Library | OS | Build-tagged? | Persists | Status |
| --- | --- | --- | --- | --- | --- |
| **Secure Enclave** | CryptoKit/Swift shim via cgo | macOS | Yes (`//go:build darwin`) | An opaque, hardware-wrapped key blob at `~/.signet/se-<identity>.key` | Proven end-to-end on an unsigned ad-hoc binary (enrol + sign + verify). |
| **TPM 2.0** | `github.com/google/go-tpm` (pure Go) | Linux, Windows | No | Default identity: nothing on disk (key at a fixed TPM handle). Named identity: an opaque, TPM-wrapped key blob at `~/.signet/tpm-<identity>.key` | Proven end-to-end against the go-tpm software simulator (enrol + sign + verify; two named identities enrol distinct keys and cross-verify correctly). |
| **YubiKey / PIV** (slot 9c) | `github.com/go-piv/piv-go/v2` (cgo, PC/SC) | macOS, Linux, Windows | No | Nothing on disk (key on the token) | Builds and format-verified; real-hardware validation pending a physical key. |

Only the Secure Enclave backend sits behind a build tag, because it links a macOS-only Swift shim; TPM and PIV compile on every platform.

## Secure Enclave (macOS)

The Secure Enclave backend uses CryptoKit's self-stored-key-blob model (the same approach as [`age-plugin-se`](https://github.com/remko/age-plugin-se)). `signet enrol` asks CryptoKit to create a P-256 key inside the Secure Enclave; the Enclave returns an opaque, hardware-wrapped key blob, which signet stores in a file (`~/.signet/se-<identity>.key`, mode `0600`). The `<identity>` is the value of `--identity` (default `consumer`), so one Mac can hold more than one identity: the name is the local label of the keypair (the SSH-keyfile model), and each name maps to its own blob and so its own public key — which is what keeps two consumers on one Mac distinct to the broker. The name is local-only and never sent to the broker; see [configuration.md](configuration.md#--identity).

The keychain is never touched. Because the keychain is bypassed, **no `com.apple.application-identifier` entitlement and no code signature are needed**. The old keychain path required that entitlement and failed on unsigned binaries with `-34018 errSecMissingEntitlement`; the blob path avoids it entirely. Notarisation is irrelevant; it is a Gatekeeper distribution gate, not a runtime Secure-Enclave gate. The blob is bound to this Mac's Enclave and is useless if copied to another machine.

`enrol --user-presence` is Secure-Enclave-only: it gates each signature behind Touch ID or the device passcode, which suits an interactive identity rather than an unattended one.

## TPM 2.0 (Linux/Windows)

The TPM backend is pure Go (`go-tpm`), so it cross-compiles freely and links no C. On Linux, signet opens the resource-manager device `/dev/tpmrm0`, falling back to the raw device `/dev/tpm0` if the resource manager is unavailable. On Windows it reaches the TPM through TBS (the TPM Base Services).

This is the auto-detected backend on Linux and Windows whenever a TPM device is reachable; if none is, signet falls back to PIV.

### Identity model: one fixed key, plus one blob per named identity

The **default identity** (`consumer` — an omitted `--identity`, or the value `consumer` given explicitly) is unchanged from before named identities existed: an ECDSA P-256 key lives at the fixed persistent handle `0x81010001` (owner hierarchy), and nothing is written to disk. This is the identity every already-enrolled TPM host has; the fix for [#12](https://github.com/radar-hooves/signet/issues/12) never touches it, so an enrolled host is not broken by upgrading.

**Any other `--identity`** gets its own key, born under a deterministic ECC storage primary (`tpm2.ECCSRKTemplate`, the TCG reference template — `CreatePrimary` reproduces the bit-identical key on the same TPM every time, given the same template and an unchanged owner-hierarchy seed, so there is nothing to persist for it) via `TPM2_Create`. `TPM2_Create` returns the new key already wrapped — encrypted under that primary — so the blob signet writes to `~/.signet/tpm-<identity>.key` (`0600` under a `0700` directory, matching the Secure Enclave convention exactly) is opaque and loadable, via `TPM2_Load`, only by re-deriving the same primary on the _same_ TPM. The private key is never in the clear outside the TPM at any point: `Load` decrypts it into the TPM's own protected memory, and only a signature ever comes back out.

This is a deliberate choice over the other option the issue named — several persistent handles, one per identity, keyed by some name→handle mapping. A real TPM has very few persistent-object slots (often single digits), a scarce resource shared with anything else the host provisions into the TPM; consuming one per broker consumer does not scale to "one identity per consumer or tier" the way an unbounded number of files does. The blob-per-identity model also needs no handle-allocation bookkeeping — the identity name _is_ the filename, exactly like Secure Enclave — and "forgetting" an identity is deleting its file, no `EvictControl` required.

A named identity's `PublicKeyDER` and `Sign` error — they never create a key — when no blob file exists yet: enrolment stays a deliberate, separate act, exactly like the Secure Enclave and PIV backends. (The default identity keeps its original, different behaviour: `Sign`/`PublicKeyDER` on it create the key at the fixed handle if it is not already there, unchanged from before named identities existed.)

## YubiKey / PIV (cross-platform)

The PIV backend talks to a YubiKey (or any PIV token) over PC/SC via `go-piv`, so it links C (cgo) and works on macOS, Linux, and Windows alike. The signing key is an EC P-256 key in the selected slot (default `9c`, the Digital Signature slot; override with `--slot`); it lives on the token, and nothing is written to disk. `signet enrol` reads an existing key in the chosen slot if one is present (for example a `ykman`-provisioned key) rather than overwriting it. Each PIV slot holds an independent keypair, so one YubiKey can root multiple distinct identities. Writing a new key into an empty slot is gated by the card's management key: `enrol` tries the factory default first (a card still on defaults just works) and, if that is refused, falls back to prompting for the PIV PIN at an interactive terminal to retrieve a management key held on-card under PIN protection (`ykman piv access change-management-key --protect`). The PIN is never taken from a flag, env var, or file, and signing never touches the management key — see [usage.md](usage.md#enrol).

The key is configured `PINPolicyNever` / `TouchPolicyNever`, so signing requires no PIN entry and no touch. That makes it suitable for an unattended consumer, but it means there is no per-signature presence gate on the PIV backend; physical custody of the token is the control. (The Secure Enclave backend is the one that offers an optional presence gate, via `enrol --user-presence`.)

## No software fallback

There is no software-key fallback, by design. A host with no secure hardware genuinely cannot produce a hardware-rooted identity, so signet fails loudly rather than quietly degrading to a key on disk. The whole point of the tool is that "this identity is hardware-rooted" is never a claim that is sometimes false; a silent software fallback would reintroduce exactly the at-rest secret the tool exists to eliminate. If auto-detection finds no usable hardware, the answer is to add hardware (a TPM, a YubiKey) or pick a backend explicitly with `--backend`, not to fall back.

## Security model

- **Non-exportable key, per substrate.** The signing key is generated in hardware and never leaves it: the Secure Enclave returns only an opaque hardware-wrapped blob; the TPM key stays at its persistent handle; the PIV key stays in slot 9c on the token. In all three cases the private key never appears in a file, an env var, a log, or `argv`.
- **What persists.** signet holds no long-lived secret. The only persistent state is the short-lived bearer cache (all backends) and, on macOS, the Enclave's opaque, machine-bound key blob. The blob is useless if copied off the machine, because only this Mac's Enclave can unwrap it. The TPM and PIV backends write nothing to disk but the bearer cache. Deleting the cache simply forces a re-attestation.
- **Replay resistance.** A signature proves possession of the hardware key for one specific challenge: signet signs the broker's canonical `{challenge_id}.{nonce}` message, so a captured signature cannot be replayed against a different challenge. The bearer it earns is short-lived and scoped to one broker and one identity.
- **Enrolment is the trust anchor.** The public key you enrol is what the broker verifies every future signature against. Enrolment is a deliberate, operator-mediated act (you paste the public key into the broker once), not trust-on-first-use; there is no moment where signet's first contact is implicitly trusted.
- **No authorisation decisions in signet.** signet proves which machine it is and nothing more. Every challenge issuance, signature verification, bearer minting, and vend-scope decision is the broker's; on a `401` signet's only response is to re-attest, never to widen its own access.
