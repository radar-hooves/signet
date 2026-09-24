# Configuration

signet is configured through per-subcommand flags, plus three environment variables (`SIGNET_BACKEND`, `SIGNET_SLOT`, `SIGNET_IDENTITY`) that set those flags' defaults. For the hardware backends themselves see [backends.md](backends.md); for the commands see [usage.md](usage.md).

## Flags (accepted on every subcommand)

### --backend

Selects the hardware backend.

- **Values:** `secure-enclave` (aliases `enclave`, `se`), `tpm`, `piv`.
- **Default:** `$SIGNET_BACKEND` if set, else auto-detection (see [Backend selection](#backend-selection)).
- **Effect:** overrides auto-detection; an unrecognised value is an error rather than a silent fallback.

Switching hardware is a one-flag change: `--backend secure-enclave`, `--backend tpm`, or `--backend piv` — not a reconfiguration or a migration.

### --slot

Selects the PIV signing slot. Accepted values: `9a`, `9c`, `9d`, `9e`, or a retired key-management slot `82`–`95`. Defaults to `$SIGNET_SLOT` if set, else `9c` (Digital Signature slot). Ignored on non-PIV backends. Each slot holds an independent keypair, so one YubiKey can root multiple distinct identities — one per slot, each with its own public key and its own broker enrolment.

### --identity

Names which hardware keypair to sign as — the **local label of a keypair**, exactly like the filename you give an SSH key. Defaults to `$SIGNET_IDENTITY` if set, else `consumer`.

This is why the flag exists. A single machine can hold more than one consumer (say a sidecar service and a separate vend client), and each needs its own distinct keypair so the broker can tell them apart. Without a name there would be a single anonymous key slot per machine; with it you can have two consumers on one host, each with its own key and its own broker enrolment.

The name is **purely local. It never crosses the wire to the broker.** signet sends the broker only the key's public half; the broker identifies a consumer by that public key, not by the name chosen locally. Renaming an identity does not change the key; it just looks in a different file (Secure Enclave, TPM) or a different slot (PIV).

Honoured by the **Secure Enclave and TPM** backends. Secure Enclave names the on-disk key blob (`se-<identity>.key`); TPM names its own on-disk key blob (`tpm-<identity>.key`) for any identity except the default (`consumer`), which keeps signet's original behaviour — a key at the TPM's fixed persistent handle, nothing on disk — so an already-enrolled TPM host is unaffected by upgrading. Characters outside `[a-zA-Z0-9._-]` are normalised to underscores in either backend's filename, so `my/service` produces `se-my_service.key` or `tpm-my_service.key`. The **PIV backend ignores it**: its key lives in a PIV token slot (`--slot`), so a YubiKey holds one identity per slot instead.

### --user-presence

Secure-Enclave-only. Gates each subsequent signature behind Touch ID or the device passcode. Suits an interactive identity; on TPM and PIV this flag has no effect. Accepted only on `enrol`.

## Environment variables

`SIGNET_BACKEND`, `SIGNET_SLOT` and `SIGNET_IDENTITY` set `--backend`, `--slot` and `--identity`'s default on every subcommand that accepts them (`enrol`, `sign`, `auth`, `verify`, `headers`, `vend-to-file`, `exec`, `doctor`, and `agent`'s own `--backend`). Precedence, per flag, independently:

1. The flag, if passed — always wins.
2. The environment variable, if set to a non-empty value.
3. The built-in default (auto-detect, `9c`, `consumer`).

An unset, or explicitly-empty, environment variable changes nothing. This exists for a host that must name its backend/slot/identity once, in its own declared environment, rather than on every invocation — a stdio consumer whose launcher args are a literal array (not a shell command line) cannot splat a `--slot <n>` pair into an argument list shared by hosts that have no PIV slot to name, but it can carry a host-scoped environment block.

## Backend selection

signet resolves the backend in this order:

1. **`--backend` flag.** If passed, its value wins (`secure-enclave` / `enclave` / `se`, `tpm`, or `piv`). An unrecognised value is rejected.
2. **`SIGNET_BACKEND`**, if set to a non-empty value.
3. **Auto-detect** (when neither is set):
   - **macOS** uses the Secure Enclave.
   - **Linux and Windows** use the TPM if a TPM device is reachable, otherwise fall back to PIV.
   - **Anything else** uses PIV.

There is no software-key fallback at any step; a host with no secure hardware fails loudly rather than degrading to a key on disk (see [backends.md](backends.md#no-software-fallback)).

## On-disk paths

All of signet's persistent state lives under a single dotfolder, `~/.signet` (directory mode `0700`). signet holds no long-lived secret; the only things it writes are the short-lived bearer cache, the Secure Enclave's opaque key blob, and a named TPM identity's opaque key blob.

| Path | Mode | Backend | What it holds |
| --- | --- | --- | --- |
| `~/.signet/se-<identity>.key` | `0600` | Secure Enclave | The Enclave's opaque, hardware-wrapped key blob. `<identity>` is the value of `--identity` (default `consumer`). |
| `~/.signet/tpm-<identity>.key` | `0600` | TPM (named identity only) | A TPM-wrapped key blob (`TPM2_Create`'s encrypted private area plus its public area), loadable only by the TPM that created it. Never written for the default identity (`consumer`), which stays at the fixed persistent handle instead. |
| `~/.signet/cache/<sanitised-url>_<keyfingerprint>.json` | `0600` | all | A short-lived bearer token. |

The Secure Enclave blob is the Enclave's own machine-bound, hardware-wrapped key material; it is useless if copied to another machine, because only this Mac's Enclave can unwrap it. A named TPM identity's blob is the same idea on a different substrate: it is opaque, encrypted material the TPM alone can decrypt, and useless if copied to a different TPM.

The bearer cache is keyed by the broker URL and the enrolled public key's fingerprint (the first 16 hex characters of SHA-256 over the SPKI DER public key), so re-enrolling a new key for the same broker never serves a stale bearer minted for the old key. signet reuses a cached bearer until it nears expiry, renews it within 30 minutes of expiry, and re-attests from scratch if renewal is rejected. Deleting a cache file simply forces a fresh attestation on the next `auth`.

**The TPM backend's default identity and the PIV backend persist nothing on disk** beyond the bearer cache. Their signing key lives inside the hardware (the TPM's fixed persistent handle, or a PIV token slot), so there is no on-disk key blob to protect; the only file either writes is the bearer cache above. A **named** TPM identity is the exception: see the row above.
