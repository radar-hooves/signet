# Configuration

signet is configured through per-subcommand flags, plus one environment variable (`SIGNET_IDENTITY`) that sets one flag's default. For the commands themselves see [usage.md](usage.md).

## Flags (accepted on every subcommand)

### --identity

Names which key to sign as — the **local label of a keypair**, exactly like the filename you give an SSH key. Defaults to `$SIGNET_IDENTITY` if set, else `consumer`.

This is why the flag exists. A single machine can hold more than one consumer (say a sidecar service and a separate vend client), and each needs its own distinct keypair so the broker can tell them apart. Without a name there would be a single anonymous key per machine; with it you can have two consumers on one host, each with its own key and its own broker enrolment.

The name is **purely local. It never crosses the wire to the broker.** signet sends the broker only the key's public half; the broker identifies a consumer by that public key, not by the name chosen locally. Renaming an identity does not change the key; it just looks in a different file.

Characters outside `[a-zA-Z0-9._-]` are normalised to underscores in the derived filename, so `my/service` resolves to `my_service.key`.

### --key

Overrides the key file path directly, instead of deriving it from `--identity`. Useful when a consumer wants to name the file itself rather than by identity, or when the key lives outside the default tree.

## Environment variables

`SIGNET_IDENTITY` sets `--identity`'s default on every subcommand that accepts it. Precedence:

1. The flag, if passed — always wins.
2. `SIGNET_IDENTITY`, if set to a non-empty value.
3. The built-in default, `consumer`.

An unset, or explicitly-empty, environment variable changes nothing. This exists for a host that must name its identity once, in its own declared environment, rather than on every invocation — a stdio consumer whose launcher args are a literal array (not a shell command line) can substitute one whole token from one env var, but cannot build up a per-invocation flag pair the way a shell string can.

## On-disk paths

| Path | Mode | What it holds |
| --- | --- | --- |
| `$XDG_CONFIG_HOME/portcullis/<identity>.key` (`~/.config/portcullis/<identity>.key` when `XDG_CONFIG_HOME` is unset) | `0600` | The P-256 private key, PKCS8 PEM. `<identity>` is the value of `--identity` (default `consumer`). |
| `~/.signet/cache/<sanitised-url>_<keyfingerprint>.json` | `0600` | A short-lived bearer token. |

The key path is deliberately the same one the household's `vend-token.py` script already reads and writes, so a key enrolled by either tool is usable by the other.

The bearer cache is keyed by the broker URL and the enrolled public key's fingerprint (the first 16 hex characters of SHA-256 over the SPKI DER public key), so re-enrolling a new key for the same broker never serves a stale bearer minted for the old key. signet reuses a cached bearer until it nears expiry, renews it within 30 minutes of expiry, and re-attests from scratch if renewal is rejected. Deleting a cache file simply forces a fresh attestation on the next `auth`.
