<div align="center">

<img src="docs/branding/wordmark.svg" alt="signet" width="360">

_The key that proves which machine you are; sealed in hardware, exportable to no one._

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/) [![Release](https://img.shields.io/github/v/release/radar-hooves/signet?style=flat-square)](https://github.com/radar-hooves/signet/releases/latest) [![Licence](https://img.shields.io/badge/Licence-MIT-blue?style=flat-square)](LICENSE)

One self-contained Go binary that gives a machine a hardware-rooted signing identity and trades a signed challenge for a short-lived bearer token — on whichever secure hardware the host has.

[Installation](#installation) · [Quickstart](#quickstart) · [Backends](#backends) · [Documentation](#documentation) · [Contributing](#contributing)

</div>

## What is signet?

A machine that needs secrets has to prove it is itself before a broker will hand anything over. The robust way to do that is a non-exportable key sealed in hardware: the machine signs a challenge, the broker verifies the signature against a public key it enrolled once, and issues a short-lived credential. No long-lived secret sits on disk, in an env var, or in a config file.

signet is a single self-contained Go binary that implements this pattern across the three secure-hardware substrates a real fleet actually has:

- **Apple Secure Enclave**: auto-detected on macOS
- **TPM 2.0**: auto-detected on Linux and Windows with a reachable TPM device
- **YubiKey / PIV token**: cross-platform fallback, or explicit with `--backend piv`

The backends are compiled in and selected at runtime; switching hardware is a one-flag change, not a migration. The private key never leaves the hardware. The only thing on disk is a short-lived bearer cache and, for a named `--identity`, an opaque key blob (Secure Enclave, or TPM) useless if copied off the machine.

signet acts as a standard credential helper, the same shape as `git credential`, `docker-credential-*`, and AWS `credential_process`. A consumer shells out for a fresh `Authorization` header on demand; signet produces it and exits. For workloads that cannot reach the hardware at all (a container with no path to the YubiKey), the `agent` subcommand runs one daemon that owns the token and signs for socket clients on request — the `ssh-agent` pattern — while every other subcommand stays single-shot.

This is the same pattern AWS ships as IAM Roles Anywhere, generalised across the three secure-hardware substrates a heterogeneous fleet actually has.

## Installation

```sh
brew install radar-hooves/tap/signet
```

For Nix (home-manager / nix-darwin), a `fetchurl` + SRI derivation lives in [`nix/signet.nix`](nix/signet.nix); copy it into your config and add it to `home.packages`.

To install manually, download the per-platform tarball and checksum from the [latest release](https://github.com/radar-hooves/signet/releases/latest), verify, and put the binary on your `PATH`:

```sh
shasum -a 256 -c signet-*-*.tar.gz.sha256
tar -xzf signet-*-*.tar.gz
install -m755 signet ~/.local/bin/signet
```

## Quickstart

```sh
# Print the hardware key's public half and enrol it with the broker (once per machine)
signet enrol

# Check hardware is detected and working
signet doctor

# Attest to a broker and get a bearer header
signet auth https://your-broker.example.internal

# Consumer pre-flight: confirm attestation and credential scope
signet verify --broker https://your-broker.example.internal --credential my-secret

# Print version
signet version
```

After `enrol`, paste the printed public key into the broker. From then on `auth` is the only call a consumer makes; signet handles caching, renewal, and re-attestation automatically.

## Backends

signet auto-detects the available hardware. Pass `--backend` to override.

| Backend              | Platform              | Auto-detected?                             | `--backend` value                          |
| -------------------- | --------------------- | ------------------------------------------ | ------------------------------------------ |
| Apple Secure Enclave | macOS                 | Yes                                        | `secure-enclave` (aliases `enclave`, `se`) |
| TPM 2.0              | Linux, Windows        | Yes (if `/dev/tpmrm0` or TBS is reachable) | `tpm`                                      |
| YubiKey / PIV token  | macOS, Linux, Windows | Fallback on Linux/Windows                  | `piv`                                      |

There is no software-key fallback. A host with no secure hardware fails loudly; signet never silently degrades to a key on disk.

See [Hardware backends](docs/backends.md) for the security model, library details, and build-tag notes.

## Features

<table>
<tr>
<td width="50%"><strong>One binary, three backends</strong><br>Secure Enclave on Macs, a TPM on Linux servers, a YubiKey/PIV token anywhere; compiled in and selected at runtime, so switching hardware is a one-flag change, not a migration.</td>
<td width="50%"><strong>A credential helper, not a daemon</strong><br>The same shape as <code>git credential</code>, <code>docker-credential-*</code>, and AWS <code>credential_process</code>: a consumer shells out for a fresh bearer header on demand and holds no standing secret of its own.</td>
</tr>
<tr>
<td width="50%"><strong>Nothing exportable, nothing at rest</strong><br>The P-256 signing key is generated in hardware and never appears in a file, env var, log, or argv. The only persisted state is a short-lived bearer cache.</td>
<td width="50%"><strong>No software-key fallback, by design</strong><br>A host with no secure hardware fails loudly rather than quietly degrading to a key on disk, so "this identity is hardware-rooted" is never a claim that is sometimes false.</td>
</tr>
<tr>
<td width="50%"><strong>Consumer pre-flight (<code>verify</code>)</strong><br>Runs the full attestation round-trip and optionally probes a credential's vend scope. Exits with typed codes (0/2/3/4/5) so a health check or CI gate can branch on the exact failure mode.</td>
<td width="50%"><strong>Agent mode for container workloads</strong><br>One daemon owns the hardware token and signs on request over Unix sockets — one socket pinned to one PIV slot — so a container attests without the token ever being mounted into it.</td>
</tr>
</table>

## Wiring as a credential helper

Wire `signet auth` as the `headersHelper` in a Claude Code MCP config, or as any other `credential_process`-style helper. Backend selection is a flag:

```json
{
  "mcpServers": {
    "my-broker": {
      "type": "http",
      "url": "https://your-broker.example.internal/mcp",
      "headersHelper": "signet auth https://your-broker.example.internal"
    }
  }
}
```

To use a specific backend: `signet auth --backend piv https://your-broker.example.internal`

`auth` prints signet's own attestation bearer: the credential that proves _this machine's_ identity to the broker. Some hosted servers instead expect a **broker-vended credential**, a separate secret the broker holds on the consumer's behalf (a hosted API's bearer, an upstream service token), as their `Authorization` header. For that case wire `signet headers` instead: it attests the same way `auth` does, then vends the named credential and prints it as the header:

```json
{
  "mcpServers": {
    "example-api": {
      "type": "http",
      "url": "https://your-broker.example.internal/mcp",
      "headersHelper": "signet headers --broker https://your-broker.example.internal --credential example-api"
    }
  }
}
```

`--header` and `--format` control the emitted JSON key and value wrapping (default `Authorization` / `bearer`), and `--bare` drops the JSON framing to print the value alone; the shape to interpolate into `curl -H`, since a JSON-wrapped value builds a malformed header and earns a 401 that looks just like a stale credential. See [Usage](docs/usage.md#headers) for the full flag and exit-code reference.

Some consumers need the vended credential written to a **file** instead of an HTTP header: an agent placing a value at a destination (a `.env`, an `.envrc.local`, a stack secret sink) without it ever passing through a shell pipeline or an LLM transcript. `signet vend-to-file` attests the same way, then writes one field's value straight to disk, atomically, at mode `0600` by default:

```sh
signet vend-to-file --broker https://your-broker.example.internal example-api /etc/myapp/token
```

Nothing but a byte-count confirmation line ever reaches stdout; the credential value only ever lands in the destination file. See [Usage](docs/usage.md#vend-to-file) for `--field`, `--mode`, `--print-shape`, and the full exit-code reference.

A **stdio** MCP server needs its credential in an environment variable _before_ it even starts, and `.mcp.json` has no `envHelper` equivalent to `headersHelper`. `signet exec` closes that gap: it attests and vends the same way, sets the value as an environment variable on a child process, and replaces itself with that child, so the value goes straight from the broker into the child's own environment and never sits in the calling shell, an env var, or a file:

```sh
signet exec --broker https://your-broker.example.internal --credential github-pat \
  --env-var GITHUB_PERSONAL_ACCESS_TOKEN -- github-mcp-server stdio
```

Nothing is printed on success — the child is about to speak its own protocol on stdout — and no signet process is left running: `exec` replaces itself with `<command>` (`syscall.Exec`) rather than spawning a subprocess it waits on. See [Usage](docs/usage.md#exec) for the `--` contract and the full exit-code reference.

signet speaks the `/v1/attest` HTTP contract and nothing more; it is not coupled to any specific broker's business logic, and any secrets broker implementing the contract can consume it.

## Documentation

| Guide                                                | What it covers                                                                                                                                |
| ---------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------------------------------- |
| [Usage](docs/usage.md)                               | All ten subcommands (enrol, sign, auth, verify, headers, vend-to-file, exec, agent, doctor, version); wiring as a credential helper           |
| [Configuration](docs/configuration.md)               | Flags (--backend, --slot, --identity) and their SIGNET_BACKEND/SIGNET_SLOT/SIGNET_IDENTITY env defaults, backend selection, and on-disk paths |
| [Hardware backends](docs/backends.md)                | The Secure Enclave, TPM, and PIV backends in depth                                                                                            |
| [Building from source](docs/development/building.md) | The cgo build, the Swift shim, and the release toolchain                                                                                      |
| [Contributing](CONTRIBUTING.md)                      | Build prerequisites, per-platform constraints, test commands                                                                                  |
| [Security](SECURITY.md)                              | Reporting vulnerabilities and supported versions                                                                                              |
| Brand assets                                         | [`docs/branding/`](docs/branding/)                                                                                                            |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for build prerequisites and the per-platform native-build constraint.

```sh
make build       # builds ./signet
make test        # runs the test suite
```

<div align="center">
<sub>
The key that proves which machine you are; sealed in hardware, exportable to no one.<br>
<a href="LICENSE">MIT Licence</a> · <a href="https://github.com/radar-hooves/signet/issues">Report Bug</a> · <a href="SECURITY.md">Security</a>
</sub>
</div>
