<div align="center">

<img src="docs/branding/wordmark.svg" alt="signet" width="360">

_The key that proves which machine you are._

[![Go](https://img.shields.io/badge/Go-1.25-00ADD8?style=flat-square&logo=go&logoColor=white)](https://go.dev/) [![Release](https://img.shields.io/github/v/release/radar-hooves/signet?style=flat-square)](https://github.com/radar-hooves/signet/releases/latest) [![Licence](https://img.shields.io/badge/Licence-MIT-blue?style=flat-square)](LICENSE)

[Installation](#installation) · [Quickstart](#quickstart) · [Documentation](#documentation) · [Contributing](#contributing)

</div>

## What is signet?

A machine that needs secrets has to prove it is itself before a broker will hand anything over. signet is a single self-contained Go binary that does this: it holds a P-256 private key in a file, signs the broker's attestation challenge, and exchanges that proof for a short-lived bearer token.

signet acts as a standard credential helper, the same shape as `git credential`, `docker-credential-*`, and AWS `credential_process`. A consumer shells out for a fresh `Authorization` header on demand; signet produces it and exits, with no daemon and no standing secret held anywhere but the key file itself.

signet speaks the `/v1/attest` HTTP contract and nothing more; it is not coupled to any specific broker's business logic, and any secrets broker implementing the contract can consume it. It is the client for [Portcullis](https://github.com/radar-hooves/portcullis), the household secrets broker.

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
# Mint the key (if absent) and print its public half; enrol it with the broker (once per machine)
signet enrol

# Check the key is present and readable
signet doctor

# Attest to a broker and get a bearer header
signet auth https://your-broker.example.internal

# Consumer pre-flight: confirm attestation and credential scope
signet verify --broker https://your-broker.example.internal --credential my-secret
```

After `enrol`, paste the printed public key into the broker. From then on `auth` is the only call a consumer makes; signet handles caching, renewal, and re-attestation automatically.

The key lives at `$XDG_CONFIG_HOME/portcullis/<identity>.key` (`~/.config/portcullis/consumer.key` by default): mode `0600`, one file, nothing exportable beyond it. `--identity` names a second key on the same host for a second consumer; see [Configuration](docs/configuration.md).

## Wiring as a credential helper

Wire `signet auth` as the `headersHelper` in a Claude Code MCP config, or as any other `credential_process`-style helper:

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

`auth` prints signet's own attestation bearer: the credential that proves _this machine's_ identity to the broker. For a **broker-vended credential**, a separate secret the broker holds on the consumer's behalf, wire `signet headers` instead; for one written to a **file** use `signet vend-to-file`; for a **stdio** server that needs the credential in its environment before it starts, use `signet exec`. See [Usage](docs/usage.md) for all seven subcommands, their flags, and exit codes.

## Documentation

| Guide                                   | What it covers                                                              |
| ---------------------------------------- | ----------------------------------------------------------------------------- |
| [Usage](docs/usage.md)                   | All seven subcommands (enrol, sign, auth, verify, headers, vend-to-file, exec, doctor, version); wiring as a credential helper |
| [Configuration](docs/configuration.md)   | Flags (`--identity`, `--key`), `SIGNET_IDENTITY`, and on-disk paths           |
| [Building from source](docs/development/building.md) | Build, test, and the release toolchain                          |
| [Contributing](CONTRIBUTING.md)          | Build and test commands                                                       |
| [Security](SECURITY.md)                 | Reporting vulnerabilities and supported versions                              |
| Brand assets                            | [`docs/branding/`](docs/branding/)                                            |

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md).

```sh
make build       # builds ./signet
make test        # runs the test suite
```

<div align="center">
<sub>
The key that proves which machine you are.<br>
<a href="LICENSE">MIT Licence</a> · <a href="https://github.com/radar-hooves/signet/issues">Report Bug</a> · <a href="SECURITY.md">Security</a>
</sub>
</div>
