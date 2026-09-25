# Building from source

signet is a plain Go binary — no cgo, no per-platform native build step. It cross-compiles freely.

## Package map

```text
cmd/signet/          — CLI entry point (main.go, doctor.go, exec.go)
internal/signer/     — Signer interface + the software P-256 backend, p1363 wire-format helpers
internal/attest/     — broker client (attestFresh, renewBearer), bearer cache, auth/verify/headers/vend-to-file/exec flows
internal/datadir/    — ~/.signet root path resolution (bearer cache)
```

## Prerequisites

- **Go 1.25** (the module targets `go 1.25.0`).

## Build and test

```sh
make build       # CGO_ENABLED=0 go build -o signet ./cmd/signet
make test        # CGO_ENABLED=0 go test ./...
make clean        # removes the binary
```

Cross-compiling another target is an ordinary `GOOS`/`GOARCH` build:

```sh
GOOS=darwin GOARCH=arm64 go build -o signet-darwin-arm64 ./cmd/signet
```

## Release toolchain

Releases are cut from the `release` workflow (`.github/workflows/release.yaml`), triggered by pushing a `v*` tag or dispatched manually. It cross-compiles both release targets — `darwin/arm64` and `linux/amd64` — from one `ubuntu-latest` runner, packages each as `signet-<version>-<os>-<arch>.tar.gz` plus a `.sha256` checksum, and uploads them to the GitHub Release.

For Nix users there is a `fetchurl` + SRI derivation at `nix/signet.nix`; it downloads the published release tarball and pins it by SRI hash. Copy it into your Nix configuration and add it to your packages:

```nix
home.packages = [ (pkgs.callPackage ./signet.nix { }) ];
```

When a new release is cut, bump `version` in the derivation and refresh the SRI hash for each platform in its `hashes` set; `nix store prefetch-file <url>` (or the hash-mismatch build error) yields the value.
