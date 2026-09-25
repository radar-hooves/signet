# Contributing to signet

## Build and test

signet is a plain Go binary — Go 1.25, no cgo, no native per-platform step.

```sh
make build       # compile ./signet
make test        # go test ./...
make clean        # remove the binary
```

## Code style

- Standard `gofmt` formatting; the CI gate rejects unformatted code
- Australian English in prose and comments
- No backwards-compatibility shims or deprecated wrappers; breaking changes are documented in `CHANGELOG.md`

## Submitting changes

Open a GitHub Issue before starting significant work, so the approach can be agreed before a PR lands. For small fixes a PR directly is fine. Reference the issue number in the PR description.
