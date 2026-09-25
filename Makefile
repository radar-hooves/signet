# signet build. A plain Go binary — no cgo, no per-platform native build step.

GO ?= go
BINARY ?= signet

VERSION := $(shell git describe --tags --always 2>/dev/null || echo dev)
LDFLAGS := -ldflags "-X main.version=$(VERSION)"

.PHONY: build test clean

build:
	CGO_ENABLED=0 $(GO) build $(LDFLAGS) -o $(BINARY) ./cmd/signet

test:
	CGO_ENABLED=0 $(GO) test ./...

clean:
	rm -f $(BINARY)
