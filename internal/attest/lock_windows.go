//go:build windows

// lock_windows.go: no cross-process single-flight on Windows.
//
// The stampede this guards against is a Claude Code session starting many
// gate-served MCP servers at once, which is a macOS/Linux workstation shape.
// Windows hosts run signet as a single credential helper, so the lock would buy
// nothing; `bearer` treats locking as an optimisation and is correct without it.
package attest

// lockCache is a no-op on Windows, matching bearer's contract that a caller
// which cannot take the lock still proceeds.
func lockCache(_, _ string) (func(), error) { return func() {}, nil }
