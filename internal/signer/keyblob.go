// keyblob.go: shared on-disk key-blob helpers for backends that store a
// hardware-wrapped key blob under signet's data directory, keyed by identity
// name. Used by the Secure Enclave backend (enclave_darwin.go, every
// identity) and the TPM backend (tpm.go, every identity but the legacy
// default, which stays at its fixed persistent handle). Carries no
// build tag: the TPM backend needs it on every platform.
package signer

import (
	"os"
	"path/filepath"
)

// safeFilename reduces an arbitrary identity name to a filesystem-safe
// component, matching the local-label-of-a-keypair model documented in
// configuration.md#--identity: characters outside [a-zA-Z0-9._-] become '_'.
func safeFilename(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '.', r == '-', r == '_':
			out = append(out, r)
		default:
			out = append(out, '_')
		}
	}
	if len(out) == 0 {
		return "default"
	}
	return string(out)
}

// writeKeyBlob persists an opaque, hardware-wrapped key blob (0600) under a
// 0700 directory, writing to a temp file then renaming for atomicity.
func writeKeyBlob(path string, blob []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, blob, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		os.Remove(tmp)
		return err
	}
	return nil
}
