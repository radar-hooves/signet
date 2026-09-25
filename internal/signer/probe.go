// probe.go: the software backend's availability probe for 'signet doctor'.
package signer

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"os"
)

// ProbeSoftware reports whether a key file exists at path and, if so, its
// mode and its public key's fingerprint — 16 hex characters of SHA-256 over
// the SPKI DER, the same fingerprint the attest package's bearer cache keys
// on, so a doctor reading matches what the broker actually enrolled.
func ProbeSoftware(path string) (ok bool, detail string) {
	info, err := os.Stat(path)
	if err != nil {
		return false, fmt.Sprintf("no key at %s; run 'signet enrol' first", path)
	}
	spkiB64, err := newSoftwareSigner(path).PublicKeyDER()
	if err != nil {
		return false, fmt.Sprintf("%s exists but could not be read: %v", path, err)
	}
	der, err := base64.StdEncoding.DecodeString(spkiB64)
	if err != nil {
		return false, fmt.Sprintf("%s: undecodable public key", path)
	}
	sum := sha256.Sum256(der)
	fingerprint := hex.EncodeToString(sum[:])[:16]
	return true, fmt.Sprintf("key present, mode %s, fingerprint %s", info.Mode().Perm(), fingerprint)
}
