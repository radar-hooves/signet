// Package signer holds signet's one signing backend — a P-256 key in a PKCS8
// PEM file — and the Signer interface the rest of signet is written against.
package signer

import "fmt"

// Signer signs on behalf of a machine identity: it can publish its public key
// (Enrol), return the public key without side effects (PublicKeyDER), and
// sign a message (Sign). All three return the broker's wire encodings.
//
//   - Enrol returns SPKI DER (base64-encoded); idempotent — an existing key is
//     never clobbered.
//   - PublicKeyDER returns the same SPKI DER without generating a new key;
//     returns an error if no key has been enrolled yet.
//   - Sign returns the IEEE P1363 r||s ECDSA-P256 signature over
//     SHA256(message) (base64-encoded).
type Signer interface {
	Enrol() (string, error)
	PublicKeyDER() (string, error)
	Sign(message string) (string, error)
}

// New returns the software signer for keyPath. An empty keyPath resolves to
// DefaultKeyPath(identity).
func New(keyPath, identity string) (Signer, error) {
	if keyPath == "" {
		p, err := DefaultKeyPath(identity)
		if err != nil {
			return nil, fmt.Errorf("software: %w", err)
		}
		keyPath = p
	}
	return newSoftwareSigner(keyPath), nil
}
