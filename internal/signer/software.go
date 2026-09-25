// software.go: the software P-256 signing backend — signet's only backend
// since hardware attestation left the estate (operator ruling, 25/09/2026).
//
// The key is an ECDSA P-256 private key in a PKCS8 PEM file, mode 0600,
// matching the format and default path (`$XDG_CONFIG_HOME/portcullis/
// <identity>.key`) the household's vend-token.py already generates and reads,
// so the two agree on one key per identity.
package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
)

// defaultIdentity is the key name used when --identity is unset.
const defaultIdentity = "consumer"

// DefaultKeyPath returns $XDG_CONFIG_HOME/portcullis/<identity>.key
// ($HOME/.config/portcullis/<identity>.key when XDG_CONFIG_HOME is unset). An
// empty identity resolves to "consumer".
func DefaultKeyPath(identity string) (string, error) {
	if identity == "" {
		identity = defaultIdentity
	}
	base := os.Getenv("XDG_CONFIG_HOME")
	if base == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("locate home directory: %w", err)
		}
		base = filepath.Join(home, ".config")
	}
	return filepath.Join(base, "portcullis", safeFilename(identity)+".key"), nil
}

// safeFilename reduces an arbitrary identity name to a filesystem-safe
// component: characters outside [a-zA-Z0-9._-] become '_'.
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

// softwareSigner signs with a P-256 key held in a PKCS8 PEM file at path.
type softwareSigner struct {
	path string
}

func newSoftwareSigner(path string) *softwareSigner {
	return &softwareSigner{path: path}
}

// Enrol mints the key file if absent, never overwriting an existing one, and
// returns its public key as base64 SPKI DER — the same shape whether the key
// was just created or already existed, so re-enrolling is a no-op.
func (s *softwareSigner) Enrol() (string, error) {
	if key, err := s.load(); err == nil {
		return marshalSPKI(&key.PublicKey)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("software: generate key: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("software: marshal key: %w", err)
	}
	block := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	if err := writeKeyFileExclusive(s.path, block); err != nil {
		// Another process may have won the race to create the same file
		// (e.g. two concurrent first-run enrols); a concurrent creator's key
		// is just as valid as one this call would have written, so read it
		// back and return its public key rather than failing.
		if key2, loadErr := s.load(); loadErr == nil {
			return marshalSPKI(&key2.PublicKey)
		}
		return "", fmt.Errorf("software: write key %s: %w", s.path, err)
	}
	return marshalSPKI(&key.PublicKey)
}

// PublicKeyDER returns the enrolled public key as base64 SPKI DER without
// generating a new key. Returns an error when no key is enrolled.
func (s *softwareSigner) PublicKeyDER() (string, error) {
	key, err := s.load()
	if err != nil {
		return "", err
	}
	return marshalSPKI(&key.PublicKey)
}

func (s *softwareSigner) Sign(message string) (string, error) {
	key, err := s.load()
	if err != nil {
		return "", err
	}
	digest := sha256.Sum256([]byte(message))
	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		return "", fmt.Errorf("software: sign: %w", err)
	}
	p1363, err := derToP1363(der)
	if err != nil {
		return "", fmt.Errorf("software: %w", err)
	}
	return base64.StdEncoding.EncodeToString(p1363), nil
}

// load reads and parses the PKCS8 PEM key at s.path.
func (s *softwareSigner) load() (*ecdsa.PrivateKey, error) {
	pemBytes, err := os.ReadFile(s.path)
	if err != nil {
		return nil, fmt.Errorf("software: no enrolled key at %s; run 'signet enrol' first", s.path)
	}
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, fmt.Errorf("software: %s is not a PEM-encoded key", s.path)
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("software: parse key %s: %w", s.path, err)
	}
	key, ok := raw.(*ecdsa.PrivateKey)
	if !ok || key.Curve != elliptic.P256() {
		return nil, fmt.Errorf("software: %s is not a P-256 ECDSA key", s.path)
	}
	return key, nil
}

// writeKeyFileExclusive creates path (mode 0600, parent directory 0700 if it
// must be created) and writes data, refusing if the file already exists:
// Enrol is never destructive, so a losing concurrent enrol errors here rather
// than clobbering the winner's key.
func writeKeyFileExclusive(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

// marshalSPKI encodes a P-256 public key as base64 SPKI DER, the wire form
// the broker's /v1/attest/challenge expects.
func marshalSPKI(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("software: marshal public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}
