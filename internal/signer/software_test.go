package signer

import (
	"crypto/ecdsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"math/big"
	"os"
	"path/filepath"
	"testing"
)

// TestSoftwareSigner_EnrolSignVerify round-trips enrol -> sign -> verify: the
// key Enrol mints is the key Sign uses, and the signature it produces
// verifies against the public key Enrol printed.
func TestSoftwareSigner_EnrolSignVerify(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumer.key")
	s := newSoftwareSigner(path)

	spkiB64, err := s.Enrol()
	if err != nil {
		t.Fatalf("Enrol: %v", err)
	}

	der, err := base64.StdEncoding.DecodeString(spkiB64)
	if err != nil {
		t.Fatalf("decode SPKI: %v", err)
	}
	rawPub, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		t.Fatalf("parse SPKI: %v", err)
	}
	pub, ok := rawPub.(*ecdsa.PublicKey)
	if !ok {
		t.Fatalf("public key type = %T, want *ecdsa.PublicKey", rawPub)
	}

	const message = "challenge-id.nonce"
	sigB64, err := s.Sign(message)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}
	sig, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	if len(sig) != p256SigLen {
		t.Fatalf("signature length = %d, want %d (IEEE P1363 r||s)", len(sig), p256SigLen)
	}
	r := new(big.Int).SetBytes(sig[:p256ScalarLen])
	sVal := new(big.Int).SetBytes(sig[p256ScalarLen:])
	digest := sha256.Sum256([]byte(message))
	if !ecdsa.Verify(pub, digest[:], r, sVal) {
		t.Fatal("signature does not verify against the enrolled public key")
	}
}

// TestSoftwareSigner_EnrolIdempotent verifies a second Enrol never clobbers
// the key: it returns the same public key, and the on-disk file's mode and
// bytes are unchanged.
func TestSoftwareSigner_EnrolIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumer.key")
	s := newSoftwareSigner(path)

	first, err := s.Enrol()
	if err != nil {
		t.Fatalf("first Enrol: %v", err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key after first enrol: %v", err)
	}

	second, err := s.Enrol()
	if err != nil {
		t.Fatalf("second Enrol: %v", err)
	}
	if first != second {
		t.Errorf("second Enrol returned a different public key: %q != %q", first, second)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read key after second enrol: %v", err)
	}
	if string(before) != string(after) {
		t.Error("second Enrol rewrote the key file")
	}
}

// TestSoftwareSigner_KeyFileMode verifies the key file is written 0600.
func TestSoftwareSigner_KeyFileMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "consumer.key")
	s := newSoftwareSigner(path)
	if _, err := s.Enrol(); err != nil {
		t.Fatalf("Enrol: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat: %v", err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("key file mode = %o, want 0600", perm)
	}
}

// TestSoftwareSigner_NoKeyErrors verifies PublicKeyDER and Sign refuse with a
// clear error, naming the path, when no key has been enrolled — never
// silently generating one.
func TestSoftwareSigner_NoKeyErrors(t *testing.T) {
	path := filepath.Join(t.TempDir(), "never-enrolled.key")
	s := newSoftwareSigner(path)

	if _, err := s.PublicKeyDER(); err == nil {
		t.Error("PublicKeyDER with no enrolled key: expected error, got nil")
	}
	if _, err := s.Sign("message"); err == nil {
		t.Error("Sign with no enrolled key: expected error, got nil")
	}
	if _, err := os.Stat(path); err == nil {
		t.Error("Sign/PublicKeyDER must never create a key file as a side effect")
	}
}

// TestDefaultKeyPath verifies the identity-scoped default path, including the
// "consumer" fallback for an empty identity and XDG_CONFIG_HOME override.
func TestDefaultKeyPath(t *testing.T) {
	tmp := t.TempDir()
	t.Setenv("XDG_CONFIG_HOME", tmp)

	got, err := DefaultKeyPath("")
	if err != nil {
		t.Fatalf("DefaultKeyPath(\"\"): %v", err)
	}
	want := filepath.Join(tmp, "portcullis", "consumer.key")
	if got != want {
		t.Errorf("DefaultKeyPath(\"\") = %q, want %q", got, want)
	}

	got, err = DefaultKeyPath("github-mcp")
	if err != nil {
		t.Fatalf("DefaultKeyPath(github-mcp): %v", err)
	}
	want = filepath.Join(tmp, "portcullis", "github-mcp.key")
	if got != want {
		t.Errorf("DefaultKeyPath(github-mcp) = %q, want %q", got, want)
	}
}

// TestSafeFilename pins the filesystem-safe normalisation used to derive a
// key filename from an arbitrary identity name.
func TestSafeFilename(t *testing.T) {
	cases := map[string]string{
		"consumer":     "consumer",
		"github-mcp":   "github-mcp",
		"my/service":   "my_service",
		"a b":          "a_b",
		"":             "default",
		"..":           "..",
		"weird$chars!": "weird_chars_",
	}
	for in, want := range cases {
		if got := safeFilename(in); got != want {
			t.Errorf("safeFilename(%q) = %q, want %q", in, got, want)
		}
	}
}
