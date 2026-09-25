// sig_common_test.go: unit tests for the DER→P1363 format conversion helper.
package signer

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/asn1"
	"math/big"
	"testing"
)

// TestDerToP1363_SoftwareKey generates a real ECDSA P-256 signature in DER
// format using the Go standard library, converts it to P1363 via derToP1363,
// and verifies the decoded r,s still validate against the original public key.
//
// This exercises derToP1363 directly against the standard library's own DER
// encoding, independent of the software backend's own signing path.
func TestDerToP1363_SoftwareKey(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	msg := []byte("ch-00000000-0000-0000-0000-000000000001.nonce")
	digest := sha256.Sum256(msg)

	// crypto/ecdsa.Sign returns DER: SEQUENCE { INTEGER r, INTEGER s }
	der, err := ecdsa.SignASN1(rand.Reader, priv, digest[:])
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	p1363, err := derToP1363(der)
	if err != nil {
		t.Fatalf("derToP1363: %v", err)
	}
	if len(p1363) != 64 {
		t.Fatalf("P1363 length = %d, want 64", len(p1363))
	}

	r := new(big.Int).SetBytes(p1363[:32])
	s := new(big.Int).SetBytes(p1363[32:])
	if !ecdsa.Verify(&priv.PublicKey, digest[:], r, s) {
		t.Error("ecdsa.Verify failed after DER→P1363 conversion")
	}
}

// TestDerToP1363_ShortScalar verifies that a DER signature whose r or s
// encodes to fewer than 32 bytes (leading zeros stripped by big.Int) is still
// correctly left-padded to 32 bytes in the P1363 output.
func TestDerToP1363_ShortScalar(t *testing.T) {
	// Build a synthetic DER signature with small r and s values (1 byte each).
	r := big.NewInt(1)
	s := big.NewInt(42)
	der, err := asn1.Marshal(struct{ R, S *big.Int }{r, s})
	if err != nil {
		t.Fatalf("marshal synthetic DER: %v", err)
	}
	p1363, err := derToP1363(der)
	if err != nil {
		t.Fatalf("derToP1363: %v", err)
	}
	if len(p1363) != 64 {
		t.Fatalf("P1363 length = %d, want 64", len(p1363))
	}
	// r is in bytes 0..31: only the last byte should be 1.
	for i := 0; i < 31; i++ {
		if p1363[i] != 0 {
			t.Errorf("p1363[%d] = %d, want 0 (r padding)", i, p1363[i])
		}
	}
	if p1363[31] != 1 {
		t.Errorf("p1363[31] = %d, want 1 (r value)", p1363[31])
	}
	// s is in bytes 32..63: only the last byte should be 42.
	for i := 32; i < 63; i++ {
		if p1363[i] != 0 {
			t.Errorf("p1363[%d] = %d, want 0 (s padding)", i, p1363[i])
		}
	}
	if p1363[63] != 42 {
		t.Errorf("p1363[63] = %d, want 42 (s value)", p1363[63])
	}
}

// TestDerToP1363_Malformed verifies that malformed input returns an error.
func TestDerToP1363_Malformed(t *testing.T) {
	_, err := derToP1363([]byte{0x30, 0x06, 0x02, 0x01, 0xff}) // truncated
	if err == nil {
		t.Error("expected error for malformed DER, got nil")
	}
}
