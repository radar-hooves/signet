// p1363.go: ECDSA wire-format utilities.
package signer

import (
	"encoding/asn1"
	"fmt"
	"math/big"
)

// P-256 wire-format constants used across all backends.
const (
	p256ScalarLen = 32 // bytes per scalar (r or s)
	p256SigLen    = 64 // bytes for P1363 r||s
	p256PointLen  = 65 // bytes for X9.63 uncompressed point (0x04 || X || Y)
)

// rsToP1363 encodes a pair of P-256 scalars r and s into the IEEE P1363
// fixed-width r||s format: each scalar is left-padded to p256ScalarLen bytes.
// Returns an error if either scalar exceeds p256ScalarLen bytes (not P-256).
func rsToP1363(r, s *big.Int) ([]byte, error) {
	rBytes := r.Bytes()
	sBytes := s.Bytes()
	if len(rBytes) > p256ScalarLen || len(sBytes) > p256ScalarLen {
		return nil, fmt.Errorf("ECDSA r or s exceeds %d bytes (not a P-256 signature)", p256ScalarLen)
	}
	out := make([]byte, p256SigLen)
	copy(out[p256ScalarLen-len(rBytes):p256ScalarLen], rBytes)
	copy(out[p256SigLen-len(sBytes):p256SigLen], sBytes)
	return out, nil
}

// derToP1363 converts a DER-encoded ECDSA signature (ASN.1 SEQUENCE of two
// INTEGERs r and s) into the IEEE P1363 fixed-width r||s encoding expected by
// the broker. For P-256 the output is always exactly 64 bytes (32 per scalar).
func derToP1363(der []byte) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	if rest, err := asn1.Unmarshal(der, &sig); err != nil || len(rest) != 0 {
		if err == nil {
			err = fmt.Errorf("trailing bytes after DER ECDSA signature")
		}
		return nil, fmt.Errorf("parse DER ECDSA signature: %w", err)
	}
	return rsToP1363(sig.R, sig.S)
}
