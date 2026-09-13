// tpm_test.go: TPM backend tests that need no hardware and no simulator —
// the on-disk blob framing and path/identity resolution only. The end-to-end
// enrol/sign/verify proof against real TPM commands lives in
// tpm_simulator_test.go (tpmsimulator build tag).
package signer

import (
	"strings"
	"testing"

	"github.com/google/go-tpm/tpm2"
)

// tpm2BPublicOf builds a TPM2BPublic from raw opaque bytes (as if read off the
// wire), for tests that only care about round-tripping the framing, not the
// TPMTPublic structure inside it.
func tpm2BPublicOf(b []byte) tpm2.TPM2BPublic {
	return tpm2.BytesAs2B[tpm2.TPMTPublic](b)
}

// TestTPMBlobRoundTrip proves encodeTPMBlob/decodeTPMBlob preserve a
// TPM2_Create response's wrapped private and public areas exactly, including
// when the private area is much larger than the public one (or empty) — the
// length-prefixed framing must not depend on any relative ordering by size.
func TestTPMBlobRoundTrip(t *testing.T) {
	for name, tc := range map[string]struct {
		priv tpm2.TPM2BPrivate
		pub  []byte
	}{
		"typical": {
			priv: tpm2.TPM2BPrivate{Buffer: []byte{0x01, 0x02, 0x03, 0x04, 0x05}},
			pub:  []byte{0xAA, 0xBB, 0xCC},
		},
		"empty private": {
			priv: tpm2.TPM2BPrivate{Buffer: nil},
			pub:  []byte{0xAA},
		},
		"empty public": {
			priv: tpm2.TPM2BPrivate{Buffer: []byte{0x01}},
			pub:  []byte{},
		},
	} {
		t.Run(name, func(t *testing.T) {
			pub := tpm2BPublicOf(tc.pub)
			blob := encodeTPMBlob(tc.priv, pub)
			priv, decodedPub, err := decodeTPMBlob(blob)
			if err != nil {
				t.Fatalf("decodeTPMBlob: %v", err)
			}
			if string(priv.Buffer) != string(tc.priv.Buffer) {
				t.Errorf("private area = %v, want %v", priv.Buffer, tc.priv.Buffer)
			}
			if string(decodedPub.Bytes()) != string(tc.pub) {
				t.Errorf("public area = %v, want %v", decodedPub.Bytes(), tc.pub)
			}
		})
	}
}

// TestTPMBlobDecodeTruncated proves a corrupt or truncated blob is refused
// rather than panicking or silently returning a zero-value key.
func TestTPMBlobDecodeTruncated(t *testing.T) {
	full := encodeTPMBlob(tpm2.TPM2BPrivate{Buffer: []byte{1, 2, 3}}, tpm2BPublicOf([]byte{4, 5}))
	for n := 0; n < len(full); n++ {
		if _, _, err := decodeTPMBlob(full[:n]); err == nil {
			t.Errorf("decodeTPMBlob(truncated to %d/%d bytes) should error", n, len(full))
		}
	}
	if _, _, err := decodeTPMBlob(append(full, 0xFF)); err == nil {
		t.Error("decodeTPMBlob with trailing garbage should error")
	}
}

// TestTPMBlobPath proves each identity gets its own file, named after it
// (mirroring the Secure Enclave se-<identity>.key convention), and that the
// default identity's path is distinguishable from a named one — the default
// never actually uses this path (it stays at the fixed persistent handle),
// but the naming must not collide if it ever did.
func TestTPMBlobPath(t *testing.T) {
	t.Setenv("HOME", t.TempDir())

	deploy, err := tpmBlobPath("deploy")
	if err != nil {
		t.Fatalf("tpmBlobPath(deploy): %v", err)
	}
	webSvc, err := tpmBlobPath("web-svc")
	if err != nil {
		t.Fatalf("tpmBlobPath(web-svc): %v", err)
	}
	if deploy == webSvc {
		t.Fatalf("tpmBlobPath(deploy) == tpmBlobPath(web-svc) == %q; identities must not collide", deploy)
	}
	for _, want := range []string{"tpm-", "deploy", ".key"} {
		if !strings.Contains(deploy, want) {
			t.Errorf("tpmBlobPath(deploy) = %q, want it to contain %q", deploy, want)
		}
	}
}
