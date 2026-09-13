// signer_test.go: tests for backend selection in New and autoDetect.
// No hardware required; backend construction is tested without calling Enrol/Sign.
package signer

import (
	"runtime"
	"strings"
	"testing"
)

// TestNew_BackendOverride_TPM verifies the tpm name returns a *tpmSigner.
func TestNew_BackendOverride_TPM(t *testing.T) {
	s, err := New("tpm", "", "")
	if err != nil {
		t.Fatalf("New(tpm): %v", err)
	}
	if _, ok := s.(*tpmSigner); !ok {
		t.Errorf("New(tpm) type = %T, want *tpmSigner", s)
	}
}

// TestNew_TPM_IdentityDefault verifies --identity resolution for tpm: an
// omitted identity and an explicit "consumer" both resolve to
// tpmDefaultIdentity (the legacy fixed-handle key), and a named identity is
// carried through unchanged — no hardware touched, construction only.
func TestNew_TPM_IdentityDefault(t *testing.T) {
	for _, tc := range []struct {
		identity string
		want     string
	}{
		{"", tpmDefaultIdentity},
		{"consumer", tpmDefaultIdentity},
		{"deploy", "deploy"},
	} {
		s, err := New("tpm", "", tc.identity)
		if err != nil {
			t.Fatalf("New(tpm, identity=%q): %v", tc.identity, err)
		}
		tpm, ok := s.(*tpmSigner)
		if !ok {
			t.Fatalf("New(tpm) type = %T, want *tpmSigner", s)
		}
		if tpm.identity != tc.want {
			t.Errorf("identity %q resolved to %q, want %q", tc.identity, tpm.identity, tc.want)
		}
	}
}

// TestNew_BackendOverride_PIV verifies the piv name returns a *pivSigner
// (slot construction only; no hardware touched).
func TestNew_BackendOverride_PIV(t *testing.T) {
	s, err := New("piv", "", "")
	if err != nil {
		t.Fatalf("New(piv): %v", err)
	}
	if _, ok := s.(*pivSigner); !ok {
		t.Errorf("New(piv) type = %T, want *pivSigner", s)
	}
}

// The secure-enclave alias test lives in enclave_darwin_test.go: the
// *enclaveSigner type only exists behind the darwin build tag, so a type
// assertion on it here would fail to compile on every other platform.

// TestNew_UnknownBackend verifies an unknown backend returns an error that
// names the unknown value and the valid options. An empty backend is not tested
// here: it triggers auto-detect, not an error.
func TestNew_UnknownBackend(t *testing.T) {
	for _, tc := range []string{"unknown-backend", "INVALID", "tpm2"} {
		tc := tc
		t.Run(tc, func(t *testing.T) {
			_, err := New(tc, "", "")
			if err == nil {
				t.Fatalf("New(%q): expected error, got nil", tc)
			}
			if !strings.Contains(err.Error(), tc) {
				t.Errorf("error %q does not mention the unknown backend %q", err, tc)
			}
			if !strings.Contains(err.Error(), "secure-enclave") {
				t.Errorf("error %q does not mention valid options", err)
			}
		})
	}
}

// TestAutoDetectBackend_GOOS verifies the platform default.
// On darwin: must return "secure-enclave".
// On linux/windows: must return "tpm" or "piv" (TPM availability is not guaranteed).
// Other platforms: must return "piv".
func TestAutoDetectBackend_GOOS(t *testing.T) {
	got := autoDetect()
	switch runtime.GOOS {
	case "darwin":
		if got != "secure-enclave" {
			t.Errorf("autoDetect on darwin = %q, want %q", got, "secure-enclave")
		}
	case "linux", "windows":
		if got != "tpm" && got != "piv" {
			t.Errorf("autoDetect on %s = %q, want tpm or piv", runtime.GOOS, got)
		}
	default:
		if got != "piv" {
			t.Errorf("autoDetect on %s = %q, want %q", runtime.GOOS, got, "piv")
		}
	}
}
