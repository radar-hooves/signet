// verify_test.go: tests for the 'signet verify' consumer pre-flight.
// All five typed exit codes are exercised; no real hardware or network required.
package attest

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

// addAttestHandlers registers the /v1/attest/challenge and /v1/attest/token
// handlers (used by attestFresh) on mux. Mirrors the core of fakeBroker without
// /renew (not needed by verify).
func addAttestHandlers(t *testing.T, mux *http.ServeMux) {
	t.Helper()
	maxExpiry := fakeNow.Add(24 * time.Hour)

	mux.HandleFunc("/v1/attest/challenge", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(challengeResult{ //nolint:errcheck
			ChallengeID: "ch-verify-test",
			Nonce:       "verifynonce",
			ExpiresAt:   fakeNow.Add(5 * time.Minute).Format(time.RFC3339),
		})
	})

	mux.HandleFunc("/v1/attest/token", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(tokenResult{ //nolint:errcheck
			Key:          "verify-bearer-key",
			KeyID:        "kid-v1",
			Name:         "test-identity",
			ExpiresAt:    fakeNow.Add(2 * time.Hour).Format(time.RFC3339),
			MaxExpiresAt: maxExpiry.Format(time.RFC3339),
		})
	})
}

// verifyBrokerWithCred builds a fake broker that serves the attestation
// endpoints plus GET /v1/credentials/{name} returning credStatus.
func verifyBrokerWithCred(t *testing.T, credStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	addAttestHandlers(t, mux)
	mux.HandleFunc("/v1/credentials/", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method", http.StatusMethodNotAllowed)
			return
		}
		if r.Header.Get("Authorization") == "" {
			http.Error(w, "unauthenticated", http.StatusUnauthorized)
			return
		}
		w.WriteHeader(credStatus)
		if credStatus >= 200 && credStatus < 300 {
			w.Write([]byte(`{"name":"test-cred","purpose":"login"}`)) //nolint:errcheck
		}
	})
	return httptest.NewServer(mux)
}

// rejectingBroker builds a fake broker that returns challengeStatus on
// /v1/attest/challenge, simulating a broker rejection of the attestation. The
// body matches the real broker's shape for an unauthenticated 401
// (portcullis: {"error":"unauthenticated","detail":"attestation failed"}) —
// the SAME body whether the presented key genuinely is not enrolled or the
// broker's per-key pending-challenge cap was hit, so a test against this body
// cannot distinguish the two causes either, matching production.
func rejectingBroker(t *testing.T, challengeStatus int) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/attest/challenge", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(challengeStatus)
		w.Write([]byte(`{"error":"unauthenticated","detail":"attestation failed"}`)) //nolint:errcheck
	})
	return httptest.NewServer(mux)
}

// TestVerify_Success verifies exit code 0 when attestation succeeds without
// a credential probe.
func TestVerify_Success(t *testing.T) {
	setTempHome(t)
	mux := http.NewServeMux()
	addAttestHandlers(t, mux)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Verify(s, srv.URL, "")
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if code != ExitVerifyOK {
		t.Errorf("exit code = %d, want %d (ExitVerifyOK)", code, ExitVerifyOK)
	}
}

// TestVerify_KeyMissing verifies exit code 2 when PublicKeyDER fails (key
// not enrolled). The broker must not be contacted at all.
func TestVerify_KeyMissing(t *testing.T) {
	setTempHome(t)
	s := &stubSigner{pubKeyErr: errors.New("key blob not found")}
	// Use an unreachable URL; any attempt to dial it would produce a transport
	// error that would appear as exit code 1, catching a regression.
	code, err := Verify(s, "http://127.0.0.1:0", "")
	if err != nil {
		t.Fatalf("Verify: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitVerifyKeyMissing {
		t.Errorf("exit code = %d, want %d (ExitVerifyKeyMissing)", code, ExitVerifyKeyMissing)
	}
}

// TestVerify_KeyCardBusy verifies that a transient PC/SC sharing violation
// (openFirstYubiKey's retries exhausted, per internal/signer.IsCardBusy) is
// reported as "card busy", never misread as "no key enrolled".
func TestVerify_KeyCardBusy(t *testing.T) {
	setTempHome(t)
	s := &stubSigner{pubKeyErr: errors.New(`PIV: open "reader": card busy (gave up after 6 retries): the smart card cannot be accessed because of other connections outstanding`)}
	code, err := Verify(s, "http://127.0.0.1:0", "")
	if err == nil {
		t.Fatal("Verify: want a non-nil error for a card-busy failure (exit 1, not a typed conclusive exit)")
	}
	if code != 1 {
		t.Errorf("exit code = %d, want 1 (card busy is transient, not the typed key-missing exit)", code)
	}
}

// TestVerify_AttestRejected verifies exit code 3 when the broker returns 401
// on the attestation challenge (resolves to a broker-rejection, not transport),
// that the guidance line steers the reader local rather than reading like a
// broker fault, and that it quotes the broker's own detail and names both
// live causes (not enrolled, or the per-key pending-challenge cap) instead of
// asserting the wrong one with confidence — radar-hooves/master-project,
// dispatched 2026-09-14 while restoring atlas's household vault: the broker's
// cap refused 7 of 17 concurrent `signet vend-to-file` attestations with the
// same 401 body a genuinely unenrolled key gets, and every key was enrolled.
func TestVerify_AttestRejected(t *testing.T) {
	setTempHome(t)
	srv := rejectingBroker(t, http.StatusUnauthorized)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	var code int
	var err error
	out := captureVerifyStdout(t, func() {
		code, err = Verify(s, srv.URL, "")
	})
	if err != nil {
		t.Fatalf("Verify: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitVerifyAttestRejected {
		t.Errorf("exit code = %d, want %d (ExitVerifyAttestRejected)", code, ExitVerifyAttestRejected)
	}
	if !strings.Contains(out, "not enrolled for this identity, or too many challenges pending for this key") {
		t.Errorf("stdout = %q, want the two-cause guidance after a broker-rejected attestation", out)
	}
	if !strings.Contains(out, "unauthenticated: attestation failed") {
		t.Errorf("stdout = %q, want the broker's own quoted detail", out)
	}
}

// TestVerify_CredOutOfScope verifies exit code 4 when the broker returns 403
// on the credential vend endpoint.
func TestVerify_CredOutOfScope(t *testing.T) {
	setTempHome(t)
	srv := verifyBrokerWithCred(t, http.StatusForbidden)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Verify(s, srv.URL, "my-cred")
	if err != nil {
		t.Fatalf("Verify: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitVerifyCredOutOfScope {
		t.Errorf("exit code = %d, want %d (ExitVerifyCredOutOfScope)", code, ExitVerifyCredOutOfScope)
	}
}

// TestVerify_CredNotFound verifies exit code 5 when the broker returns 404
// on the credential vend endpoint.
func TestVerify_CredNotFound(t *testing.T) {
	setTempHome(t)
	srv := verifyBrokerWithCred(t, http.StatusNotFound)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Verify(s, srv.URL, "nonexistent-cred")
	if err != nil {
		t.Fatalf("Verify: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitVerifyCredNotFound {
		t.Errorf("exit code = %d, want %d (ExitVerifyCredNotFound)", code, ExitVerifyCredNotFound)
	}
}

// captureVerifyStdout runs f with os.Stdout redirected to a pipe and returns
// everything written to stdout. Verify writes via fmt.Printf, so this is the
// only way to assert on its human-readable output.
func captureVerifyStdout(t *testing.T, f func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("os.Pipe: %v", err)
	}
	os.Stdout = w
	f()
	w.Close()
	os.Stdout = old
	out, err := io.ReadAll(r)
	if err != nil {
		t.Fatalf("read captured stdout: %v", err)
	}
	return string(out)
}

// TestVerify_NoSecretInOutput asserts that neither the minted bearer key nor
// a credential value from the vend response is ever printed — verify is a
// diagnostic, and a secret in its output would be a leak (#4 acceptance).
func TestVerify_NoSecretInOutput(t *testing.T) {
	setTempHome(t)
	mux := http.NewServeMux()
	addAttestHandlers(t, mux)
	// The credential endpoint returns a 200 envelope carrying a secret-shaped
	// field; verify must classify it as resolvable WITHOUT echoing the value.
	mux.HandleFunc("/v1/credentials/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"name":"my-cred","material":{"access_token":"SUPERSECRETTOKENVALUE"}}`)) //nolint:errcheck
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	out := captureVerifyStdout(t, func() {
		code, err := Verify(s, srv.URL, "my-cred")
		if err != nil || code != ExitVerifyOK {
			t.Errorf("Verify = (%d, %v), want (%d, nil)", code, err, ExitVerifyOK)
		}
	})
	if strings.Contains(out, "SUPERSECRETTOKENVALUE") {
		t.Error("credential value leaked into verify output")
	}
	// "verify-bearer-key" is the bearer the fake /v1/attest/token mints.
	if strings.Contains(out, "verify-bearer-key") {
		t.Error("minted bearer leaked into verify output")
	}
}

// TestVerify_CredSuccess verifies exit code 0 when attestation succeeds and
// the credential vend endpoint returns 200.
func TestVerify_CredSuccess(t *testing.T) {
	setTempHome(t)
	srv := verifyBrokerWithCred(t, http.StatusOK)
	defer srv.Close()

	s := &stubSigner{sig: "c3R1YnNpZw=="}
	code, err := Verify(s, srv.URL, "my-cred")
	if err != nil {
		t.Fatalf("Verify: unexpected non-nil error for typed exit: %v", err)
	}
	if code != ExitVerifyOK {
		t.Errorf("exit code = %d, want %d (ExitVerifyOK)", code, ExitVerifyOK)
	}
}
